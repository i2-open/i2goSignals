package delivery

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key, "kid-test"
}

func newPublishStream(endpointURL string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:              "stream-publish-1",
			Iss:             "https://issuer.example.com",
			Aud:             []string{"https://receiver.example.com"},
			EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
			RouteMode:       model.RouteModePublish,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushTransmitMethod: &model.PushTransmitMethod{
					Method:      model.DeliveryPush,
					EndpointUrl: endpointURL,
				},
			},
		},
	}
}

func newForwardStream(endpointURL string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:              "stream-forward-1",
			Iss:             "https://issuer.example.com",
			Aud:             []string{"https://receiver.example.com"},
			EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
			RouteMode:       model.RouteModeForward,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushTransmitMethod: &model.PushTransmitMethod{
					Method:      model.DeliveryPush,
					EndpointUrl: endpointURL,
				},
			},
		},
	}
}

func newEventRecord() *model.EventRecord {
	return &model.EventRecord{
		Jti:      "jti-test",
		Original: "raw-token-string",
		Event:    goSet.SecurityEventToken{},
		Types:    []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
	}
}

// stubKeyReloader records each InvalidateAndReload call and returns the scripted key.
type stubKeyReloader struct {
	key    *rsa.PrivateKey
	kid    string
	called int
}

func (s *stubKeyReloader) InvalidateAndReload(_, _ string) (*rsa.PrivateKey, string) {
	s.called++
	return s.key, s.kid
}

func TestHTTPAdapter_JwsSignatureFailedRotatesAndRetries(t *testing.T) {
	var requests int
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"err":"jws_signature_failed","description":"bad sig"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	originalKey, _ := newTestKey(t)
	rotatedKey, _ := newTestKey(t)

	stream := newPublishStream(receiver.URL + "/events")
	reloader := &stubKeyReloader{key: rotatedKey, kid: "kid-rotated"}
	adapter := NewHTTPAdapter(nil, reloader)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newEventRecord(),
		Key:    originalKey,
		Kid:    "kid-original",
	})

	assert.Equal(t, goSetPush.ClassAccepted, out.Classification.Class,
		"after rotate-and-retry the second attempt should be accepted")
	assert.Equal(t, 2, requests, "the receiver must see two POSTs (initial + retry)")
	assert.Equal(t, 1, reloader.called, "key reloader must be invoked exactly once")
	assert.Same(t, rotatedKey, out.Key, "outcome must carry the rotated key forward")
	assert.Equal(t, "kid-rotated", out.Kid)
}

func TestHTTPAdapter_JwsSignatureFailedNotRetriedOnForwardMode(t *testing.T) {
	var requests int
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"err":"jws_signature_failed","description":"bad sig"}`))
	}))
	defer receiver.Close()

	stream := newForwardStream(receiver.URL + "/events")
	reloader := &stubKeyReloader{}
	adapter := NewHTTPAdapter(nil, reloader)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newEventRecord(),
	})

	assert.Equal(t, goSetPush.ClassRFC8935Error, out.Classification.Class)
	assert.Equal(t, 1, requests, "forward-mode jws_signature_failed must NOT be retried")
	assert.Equal(t, 0, reloader.called, "key reloader must not be called for forward mode")
}

func TestHTTPAdapter_JwsSignatureFailedNoReloaderFallsThrough(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"err":"jws_signature_failed","description":"bad sig"}`))
	}))
	defer receiver.Close()

	stream := newPublishStream(receiver.URL + "/events")
	key, _ := newTestKey(t)
	adapter := NewHTTPAdapter(nil, nil)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newEventRecord(),
		Key:    key,
		Kid:    "kid-original",
	})

	assert.Equal(t, goSetPush.ClassRFC8935Error, out.Classification.Class,
		"absence of KeyReloader must surface the classification rather than retrying")
	assert.Same(t, key, out.Key, "outcome carries the original key when no rotation happened")
}

func TestHTTPAdapter_ServerErrorClassifies5xx(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer receiver.Close()

	stream := newForwardStream(receiver.URL + "/events")
	adapter := NewHTTPAdapter(nil, nil)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newEventRecord(),
	})

	assert.Equal(t, goSetPush.ClassServerError, out.Classification.Class,
		"5xx without Retry-After must classify as ClassServerError")
}

func TestHTTPAdapter_UnauthorizedClassifies401(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer receiver.Close()

	stream := newForwardStream(receiver.URL + "/events")
	adapter := NewHTTPAdapter(nil, nil)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newEventRecord(),
	})

	assert.Equal(t, goSetPush.ClassUnauthorized, out.Classification.Class,
		"401 must classify as ClassUnauthorized (non-400 4xx)")
}

func TestHTTPAdapter_RemoteAddressPersistedToStreamService(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "delivery_remote_address_test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = persistence.Storage.Close() })

	// Issue a project IAT to derive a project id, then create a forward-mode stream.
	iat, err := persistence.KeyService.GetAuthIssuer().IssueProjectIat(nil)
	require.NoError(t, err)
	parsed, err := persistence.KeyService.GetAuthIssuer().ParseAuthToken(iat)
	require.NoError(t, err)
	projectId := parsed.ProjectId

	cfg := newForwardStream(receiver.URL + "/events").StreamConfiguration
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := persistence.StreamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
	require.NoError(t, err)
	stream, err := persistence.StreamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	require.Nil(t, stream.RemoteAddress, "precondition: no RemoteAddress yet")

	adapter := NewHTTPAdapter(persistence.StreamService, nil)
	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newEventRecord(),
	})

	require.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
	require.NotEmpty(t, out.RemoteAddress, "successful push must capture peer address")
	require.NotNil(t, stream.RemoteAddress, "in-memory stream pointer must be updated after a successful push")
	assert.NotEmpty(t, stream.RemoteAddress.IP)
	assert.Equal(t, "http", stream.RemoteAddress.Protocol)

	persisted, err := persistence.StreamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	require.NotNil(t, persisted.RemoteAddress, "remote address must be persisted via streamService")
	assert.Equal(t, stream.RemoteAddress.IP, persisted.RemoteAddress.IP,
		"in-memory and persisted IP must match")
}

func TestHTTPAdapter_SamePeerSecondPushDoesNotChangeRemoteAddress(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "delivery_same_peer_test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = persistence.Storage.Close() })

	iat, err := persistence.KeyService.GetAuthIssuer().IssueProjectIat(nil)
	require.NoError(t, err)
	parsed, err := persistence.KeyService.GetAuthIssuer().ParseAuthToken(iat)
	require.NoError(t, err)
	projectId := parsed.ProjectId

	cfg := newForwardStream(receiver.URL + "/events").StreamConfiguration
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := persistence.StreamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
	require.NoError(t, err)
	stream, err := persistence.StreamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)

	adapter := NewHTTPAdapter(persistence.StreamService, nil)
	out1 := adapter.Deliver(context.Background(), PushRequest{Stream: stream, Event: newEventRecord()})
	require.Equal(t, goSetPush.ClassAccepted, out1.Classification.Class)
	require.NotNil(t, stream.RemoteAddress)
	first := *stream.RemoteAddress

	out2 := adapter.Deliver(context.Background(), PushRequest{Stream: stream, Event: newEventRecord()})
	require.Equal(t, goSetPush.ClassAccepted, out2.Classification.Class)
	require.NotNil(t, stream.RemoteAddress, "second push to same peer must not clear RemoteAddress")
	assert.True(t, stream.RemoteAddress.Equals(&first),
		"second push to same peer must leave RemoteAddress equal to the first")
}

func TestHTTPAdapter_TransportError(t *testing.T) {
	// Closed listener => connection refused, no HTTP response.
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	receiver.Close() // closed before any request hits it

	stream := newForwardStream(receiver.URL + "/events")
	adapter := NewHTTPAdapter(nil, nil)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newEventRecord(),
	})

	assert.Equal(t, goSetPush.ClassTransport, out.Classification.Class,
		"connection refused must classify as ClassTransport")
	assert.Empty(t, out.RemoteAddress,
		"transport error without GotConn must leave RemoteAddress empty")
}

func TestHTTPAdapter_RFC8935DeliveryErrParsed(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"err":"invalid_audience","description":"aud mismatch"}`))
	}))
	defer receiver.Close()

	stream := newForwardStream(receiver.URL + "/events")
	adapter := NewHTTPAdapter(nil, nil)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newEventRecord(),
	})

	assert.Equal(t, goSetPush.ClassRFC8935Error, out.Classification.Class)
	assert.Equal(t, "invalid_audience", out.Classification.RFC8935ErrCode)
	assert.Equal(t, "aud mismatch", out.Classification.RFC8935Description)
}

// newPublishStreamWithIdentity builds a PB-mode stream with caller-supplied iss/aud so
// concurrent fan-out tests can assert each stream re-signs under its own identity.
func newPublishStreamWithIdentity(id, iss string, aud []string, endpointURL string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        id,
			Iss:       iss,
			Aud:       aud,
			RouteMode: model.RouteModePublish,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushTransmitMethod: &model.PushTransmitMethod{
					Method:      model.DeliveryPush,
					EndpointUrl: endpointURL,
				},
			},
		},
	}
}

// newSourceEventRecord builds the shared, stored event a PB re-sign reads from. It carries
// a source iss/aud (which PB must overwrite per stream), a jti and txn (which PB must
// preserve verbatim), and a fixed iat (so we can prove iat is refreshed, not preserved).
func newSourceEventRecord() *model.EventRecord {
	return &model.EventRecord{
		Jti:      "jti-source-1",
		Original: "raw-token-string",
		Types:    []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		Event: goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       "jti-source-1",
				Issuer:   "https://source-issuer.example.com",
				Audience: jwt.ClaimStrings{"https://source-audience.example.com"},
				IssuedAt: jwt.NewNumericDate(time.Unix(1000, 0)),
			},
			TransactionId: "txn-source-1",
			Events: map[string]interface{}{
				"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]interface{}{},
			},
		},
	}
}

// captureBody returns a receiver that records every POST body it sees and replies 202.
func captureBody(bodies *[]string, mu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		*bodies = append(*bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}
}

func TestHTTPAdapter_PBReSignPreservesJtiAndTxn(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	receiver := httptest.NewServer(captureBody(&bodies, &mu))
	defer receiver.Close()

	stream := newPublishStreamWithIdentity(
		"stream-pb-1",
		"https://stream-issuer.example.com",
		[]string{"https://stream-audience.example.com"},
		receiver.URL+"/events",
	)
	key, kid := newTestKey(t)
	adapter := NewHTTPAdapter(nil, nil)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  newSourceEventRecord(),
		Key:    key,
		Kid:    kid,
	})
	require.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
	require.Len(t, bodies, 1, "receiver must see exactly one signed SET")

	parsed, err := goSet.Parse(bodies[0], nil)
	require.NoError(t, err, "the pushed PB token must be a parseable SET")

	assert.Equal(t, "jti-source-1", parsed.ID, "PB re-sign must preserve jti verbatim (ADR 0017)")
	assert.Equal(t, "txn-source-1", parsed.TransactionId, "PB re-sign must preserve txn verbatim")
	assert.Equal(t, "https://stream-issuer.example.com", parsed.Issuer, "PB re-sign must use the stream's iss")
	assert.Equal(t, jwt.ClaimStrings{"https://stream-audience.example.com"}, parsed.Audience, "PB re-sign must use the stream's aud")
	require.NotNil(t, parsed.IssuedAt)
	assert.True(t, parsed.IssuedAt.After(time.Unix(1000, 0)), "PB re-sign must refresh iat, not preserve the source iat")
}

func TestHTTPAdapter_PBReSignDoesNotMutateSharedEvent(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	stream := newPublishStreamWithIdentity(
		"stream-pb-1",
		"https://stream-issuer.example.com",
		[]string{"https://stream-audience.example.com"},
		receiver.URL+"/events",
	)
	key, kid := newTestKey(t)
	adapter := NewHTTPAdapter(nil, nil)

	event := newSourceEventRecord()
	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  event,
		Key:    key,
		Kid:    kid,
	})
	require.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)

	// The stored/shared event must be untouched: PB copies before mutating.
	assert.Equal(t, "https://source-issuer.example.com", event.Event.Issuer, "shared event iss must not be mutated by PB re-sign")
	assert.Equal(t, jwt.ClaimStrings{"https://source-audience.example.com"}, event.Event.Audience, "shared event aud must not be mutated by PB re-sign")
	assert.Equal(t, "", event.Event.Kid, "shared event kid must not be mutated by PB re-sign")
	require.NotNil(t, event.Event.IssuedAt)
	assert.Equal(t, int64(1000), event.Event.IssuedAt.Unix(), "shared event iat must not be mutated by PB re-sign")
	assert.Equal(t, "jti-source-1", event.Event.ID, "shared event jti must be intact")
	assert.Equal(t, "txn-source-1", event.Event.TransactionId, "shared event txn must be intact")
}

func TestHTTPAdapter_ConcurrentFanOutNoSharedMutation(t *testing.T) {
	// Production-wiring AC: two PB streams with distinct iss/aud share ONE EventRecord
	// and re-sign concurrently. Each receiver must see a SET signed under its own stream's
	// identity (no cross-stream leak), jti+txn preserved, and -race must report no data race
	// on the shared event.
	var muA, muB sync.Mutex
	var bodiesA, bodiesB []string
	recvA := httptest.NewServer(captureBody(&bodiesA, &muA))
	defer recvA.Close()
	recvB := httptest.NewServer(captureBody(&bodiesB, &muB))
	defer recvB.Close()

	streamA := newPublishStreamWithIdentity("stream-A", "https://issuer-A.example.com", []string{"https://aud-A.example.com"}, recvA.URL+"/events")
	streamB := newPublishStreamWithIdentity("stream-B", "https://issuer-B.example.com", []string{"https://aud-B.example.com"}, recvB.URL+"/events")

	keyA, _ := newTestKey(t)
	keyB, _ := newTestKey(t)
	adapter := NewHTTPAdapter(nil, nil)

	// One shared, stored event fanned out to both streams.
	shared := newSourceEventRecord()

	const iterations = 25
	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			out := adapter.Deliver(context.Background(), PushRequest{Stream: streamA, Event: shared, Key: keyA, Kid: "kid-A"})
			assert.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
		}()
		go func() {
			defer wg.Done()
			out := adapter.Deliver(context.Background(), PushRequest{Stream: streamB, Event: shared, Key: keyB, Kid: "kid-B"})
			assert.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
		}()
	}
	wg.Wait()

	muA.Lock()
	defer muA.Unlock()
	muB.Lock()
	defer muB.Unlock()
	require.Len(t, bodiesA, iterations)
	require.Len(t, bodiesB, iterations)

	for _, body := range bodiesA {
		parsed, err := goSet.Parse(body, nil)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer-A.example.com", parsed.Issuer, "stream A receiver must only ever see stream A's iss")
		assert.Equal(t, jwt.ClaimStrings{"https://aud-A.example.com"}, parsed.Audience, "stream A receiver must only ever see stream A's aud")
		assert.Equal(t, "jti-source-1", parsed.ID, "jti must be preserved across fan-out")
		assert.Equal(t, "txn-source-1", parsed.TransactionId, "txn must be preserved across fan-out")
	}
	for _, body := range bodiesB {
		parsed, err := goSet.Parse(body, nil)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer-B.example.com", parsed.Issuer, "stream B receiver must only ever see stream B's iss")
		assert.Equal(t, jwt.ClaimStrings{"https://aud-B.example.com"}, parsed.Audience, "stream B receiver must only ever see stream B's aud")
		assert.Equal(t, "jti-source-1", parsed.ID, "jti must be preserved across fan-out")
		assert.Equal(t, "txn-source-1", parsed.TransactionId, "txn must be preserved across fan-out")
	}

	// The shared, stored event must remain pristine after all the concurrent re-signs.
	assert.Equal(t, "https://source-issuer.example.com", shared.Event.Issuer, "shared event iss must survive concurrent fan-out untouched")
	assert.Equal(t, jwt.ClaimStrings{"https://source-audience.example.com"}, shared.Event.Audience, "shared event aud must survive concurrent fan-out untouched")
	assert.Equal(t, "", shared.Event.Kid, "shared event kid must survive concurrent fan-out untouched")
}

func TestHTTPAdapter_ForwardEmitsOriginalBytesVerbatim(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	receiver := httptest.NewServer(captureBody(&bodies, &mu))
	defer receiver.Close()

	stream := newForwardStream(receiver.URL + "/events")
	event := newSourceEventRecord()
	event.Original = "forward.original.token.bytes"
	adapter := NewHTTPAdapter(nil, nil)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  event,
	})
	require.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
	require.Len(t, bodies, 1)
	assert.Equal(t, "forward.original.token.bytes", bodies[0], "FW mode must emit Event.Original verbatim (no re-sign)")
}

func TestHTTPAdapter_SuccessReturnsAccepted(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	stream := newForwardStream(receiver.URL + "/events")
	event := newEventRecord()
	adapter := NewHTTPAdapter(nil, nil)

	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: stream,
		Event:  event,
	})

	assert.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
	assert.NotEmpty(t, out.RemoteAddress, "successful push should capture peer address via httptrace")
}
