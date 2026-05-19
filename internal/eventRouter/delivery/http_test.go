package delivery

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
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

func newEventRecord() *model.AgEventRecord {
	return &model.AgEventRecord{
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
	ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authUtil.ConvertProject(projectId))
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
	ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authUtil.ConvertProject(projectId))
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
