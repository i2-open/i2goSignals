package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"net/url"

	"github.com/i2-open/i2goSignals/pkg/dao"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// flakyJwksServer serves an RSA JWKS under kid once healthy is set, and 503s
// (a transient failure per isPermanentJwksError) until then. attempts counts
// every inbound request so a test can assert that a lookup inside the backoff
// window makes no network call.
type flakyJwksServer struct {
	*httptest.Server
	attempts atomic.Int32
	healthy  atomic.Bool
	body     atomic.Pointer[[]byte]
}

func newFlakyJwksServer(t *testing.T, kid string, pub *rsa.PublicKey) *flakyJwksServer {
	t.Helper()
	f := &flakyJwksServer{}
	body := rsaPublicJWKSBytes(t, kid, pub)
	f.body.Store(&body)
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.attempts.Add(1)
		if !f.healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(*f.body.Load())
	}))
	t.Cleanup(f.Close)
	return f
}

// retryHarness is a StreamService over the in-memory DAOs whose JWKS retry
// backoff is driven by a manually-advanced clock.
type retryHarness struct {
	svc        *StreamService
	streamDAO  dao.StreamDAO
	keyService *KeyService
	clock      *fakeClock
}

func newRetryHarness(t *testing.T) *retryHarness {
	t.Helper()
	streamDAO := memory.NewStreamDAO()
	keyService := NewKeyService(memory.NewKeyDAO(), "http://receiver.com", nil, nil)
	require.NoError(t, keyService.InitializeTokenKey(context.Background(), "http://receiver.com"))
	svc := NewStreamService(streamDAO, keyService, "http://receiver.com", StreamServiceConfig{})
	baseUrl, err := url.Parse("http://receiver.com")
	require.NoError(t, err)
	svc.SetBaseUrl(baseUrl)
	clock := newFakeClock(time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC))
	svc.now = clock.Now
	return &retryHarness{svc: svc, streamDAO: streamDAO, keyService: keyService, clock: clock}
}

// newJwksReceiverFixture is a ReceivePush receiver stream whose verification
// material comes from an explicit issuer JWKS URL — the shape ADR 0033 calls
// "expects verification material".
func newJwksReceiverFixture(t *testing.T, iss, jwksUrl string) *model.StreamStateRecord {
	t.Helper()
	rec := newReceiverFixture(t, model.ReceivePush, model.RouteModeImport, "jwks-receiver")
	rec.StreamConfiguration.Iss = iss
	rec.StreamConfiguration.IssuerJWKSUrl = jwksUrl
	return rec
}

// TestGetIssuerJwksForReceiver_TransientFailureIsRetriedAfterBackoff is the
// GH #264 reproduction. A receiver stream whose issuer JWKS endpoint is
// unreachable at startup used to cache a nil ValidateJwks under its SID; every
// later lookup was a cache *hit* on that nil, so the "will retry" the log
// promised never happened and the stream verified nothing for the life of the
// process while still reporting enabled.
//
// The bar: after the endpoint recovers and the backoff deadline passes, a
// lookup must re-attempt the fetch and resolve the real JWKS — with no restart
// and no stream re-provisioning.
func TestGetIssuerJwksForReceiver_TransientFailureIsRetriedAfterBackoff(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "retry-after-backoff"
	jwksSrv := newFlakyJwksServer(t, kid, &key.PublicKey)

	h := newRetryHarness(t)
	svc, streamDAO, clock := h.svc, h.streamDAO, h.clock
	ctx := context.Background()

	rec := newJwksReceiverFixture(t, "https://tx.example", jwksSrv.URL)
	require.NoError(t, streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id

	// Startup preload while the issuer's JWKS endpoint is down.
	svc.LoadReceiverStreams(ctx)
	require.Equal(t, int32(1), jwksSrv.attempts.Load(), "startup preload must attempt the fetch once")
	require.Nil(t, svc.GetIssuerJwksForReceiver(ctx, sid),
		"fail-closed: an unresolved direction must not hand out verification material")

	// The endpoint recovers, but we are still inside the first backoff window:
	// the lookup must NOT stampede the endpoint.
	jwksSrv.healthy.Store(true)
	require.Nil(t, svc.GetIssuerJwksForReceiver(ctx, sid))
	require.Equal(t, int32(1), jwksSrv.attempts.Load(),
		"a lookup inside the backoff window must not re-attempt the fetch")

	// Past the deadline, the next lookup re-attempts and resolves.
	clock.Advance(11 * time.Second)
	jwks := svc.GetIssuerJwksForReceiver(ctx, sid)
	require.NotNil(t, jwks,
		"GH #264: a transient startup failure must be retried on lookup once the backoff deadline passes")
	assert.Contains(t, jwks.KIDs(), kid, "the retry must resolve the issuer's real key")

	// Once resolved, the entry is a cache hit again — no further fetches.
	resolvedAt := jwksSrv.attempts.Load()
	clock.Advance(time.Hour)
	require.NotNil(t, svc.GetIssuerJwksForReceiver(ctx, sid))
	assert.Equal(t, resolvedAt, jwksSrv.attempts.Load(),
		"a resolved entry must be served from cache, never re-fetched")
}

// TestJwksRetryBackoff_DoublesFromTenSecondsAndCapsAtFiveMinutes pins the
// ADR 0033 schedule: exponential from ~10s, doubling, capped at 5 minutes. The
// cap matches RefreshRateLimit in pkg/goSet's JWKS loader so the server has a
// single story about how often it re-hits a JWKS endpoint.
func TestJwksRetryBackoff_DoublesFromTenSecondsAndCapsAtFiveMinutes(t *testing.T) {
	assert.Equal(t, 10*time.Second, jwksRetryInitialBackoff)
	assert.Equal(t, 5*time.Minute, jwksRetryMaxBackoff,
		"the cap must match RefreshRateLimit in pkg/goSet/jwks_loader.go")

	want := []time.Duration{
		10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute,
	}
	got := time.Duration(0)
	for i, expect := range want {
		got = nextJwksBackoff(got)
		assert.Equalf(t, expect, got, "backoff after %d failures", i+1)
	}
}

// TestGetIssuerJwksForReceiver_ZeroKeyJwksIsUnresolved: a JWKS that parses but
// carries zero keys is unresolved, NOT resolved. Non-nil is not the test —
// keyService.GetPublicJWKS swallows per-key errors and can return {"keys":[]},
// which keyfunc parses into a non-nil, zero-key JWKS with a nil error. Caching
// that as success would leave the stream unable to verify anything with nothing
// scheduled to fix it (ADR 0033).
func TestGetIssuerJwksForReceiver_ZeroKeyJwksIsUnresolved(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "published-late"
	jwksSrv := newFlakyJwksServer(t, kid, &key.PublicKey)
	// Healthy endpoint that has simply published no keys yet.
	empty := []byte(`{"keys":[]}`)
	jwksSrv.body.Store(&empty)
	jwksSrv.healthy.Store(true)

	h := newRetryHarness(t)
	ctx := context.Background()

	rec := newJwksReceiverFixture(t, "https://tx.example", jwksSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id

	require.Nil(t, h.svc.GetIssuerJwksForReceiver(ctx, sid),
		"a zero-key JWKS carries no verification material and must not be handed out")

	stored, err := h.streamDAO.FindByID(ctx, sid)
	require.NoError(t, err)
	h.svc.OverlayJwksReadiness(stored)
	require.NotNil(t, stored.JwksReadiness)
	assert.Equal(t, model.JwksReadinessUnresolved, stored.JwksReadiness.State,
		"a healthy endpoint publishing zero keys is unresolved, not ready")

	// The endpoint publishes its keys; the scheduled retry picks them up.
	full := rsaPublicJWKSBytes(t, kid, &key.PublicKey)
	jwksSrv.body.Store(&full)
	h.clock.Advance(11 * time.Second)
	jwks := h.svc.GetIssuerJwksForReceiver(ctx, sid)
	require.NotNil(t, jwks, "a zero-key result must stay retryable")
	assert.Contains(t, jwks.KIDs(), kid)
}

// TestGetIssuerJwksForReceiver_PermanentErrorIsNotRetried: permanent-error
// handling is unchanged (ADR 0033). isPermanentJwksError still disables the
// record and persists the reason — that path is already visible to operators
// and is not a retry candidate, so no backoff is scheduled and no further
// attempt is made however far the clock advances.
func TestGetIssuerJwksForReceiver_PermanentErrorIsNotRetried(t *testing.T) {
	h := newRetryHarness(t)
	ctx := context.Background()

	// An unsupported protocol scheme is permanent per isPermanentJwksError.
	rec := newJwksReceiverFixture(t, "https://tx.example", "ftp://keys.example/jwks.json")
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id

	require.Nil(t, h.svc.GetIssuerJwksForReceiver(ctx, sid))

	stored, err := h.streamDAO.FindByID(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, stored.Status,
		"a permanent JWKS error must still disable the stream")
	assert.Contains(t, stored.ErrorMsg, "Error retrieving issuer JWKS public key",
		"a permanent JWKS error must still persist the reason")

	h.svc.OverlayJwksReadiness(stored)
	require.NotNil(t, stored.JwksReadiness)
	assert.Equal(t, model.JwksReadinessUnresolved, stored.JwksReadiness.State)
	assert.Nil(t, stored.JwksReadiness.NextRetryAt,
		"a permanent failure must not schedule a retry")

	h.clock.Advance(24 * time.Hour)
	assert.Nil(t, h.svc.GetIssuerJwksForReceiver(ctx, sid))
}

// TestGetIssuerJwksForReceiver_NoJwksUrlIsNeverUnresolved: no URL configured is
// a valid resting state. The internal key lookup is authoritative and its
// result — including "no key at all" — is legitimate, so the direction is never
// unresolved and never retried (ADR 0033). Retrying it would put every
// bearer-authenticated stream into a permanent loop against an endpoint it was
// never given.
func TestGetIssuerJwksForReceiver_NoJwksUrlIsNeverUnresolved(t *testing.T) {
	h := newRetryHarness(t)
	ctx := context.Background()

	t.Run("internally registered key resolves", func(t *testing.T) {
		rec := newJwksReceiverFixture(t, "http://receiver.com", "")
		require.NoError(t, h.streamDAO.Create(ctx, rec))
		jwks := h.svc.GetIssuerJwksForReceiver(ctx, rec.StreamConfiguration.Id)
		require.NotNil(t, jwks, "an internally registered issuer key must resolve without a URL")
	})

	t.Run("no key at all is a legitimate resting state", func(t *testing.T) {
		rec := newJwksReceiverFixture(t, "https://unregistered.example", "")
		require.NoError(t, h.streamDAO.Create(ctx, rec))
		sid := rec.StreamConfiguration.Id

		// The internal key lookup is authoritative here. GetPublicJWKS swallows
		// per-key errors and returns {"keys":[]} rather than nil for an issuer it
		// has no key for, which keyfunc parses into a non-nil, zero-key JWKS.
		// ADR 0033 leaves that swallow in place deliberately: it lands on this
		// branch, which by design never retries, and the zero-key predicate
		// covers the URL branch where it would matter. Pinned so the carve-out
		// is not "fixed" here by accident.
		assert.NotNil(t, h.svc.GetIssuerJwksForReceiver(ctx, sid),
			"the no-URL branch must keep returning the internal lookup's result verbatim")

		stored, err := h.streamDAO.FindByID(ctx, sid)
		require.NoError(t, err)
		h.svc.OverlayJwksReadiness(stored)
		require.NotNil(t, stored.JwksReadiness)
		assert.Equal(t, model.JwksReadinessNotConfigured, stored.JwksReadiness.State,
			"no URL means nothing is expected — not a fault")
		assert.Nil(t, stored.JwksReadiness.NextRetryAt)
	})
}

// TestGetIssuerJwksForReceiver_NoneLiteralIsAbsenceNotAUrl: "NONE" (any case)
// is absence, not a URL. SCIM peers write it to mean "the key is internal to
// this server", and a record persisted before normalizeStreamTrustFields
// existed can still carry the literal. Reading it as a URL would send the
// resolver to fetch https://…/NONE forever (ADR 0033). This exercises the
// GetIssuerJwksForReceiver miss path, which does not run the create-time
// normalization — so the predicate itself has to normalize.
func TestGetIssuerJwksForReceiver_NoneLiteralIsAbsenceNotAUrl(t *testing.T) {
	for _, literal := range []string{"NONE", "none", "None"} {
		t.Run(literal, func(t *testing.T) {
			h := newRetryHarness(t)
			ctx := context.Background()

			rec := newJwksReceiverFixture(t, "http://receiver.com", literal)
			require.NoError(t, h.streamDAO.Create(ctx, rec))
			sid := rec.StreamConfiguration.Id

			jwks := h.svc.GetIssuerJwksForReceiver(ctx, sid)
			require.NotNil(t, jwks,
				"%q must take the internal-key branch, not be fetched as a URL", literal)

			stored, err := h.streamDAO.FindByID(ctx, sid)
			require.NoError(t, err)
			h.svc.OverlayJwksReadiness(stored)
			require.NotNil(t, stored.JwksReadiness)
			assert.Equal(t, model.JwksReadinessNotConfigured, stored.JwksReadiness.State,
				"%q is absence, so the direction is not-configured and never retried", literal)
		})
	}
}

// mockJwksTransmitter stands up an SSF transmitter whose discovery document
// advertises jwksUri as its jwks_uri and its own URL as its issuer, so a
// receiver-side CreateStream registers a stream whose IssuerJWKSUrl is jwksUri.
func mockJwksTransmitter(t *testing.T, jwksUri string) (*model.Server, func()) {
	t.Helper()
	cfg := model.TransmitterConfiguration{JwksUri: jwksUri}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		var req model.StreamConfiguration
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		req.Id = "remote-jwks-stream"
		if req.Delivery != nil && req.Delivery.PollTransmitMethod != nil {
			req.Delivery.PollTransmitMethod.EndpointUrl = "http://transmitter.com/poll/x"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
	})
	ts := httptest.NewServer(mux)
	cfg.ConfigurationEndpoint = ts.URL + "/streams"
	cfg.Issuer = ts.URL
	token := "test-token"
	return &model.Server{
		Alias:       "jwks-tx",
		Host:        ts.URL,
		ClientToken: &token,
		ProjectId:   "test-project",
	}, ts.Close
}

// TestCreateStream_UnreachableIssuerJwksIsRetryable covers the case the original
// #264 report did not: CreateStream poisons the cache entry at birth. A stream
// created while its issuer's JWKS endpoint is briefly unreachable used to cache
// a resolved-nil under its SID and never verify anything, exactly as the startup
// preload did. It must instead be recorded unresolved and recover on a later
// lookup (ADR 0033).
func TestCreateStream_UnreachableIssuerJwksIsRetryable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "created-while-down"
	jwksSrv := newFlakyJwksServer(t, kid, &key.PublicKey)

	txServer, closeTx := mockJwksTransmitter(t, jwksSrv.URL)
	defer closeTx()

	h := newRetryHarness(t)
	ctx := context.Background()

	cfg, err := h.svc.CreateStream(ctx, bindingReceiveRequest(), "test-project", txServer)
	require.NoError(t, err, "the stream must still be created while the issuer's JWKS endpoint is down")
	require.Equal(t, jwksSrv.URL, cfg.IssuerJWKSUrl)
	sid := cfg.Id

	require.Nil(t, h.svc.GetIssuerJwksForReceiver(ctx, sid),
		"fail-closed while the issuer's JWKS endpoint is unreachable")

	stored, err := h.streamDAO.FindByID(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateEnabled, stored.Status,
		"a transient JWKS failure must not disable the stream")
	h.svc.OverlayJwksReadiness(stored)
	require.NotNil(t, stored.JwksReadiness)
	assert.Equal(t, model.JwksReadinessUnresolved, stored.JwksReadiness.State,
		"an enabled-but-unverifiable stream must say so somewhere an operator can see")
	require.NotNil(t, stored.JwksReadiness.NextRetryAt, "a transient failure must schedule a retry")

	jwksSrv.healthy.Store(true)
	h.clock.Advance(11 * time.Second)
	jwks := h.svc.GetIssuerJwksForReceiver(ctx, sid)
	require.NotNil(t, jwks,
		"a stream created while its issuer was unreachable must recover without re-provisioning")
	assert.Contains(t, jwks.KIDs(), kid)

	stored, err = h.streamDAO.FindByID(ctx, sid)
	require.NoError(t, err)
	h.svc.OverlayJwksReadiness(stored)
	require.NotNil(t, stored.JwksReadiness)
	assert.Equal(t, model.JwksReadinessReady, stored.JwksReadiness.State)
	assert.Nil(t, stored.JwksReadiness.NextRetryAt)
}

// TestGetIssuerJwksForReceiver_SstpPairInboundRetries: the receiver cache is
// keyed by the INBOUND SID for an SSTP pair (ADR 0018), so the retry and the
// readiness twin have to follow the inbound leg's own trust fields — not the
// primary (transmit) configuration, which carries no inbound issuer.
func TestGetIssuerJwksForReceiver_SstpPairInboundRetries(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "sstp-inbound"
	jwksSrv := newFlakyJwksServer(t, kid, &key.PublicKey)

	h := newRetryHarness(t)
	ctx := context.Background()

	txSid := bson.NewObjectID()
	rxSid := bson.NewObjectID().Hex()
	rec := &model.StreamStateRecord{
		Id:        txSid,
		ProjectId: "proj-1",
		PairId:    txSid.Hex(),
		StreamConfiguration: model.StreamConfiguration{
			Id:  txSid.Hex(),
			Iss: "https://local.example",
			Aud: []string{"https://peer.example"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp},
			},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:            rxSid,
			Iss:           "https://peer.example",
			IssuerJWKSUrl: jwksSrv.URL,
			Aud:           []string{"https://local.example"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp},
			},
		},
		SstpMethod:    &model.SstpMethod{Role: model.SstpRoleResponder},
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
		CreatedAt:     time.Now(),
	}
	require.NoError(t, h.streamDAO.Create(ctx, rec))

	require.Nil(t, h.svc.GetIssuerJwksForReceiver(ctx, rxSid))
	require.Equal(t, int32(1), jwksSrv.attempts.Load())

	stored, err := h.streamDAO.FindByID(ctx, txSid.Hex())
	require.NoError(t, err)
	h.svc.OverlayJwksReadiness(stored)
	assert.Nil(t, stored.JwksReadiness,
		"a pair's readiness belongs on the inbound twin, not the transmit side")
	require.NotNil(t, stored.InboundJwksReadiness)
	assert.Equal(t, model.JwksReadinessUnresolved, stored.InboundJwksReadiness.State)

	jwksSrv.healthy.Store(true)
	h.clock.Advance(11 * time.Second)
	jwks := h.svc.GetIssuerJwksForReceiver(ctx, rxSid)
	require.NotNil(t, jwks, "an SSTP pair's inbound direction must recover the same way")
	assert.Contains(t, jwks.KIDs(), kid)

	stored, err = h.streamDAO.FindByID(ctx, txSid.Hex())
	require.NoError(t, err)
	h.svc.OverlayJwksReadiness(stored)
	require.NotNil(t, stored.InboundJwksReadiness)
	assert.Equal(t, model.JwksReadinessReady, stored.InboundJwksReadiness.State)
}

// TestGetIssuerJwksForReceiver_ConcurrentRetriesDoNotStampede: the retry must
// not hold the cache lock across the network call, and concurrent lookups past
// the deadline must collapse to a single outbound fetch rather than one per
// caller (ADR 0033). Run under -race this also exercises the two-acquisition
// locking around the unlocked fetch.
func TestGetIssuerJwksForReceiver_ConcurrentRetriesDoNotStampede(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "no-stampede"
	jwksSrv := newFlakyJwksServer(t, kid, &key.PublicKey)

	h := newRetryHarness(t)
	ctx := context.Background()

	rec := newJwksReceiverFixture(t, "https://tx.example", jwksSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id

	h.svc.LoadReceiverStreams(ctx)
	require.Equal(t, int32(1), jwksSrv.attempts.Load())

	jwksSrv.healthy.Store(true)
	h.clock.Advance(11 * time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.svc.GetIssuerJwksForReceiver(ctx, sid)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(2), jwksSrv.attempts.Load(),
		"expected the startup preload plus exactly one collapsed retry: 32 concurrent "+
			"lookups past the deadline must not produce 32 outbound fetches")
	require.NotNil(t, h.svc.GetIssuerJwksForReceiver(ctx, sid))
}

// TestGetIssuerJwksForReceiver_DisabledDirectionIsNotRetried pins the third of
// the three outcomes ADR 0033 requires be kept apart: "the inbound direction of
// an SSTP pair is not enabled" is neither a failed fetch nor "nothing is
// expected here". Folding it into the failed fetch put a disabled stream on the
// backoff ladder and published a next-retry time that could never arrive —
// including, after a restart, for a stream that had been disabled by a
// PERMANENT error, which then lost that classification and re-entered the
// ladder.
//
// The bar: a disabled direction makes no network call, schedules no backoff,
// and advertises no next-retry time — but resolves promptly once re-enabled.
func TestGetIssuerJwksForReceiver_DisabledDirectionIsNotRetried(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "disabled-direction"
	jwksSrv := newFlakyJwksServer(t, kid, &key.PublicKey)
	jwksSrv.healthy.Store(true)

	h := newRetryHarness(t)
	ctx := context.Background()

	rec := newJwksReceiverFixture(t, "https://tx.example", jwksSrv.URL)
	rec.Status = model.StreamStateDisable
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id

	h.svc.LoadReceiverStreams(ctx)
	require.Zero(t, jwksSrv.attempts.Load(),
		"a disabled direction must not be fetched: nothing is expected to verify through it")

	require.Nil(t, h.svc.GetIssuerJwksForReceiver(ctx, sid),
		"fail-closed: a disabled direction hands out no verification material")

	stored, err := h.streamDAO.FindByID(ctx, sid)
	require.NoError(t, err)
	h.svc.OverlayJwksReadiness(stored)
	require.NotNil(t, stored.JwksReadiness)
	assert.Nil(t, stored.JwksReadiness.NextRetryAt,
		"a disabled direction must not advertise a retry deadline it will never act on")
	assert.Equal(t, errDirectionNotEnabled.Error(), stored.JwksReadiness.LastError,
		"the reason must name the disabled direction, not a fetch that never happened")

	// Re-enabling must resolve on the next lookup rather than waiting out a
	// backoff window that was never legitimately scheduled.
	h.svc.UpdateStreamStatus(ctx, sid, model.StreamStateEnabled, "")
	jwks := h.svc.GetIssuerJwksForReceiver(ctx, sid)
	require.NotNil(t, jwks, "a re-enabled direction must resolve without waiting out a backoff")
	assert.Contains(t, jwks.KIDs(), kid)
}

// TestGetIssuerJwksForReceiver_RetryDoesNotRaceStatusUpdate covers the locking
// contract ADR 0033 states as a consequence: "the retry attempt must not hold
// the cache lock across the network call, so the resolver acquires the lock
// twice around an unlocked fetch". The hazard that creates is the mirror of the
// one it solves — resolving from the shared record with the lock released races
// UpdateStreamStatus, which writes Status/ErrorMsg on that same record under
// the cache lock.
//
// Meaningful only under -race, which the repo requires for concurrent code.
func TestGetIssuerJwksForReceiver_RetryDoesNotRaceStatusUpdate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksSrv := newFlakyJwksServer(t, "retry-vs-status", &key.PublicKey)

	h := newRetryHarness(t)
	ctx := context.Background()

	rec := newJwksReceiverFixture(t, "https://tx.example", jwksSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id

	// Preload while the endpoint is down, then step past the deadline so every
	// lookup below is a retry candidate.
	h.svc.LoadReceiverStreams(ctx)
	h.clock.Advance(11 * time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.svc.GetIssuerJwksForReceiver(ctx, sid)
		}()
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				h.svc.UpdateStreamStatus(ctx, sid, model.StreamStateDisable, "flipped")
				return
			}
			h.svc.UpdateStreamStatus(ctx, sid, model.StreamStateEnabled, "")
		}(i)
	}
	wg.Wait()
}
