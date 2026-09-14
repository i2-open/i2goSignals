package eventRouter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #308: a push runner never sends a SET it cannot sign. With no active
// key for the stream's iss and signing_alg (at start, after its cached key is
// invalidated, or when signing fails) it logs an ERROR, pauses the stream with a
// reason naming the issuer and algorithm, keeps the events queued, retries the
// key on the receiver-401 cadence, resumes when the key is back and disables at
// the retry limit. A re-enable of a push transmitter with no live runner starts
// one. A Forward transmitter needs no key at all.

const signingKeyIssuer = "https://signing-key.example"

// newSigningKeyHarness is a push router whose runners deliver through seam
// (nil wires the production HTTP adapter), with the receiver status-poll and T3
// keepalive off, a fast backfill, and a key retry every 50ms up to retryLimit.
func newSigningKeyHarness(t *testing.T, seam delivery.PushDelivery, retryLimit int) *filterPushHarness {
	t.Helper()
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "0")
	t.Setenv("I2SIG_PUSH_CONCURRENCY", "1")
	t.Setenv("I2SIG_PUSH_BACKFILL_INTERVAL", "50ms")
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", "50ms")
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_LIMIT", strconv.Itoa(retryLimit))
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())

	persistence, err := dbProviders.OpenPersistence("memorydb:", "push_signing_key_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})
	r := NewRouter(RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          persistence.Coordinator,
		SubjectFilterService: persistence.SubjectFilterService,
		PushDelivery:         seam,
	}, "node-signing-key").(*router)
	t.Cleanup(r.Shutdown)

	return &filterPushHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
		eventService:  persistence.EventService,
		subjectFilter: persistence.SubjectFilterService,
	}
}

// createSigningPushStream creates a push transmitter signing as iss in route
// mode routeMode, pushing to endpoint. A signing transmitter needs its key
// before it can be created, so one is made for iss unless routeMode is Forward.
func (h *filterPushHarness) createSigningPushStream(t *testing.T, iss, routeMode, endpoint, jwksUrl string) *model.StreamStateRecord {
	t.Helper()
	ctx := context.Background()
	projectId := projectIdFromHarness(t, &testHarness{router: h.router, streamService: h.streamService, keyService: h.keyService})
	if routeMode != model.RouteModeForward {
		_, err := h.keyService.CreateKeyPair(ctx, iss, "sig", projectId)
		require.NoError(t, err)
	}
	cfg := model.StreamConfiguration{
		Iss:             iss,
		Aud:             []string{"https://receiver.example.com"},
		RouteMode:       routeMode,
		IssuerJWKSUrl:   jwksUrl,
		EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{Method: model.DeliveryPush, EndpointUrl: endpoint},
		},
	}
	authCtx := context.WithValue(ctx, authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := h.streamService.CreateStream(authCtx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
	require.NoError(t, err)
	state, err := h.streamService.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	return state
}

func (h *filterPushHarness) setKeyStatus(t *testing.T, iss, status string) {
	t.Helper()
	_, _, err := h.keyService.SetKeyStatus(context.Background(), iss, "", status)
	require.NoError(t, err)
	// What the key-status handler does after the transition (ADR 0028).
	h.router.InvalidateIssuerKey(iss)
}

func (h *filterPushHarness) storedStatus(t *testing.T, sid string) (string, string) {
	t.Helper()
	rec, err := h.streamService.GetStreamState(context.Background(), sid)
	require.NoError(t, err)
	return rec.Status, rec.ErrorMsg
}

// waitStoredStatus waits for sid's stored status to become status with a reason
// containing reason.
func (h *filterPushHarness) waitStoredStatus(t *testing.T, sid, status, reason string) {
	t.Helper()
	require.Eventually(t, func() bool {
		got, msg := h.storedStatus(t, sid)
		return got == status && strings.Contains(msg, reason)
	}, 10*time.Second, 5*time.Millisecond, "stream %s never reached %s (%q)", sid, status, reason)
}

// reEnable is what POST /status does for an operator re-enable: write the status,
// then hand the stored record to the router.
func (h *filterPushHarness) reEnable(t *testing.T, sid string) {
	t.Helper()
	ctx := context.Background()
	h.streamService.UpdateStreamStatus(ctx, sid, model.StreamStateEnabled, "")
	rec, err := h.streamService.GetStreamState(ctx, sid)
	require.NoError(t, err)
	h.router.UpdateStreamState(rec)
}

// logCapture collects log output written from any goroutine.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Split(c.buf.String(), "\n")
}

// captureLogs routes every logger.Sub logger into a capture for the rest of the
// test; the package's sub-loggers resolve slog.Default on each record.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	capture := &logCapture{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return capture
}

// startKeyedRunner creates a signing push stream through rx, starts its runner
// and waits for one event to be delivered, so the runner is known to be running
// with its key cached.
func startKeyedRunner(t *testing.T, retryLimit int) (*filterPushHarness, *holdingReceiver, string) {
	t.Helper()
	rx := newHoldingReceiver()
	rx.release()
	h := newSigningKeyHarness(t, rx, retryLimit)
	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 1)
	h.router.UpdateStreamState(stream.DeepCopy())
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond)
	require.Len(t, rx.snapshot(), 1)
	return h, rx, sid
}

func TestPushSigningKey_SuspendedKeyPausesWithoutSending(t *testing.T) {
	h, rx, sid := startKeyedRunner(t, 1000)
	logs := captureLogs(t)

	h.setKeyStatus(t, signingKeyIssuer, interfaces.KeyStatusSuspended)
	queued := h.addPendingEvents(t, sid, 1)

	reason := services.NoActiveSigningKeyReason(signingKeyIssuer, "")
	h.waitStoredStatus(t, sid, model.StreamStatePause, reason)
	assert.Contains(t, reason, "(RS256)", "the reason names the algorithm")
	time.Sleep(400 * time.Millisecond) // several key retries and backfill ticks

	assert.Len(t, rx.snapshot(), 1, "no request reaches the receiver while the key is missing")
	assert.Equal(t, 1, h.pendingCount(sid), "the event stays queued")
	assert.Equal(t, []string{queued[0]}, pendingJtis(t, h, sid))
	status, _ := h.storedStatus(t, sid)
	assert.Equal(t, model.StreamStatePause, status, "retrying the key does not move the status")
	assert.True(t, h.router.pushRunnerLive(sid), "a key-unavailable pause keeps the runner")

	found := false
	for _, line := range logs.lines() {
		if strings.Contains(line, "level=ERROR") && strings.Contains(line, "PUSH-SRV") &&
			strings.Contains(line, signingKeyIssuer) && strings.Contains(line, "sid="+sid) &&
			strings.Contains(line, "remedy") {
			found = true
		}
		assert.NotContains(t, line, "push failed", "a key problem is not reported as a receiver fault")
	}
	assert.True(t, found, "an ERROR names the stream, the issuer and the remedy")
}

func TestPushSigningKey_ReactivatedKeyResumesAndDeliversOnce(t *testing.T) {
	h, rx, sid := startKeyedRunner(t, 1000)

	h.setKeyStatus(t, signingKeyIssuer, interfaces.KeyStatusSuspended)
	queued := h.addPendingEvents(t, sid, 1)
	h.waitStoredStatus(t, sid, model.StreamStatePause, services.NoActiveSigningKeyReason(signingKeyIssuer, ""))

	h.setKeyStatus(t, signingKeyIssuer, interfaces.KeyStatusActive)

	h.waitStoredStatus(t, sid, model.StreamStateEnabled, "")
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond)
	byJti := deliveriesByJti(rx.settle(t))
	assert.Len(t, byJti[queued[0]], 1, "the queued event is delivered once")
	assert.Len(t, byJti, 2)
	_, reason := h.storedStatus(t, sid)
	assert.Empty(t, reason)
}

func TestPushSigningKey_StillMissingAfterRetryLimitDisables(t *testing.T) {
	rx := newHoldingReceiver()
	rx.release()
	h := newSigningKeyHarness(t, rx, 3)
	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	h.setKeyStatus(t, signingKeyIssuer, interfaces.KeyStatusRevoked)
	h.addPendingEvents(t, sid, 1)

	started := time.Now()
	h.router.UpdateStreamState(stream.DeepCopy())

	reason := services.NoActiveSigningKeyReason(signingKeyIssuer, "")
	h.waitStoredStatus(t, sid, model.StreamStateDisable, reason)
	assert.GreaterOrEqual(t, time.Since(started), 150*time.Millisecond, "three retries 50ms apart come before the disable")
	waitFinished(t, h.runnerFor(sid), "the runner stops once the stream is disabled")
	assert.False(t, h.router.pushRunnerLive(sid))
	assert.Empty(t, rx.snapshot(), "nothing is sent")
	assert.Equal(t, 1, h.pendingCount(sid), "the event is still pending")
}

// The runner resumes only its own key-unavailable pause: an operator pause
// placed on top of it survives the key coming back, and the runner stops.
func TestPushSigningKey_OperatorPauseIsNotResumed(t *testing.T) {
	h, rx, sid := startKeyedRunner(t, 1000)
	runner := h.runnerFor(sid)

	h.setKeyStatus(t, signingKeyIssuer, interfaces.KeyStatusSuspended)
	h.addPendingEvents(t, sid, 1)
	h.waitStoredStatus(t, sid, model.StreamStatePause, services.NoActiveSigningKeyReason(signingKeyIssuer, ""))

	h.streamService.UpdateStreamStatus(context.Background(), sid, model.StreamStatePause, "operator hold")
	h.setKeyStatus(t, signingKeyIssuer, interfaces.KeyStatusActive)

	waitFinished(t, runner, "the runner stops instead of resuming an operator's pause")
	status, reason := h.storedStatus(t, sid)
	assert.Equal(t, model.StreamStatePause, status)
	assert.Equal(t, "operator hold", reason)
	assert.Len(t, rx.snapshot(), 1, "nothing more is sent")
	assert.Equal(t, 1, h.pendingCount(sid))
}

// After a key-limit disable, creating the key and re-enabling starts a new
// runner and delivers without a node restart.
func TestPushSigningKey_ReEnableAfterKeyFixDelivers(t *testing.T) {
	rx := newHoldingReceiver()
	rx.release()
	h := newSigningKeyHarness(t, rx, 2)
	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	h.setKeyStatus(t, signingKeyIssuer, interfaces.KeyStatusSuspended)
	h.addPendingEvents(t, sid, 1)
	h.router.UpdateStreamState(stream.DeepCopy())
	h.waitStoredStatus(t, sid, model.StreamStateDisable, services.NoActiveSigningKeyReason(signingKeyIssuer, ""))
	stopped := h.runnerFor(sid)
	waitFinished(t, stopped, "the runner stops at the retry limit")

	h.setKeyStatus(t, signingKeyIssuer, interfaces.KeyStatusActive)
	h.reEnable(t, sid)

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond,
		"the re-enabled stream delivers its queued event")
	assert.Len(t, rx.settle(t), 1)
	assert.NotSame(t, stopped, h.runnerFor(sid), "a new runner was started")
	assert.True(t, h.router.pushRunnerLive(sid))
	status, _ := h.storedStatus(t, sid)
	assert.Equal(t, model.StreamStateEnabled, status)
}

// A push transmitter disabled by its receiver-401 limit starts a runner when
// re-enabled: it pauses again while the receiver still answers 401, and
// delivers once the receiver accepts.
func TestPushReEnable_AfterReceiver401LimitStartsARunner(t *testing.T) {
	var unauthorized atomic.Bool
	unauthorized.Store(true)
	rx := newHoldingReceiver()
	rx.release()
	rx.classify = func(recordedPush) goSetPush.FailureClass {
		if unauthorized.Load() {
			return goSetPush.ClassUnauthorized
		}
		return goSetPush.ClassAccepted
	}
	h := newSigningKeyHarness(t, rx, 2)
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", "20ms")
	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 1)
	h.router.UpdateStreamState(stream.DeepCopy())

	h.waitStoredStatus(t, sid, model.StreamStateDisable, "auth recovery exhausted")
	first := h.runnerFor(sid)
	waitFinished(t, first, "the 401 limit stops the runner")

	// Still 401: the re-enable is accepted without probing the receiver, and
	// normal recovery stops the stream again.
	pushes := len(rx.snapshot())
	h.reEnable(t, sid)
	require.Eventually(t, func() bool { return len(rx.snapshot()) > pushes }, 10*time.Second, 5*time.Millisecond,
		"the re-enabled stream pushes again")
	second := h.runnerFor(sid)
	assert.NotSame(t, first, second, "the re-enable started a new runner")
	h.waitStoredStatus(t, sid, model.StreamStateDisable, "auth recovery exhausted")
	waitFinished(t, second, "the 401 limit stops the second runner too")

	unauthorized.Store(false)
	h.reEnable(t, sid)
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond,
		"once the receiver accepts, the re-enabled stream delivers")
	status, _ := h.storedStatus(t, sid)
	assert.Equal(t, model.StreamStateEnabled, status)
}

// A signing failure inside delivery (nothing was sent) takes the same
// key-unavailable pause, not a receiver recovery, and the stream resumes once a
// key resolves again.
func TestPushSigningKey_SigningFailureIsTheTransmittersKeyProblem(t *testing.T) {
	seam := delivery.NewMemoryScript(
		delivery.PushOutcome{SignErr: errors.New("crypto/rsa: key unusable")},
		delivery.PushOutcome{Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted}},
	)
	h := newSigningKeyHarness(t, seam, 1000)
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", "300ms")
	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 1)
	h.router.UpdateStreamState(stream.DeepCopy())

	h.waitStoredStatus(t, sid, model.StreamStatePause, services.NoActiveSigningKeyReason(signingKeyIssuer, ""))
	assert.Equal(t, 1, h.pendingCount(sid), "the unsigned event stays queued")

	h.waitStoredStatus(t, sid, model.StreamStateEnabled, "")
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond)
	assert.Equal(t, 2, seam.Calls())
}

// capturingReceiver is an RFC 8935 receiver that records every body and answers
// 202.
func capturingReceiver(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

func TestPushSigning_EmptyRouteModeSignsWithTheIssuersKey(t *testing.T) {
	srv, bodies := capturingReceiver(t)
	h := newSigningKeyHarness(t, nil, 1000)
	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, srv.URL+"/events", "")
	sid := stream.StreamConfiguration.Id
	legacy := stream.DeepCopy()
	legacy.StreamConfiguration.RouteMode = "" // stored before route_mode defaulted to PB
	h.addPendingEvents(t, sid, 1)

	h.router.UpdateStreamState(legacy)

	require.Eventually(t, func() bool { return len(bodies()) == 1 }, 10*time.Second, 5*time.Millisecond)
	body := bodies()[0]
	require.NotEmpty(t, body, "an empty route mode must never push an empty token")
	signer, _, err := h.keyService.GetSigner(context.Background(), signingKeyIssuer, "")
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(body, claims, func(*jwt.Token) (interface{}, error) { return signer.Public(), nil })
	require.NoError(t, err, "the SET verifies against the issuer's key")
	assert.Equal(t, signingKeyIssuer, claims["iss"])
}

func TestPushSigning_ForwardWithoutAKeyRelaysTheOriginalUntouched(t *testing.T) {
	srv, bodies := capturingReceiver(t)
	h := newSigningKeyHarness(t, nil, 1000)
	const keylessIssuer = "https://no-key.example"
	stream := h.createSigningPushStream(t, keylessIssuer, model.RouteModeForward, srv.URL+"/events",
		"http://127.0.0.1:1/unresolvable/jwks.json")
	sid := stream.StreamConfiguration.Id

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": keylessIssuer, "jti": "fw-signed"}).SignedString(otherKey)
	require.NoError(t, err)
	unsigned := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL25vLWtleS5leGFtcGxlIiwianRpIjoiZnctdW5zaWduZWQifQ."
	ctx := context.Background()
	for jti, raw := range map[string]string{"fw-signed": signed, "fw-unsigned": unsigned} {
		token := &goSet.SecurityEventToken{}
		token.ID = jti
		rec, err := h.eventService.AddEvent(ctx, token, sid, raw)
		require.NoError(t, err)
		require.NoError(t, h.eventService.AddEventToStream(ctx, rec.Jti, sid))
	}

	logs := captureLogs(t)
	h.router.UpdateStreamState(stream.DeepCopy())

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond)
	assert.ElementsMatch(t, []string{signed, unsigned}, bodies(), "the original tokens are relayed as is")
	status, reason := h.storedStatus(t, sid)
	assert.Equal(t, model.StreamStateEnabled, status)
	assert.Empty(t, reason)
	for _, line := range logs.lines() {
		if !strings.Contains(line, "level=WARN") && !strings.Contains(line, "level=ERROR") {
			continue
		}
		if !strings.Contains(line, sid) && !strings.Contains(line, keylessIssuer) {
			continue // another test's router winding down
		}
		lower := strings.ToLower(line)
		assert.False(t, strings.Contains(lower, "key") || strings.Contains(lower, "jwks"),
			"a Forward transmitter logs no key or JWKS warning: %s", line)
	}
}
