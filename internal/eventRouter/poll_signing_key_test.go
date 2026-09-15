package eventRouter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #312: a poll transmitter that cannot get an active signing key answers
// the poll with a 503 naming the issuer, sends no SETs, keeps its events queued
// and takes a stored key-unavailable pause. The background key check resumes it
// when the key is back and disables it once the retry limit has passed.

const pollKeyIssuer = "https://poll-signing-key.example"

// newPollKeyHarness is a router over a fresh memory store whose background key
// check runs every retryDelay (use an hour to drive the check by hand).
func newPollKeyHarness(t *testing.T, retryDelay string) (*filterPushHarness, *dbProviders.Persistence) {
	t.Helper()
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", retryDelay)
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_LIMIT", "10")
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "poll_signing_key_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})
	return routerOn(t, persistence, "node-poll-key-1"), persistence
}

// routerOn starts another router over persistence, as a second cluster node
// sharing the same store would.
func routerOn(t *testing.T, persistence *dbProviders.Persistence, nodeId string) *filterPushHarness {
	t.Helper()
	r := NewRouter(RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          persistence.Coordinator,
		SubjectFilterService: persistence.SubjectFilterService,
	}, nodeId).(*router)
	t.Cleanup(r.Shutdown)
	return &filterPushHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
		eventService:  persistence.EventService,
		subjectFilter: persistence.SubjectFilterService,
	}
}

// createSigningPollStream creates a poll transmitter for iss in routeMode and
// registers it with the router. A signing one gets its key first.
func (h *filterPushHarness) createSigningPollStream(t *testing.T, iss, routeMode string) *model.StreamStateRecord {
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
		EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll, EndpointUrl: "https://transmitter.example.com/poll"},
		},
	}
	authCtx := context.WithValue(ctx, authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := h.streamService.CreateStream(authCtx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
	require.NoError(t, err)
	state, err := h.streamService.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	h.router.UpdateStreamState(state)
	return state
}

// queuePollEvents queues n events for poll stream sid and waits until this
// router's poll buffer holds every pending event, so an immediate poll sees them.
func (h *filterPushHarness) queuePollEvents(t *testing.T, sid string, n int) []string {
	t.Helper()
	jtis := h.addPendingEvents(t, sid, n)
	h.router.mu.RLock()
	buf := h.router.pollBuffers[sid]
	h.router.mu.RUnlock()
	require.NotNil(t, buf, "poll buffer must exist for stream %s", sid)
	buf.SubmitEvents(jtis)
	require.Eventually(t, func() bool { return buf.Cnt() == h.pendingCount(sid) }, 2*time.Second, 5*time.Millisecond,
		"queued JTIs must drain into the poll buffer")
	return jtis
}

func (h *filterPushHarness) poll(sid string, acks ...string) (map[string]string, int) {
	sets, _, status := h.router.PollStreamHandler(sid, model.PollParameters{
		MaxEvents:         100,
		ReturnImmediately: true,
		Acks:              acks,
	})
	return sets, status
}

func (h *filterPushHarness) stored(t *testing.T, sid string) *model.StreamStateRecord {
	t.Helper()
	rec, err := h.streamService.GetStreamState(context.Background(), sid)
	require.NoError(t, err)
	return rec
}

// keyCheckAt is the background key check's config with its clock at now.
func keyCheckAt(now time.Time) RecoveryConfig {
	return RecoveryConfig{AuthRetryDelay: 15 * time.Second, AuthRetryLimit: 10, Clock: func() time.Time { return now }}
}

// pauseByPoll suspends pollKeyIssuer's key and polls sid once, which must pause it.
func pauseByPoll(t *testing.T, h *filterPushHarness, sid string) *model.StreamStateRecord {
	t.Helper()
	h.setKeyStatus(t, pollKeyIssuer, interfaces.KeyStatusSuspended)
	sets, status := h.poll(sid)
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Empty(t, sets)
	rec := h.stored(t, sid)
	require.Equal(t, model.StreamStatePause, rec.Status)
	require.NotNil(t, rec.KeyUnavailableSince)
	return rec
}

func TestPollSigningKey_SuspendedKeyAnswers503AndPauses(t *testing.T) {
	h, _ := newPollKeyHarness(t, "1h")
	stream := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := stream.StreamConfiguration.Id
	delivered := h.queuePollEvents(t, sid, 1)
	sets, status := h.poll(sid)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, sets, delivered[0])
	queued := h.queuePollEvents(t, sid, 1)
	logs := captureLogs(t)

	h.setKeyStatus(t, pollKeyIssuer, interfaces.KeyStatusSuspended)
	before := time.Now()
	sets, status = h.poll(sid, delivered[0])

	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Empty(t, sets, "no SETs are sent")
	rec := h.stored(t, sid)
	assert.Equal(t, model.StreamStatePause, rec.Status)
	assert.Equal(t, "POLL-SRV: "+services.NoActiveSigningKeyReason(pollKeyIssuer, ""), rec.ErrorMsg)
	require.NotNil(t, rec.KeyUnavailableSince, "the key-unavailable marker is stored")
	assert.False(t, rec.KeyUnavailableSince.Before(before.Add(-time.Second)))
	assert.Equal(t, []string{queued[0]}, pendingJtis(t, h, sid), "the ack is applied and the event stays queued")

	// A poll that was already past the status gate when the pause landed fails
	// the same way, without moving the marker or logging again.
	marker := *rec.KeyUnavailableSince
	inFlight := *stream
	h.router.takeKeyUnavailablePause(&inFlight, "POLL-SRV", nil)
	assert.True(t, h.stored(t, sid).KeyUnavailableSince.Equal(marker), "a repeat failure keeps the first time")

	errors := 0
	for _, line := range logs.lines() {
		if strings.Contains(line, "level=ERROR") && strings.Contains(line, "no active signing key") {
			errors++
			assert.Contains(t, line, pollKeyIssuer)
			assert.Contains(t, line, "alg=RS256")
			assert.Contains(t, line, "remedy")
		}
	}
	assert.Equal(t, 1, errors, "one ERROR per key-unavailable pause")
}

func TestPollSigningKey_ReactivatedKeyResumesWithinOneRetryDelay(t *testing.T) {
	h, _ := newPollKeyHarness(t, "100ms")
	stream := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := stream.StreamConfiguration.Id
	queued := h.queuePollEvents(t, sid, 1)
	pauseByPoll(t, h, sid)

	h.setKeyStatus(t, pollKeyIssuer, interfaces.KeyStatusActive)

	require.Eventually(t, func() bool {
		rec := h.stored(t, sid)
		return rec.Status == model.StreamStateEnabled
	}, 2*time.Second, 10*time.Millisecond, "the key check resumes the stream")
	rec := h.stored(t, sid)
	assert.Empty(t, rec.ErrorMsg, "the reason is cleared")
	assert.Nil(t, rec.KeyUnavailableSince, "the marker is cleared")

	sets, status := h.poll(sid)
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, sets, queued[0], "the next poll returns the queued event")
}

func TestPollSigningKey_StillMissingPastTheLimitDisables(t *testing.T) {
	h, _ := newPollKeyHarness(t, "1h")
	stream := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := stream.StreamConfiguration.Id
	h.queuePollEvents(t, sid, 1)
	since := *pauseByPoll(t, h, sid).KeyUnavailableSince
	limit := 15 * time.Second * 10

	h.router.checkKeyUnavailablePauses(keyCheckAt(since.Add(limit - time.Second)))
	assert.Equal(t, model.StreamStatePause, h.stored(t, sid).Status, "within the limit the pause is left alone")

	h.router.checkKeyUnavailablePauses(keyCheckAt(since.Add(limit)))
	rec := h.stored(t, sid)
	assert.Equal(t, model.StreamStateDisable, rec.Status)
	assert.Equal(t, "POLL-SRV: "+services.NoActiveSigningKeyReason(pollKeyIssuer, ""), rec.ErrorMsg, "disabled with the reason")
	assert.Nil(t, rec.KeyUnavailableSince, "the disable clears the marker")
	assert.Equal(t, 1, h.pendingCount(sid), "the event is still queued")

	h.setKeyStatus(t, pollKeyIssuer, interfaces.KeyStatusActive)
	h.router.checkKeyUnavailablePauses(keyCheckAt(since.Add(2 * limit)))
	assert.Equal(t, model.StreamStateDisable, h.stored(t, sid).Status, "a disabled stream does not resume by itself")
}

func TestPollSigningKey_OperatorPauseIsNeverResumed(t *testing.T) {
	h, _ := newPollKeyHarness(t, "1h")
	stream := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := stream.StreamConfiguration.Id
	paused := pauseByPoll(t, h, sid)

	// An operator pauses it with the very same reason: POST /status's write.
	require.True(t, paused.IsStatusChange(model.StreamStatePause, paused.ErrorMsg))
	h.streamService.UpdateStreamStatus(context.Background(), sid, model.StreamStatePause, paused.ErrorMsg)
	require.Nil(t, h.stored(t, sid).KeyUnavailableSince)

	h.setKeyStatus(t, pollKeyIssuer, interfaces.KeyStatusActive)
	h.router.checkKeyUnavailablePauses(keyCheckAt(time.Now()))
	assert.Equal(t, model.StreamStatePause, h.stored(t, sid).Status, "an operator's pause stays paused")
}

func TestPollSigningKey_ResumedByAnotherRouterPollsWithout409(t *testing.T) {
	h1, persistence := newPollKeyHarness(t, "1h")
	stream := h1.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := stream.StreamConfiguration.Id
	queued := h1.queuePollEvents(t, sid, 1)
	h2 := routerOn(t, persistence, "node-poll-key-2")
	pauseByPoll(t, h1, sid)

	h2.setKeyStatus(t, pollKeyIssuer, interfaces.KeyStatusActive)
	h2.router.checkKeyUnavailablePauses(keyCheckAt(time.Now()))
	require.Equal(t, model.StreamStateEnabled, h2.stored(t, sid).Status, "the second router's check resumes the stream")
	h1.router.mu.RLock()
	local := h1.router.pollStreams[sid].Status
	h1.router.mu.RUnlock()
	require.Equal(t, model.StreamStatePause, local, "the first router's own copy still says paused")

	sets, status := h1.poll(sid)
	assert.Equal(t, http.StatusOK, status, "the first router delivers, not 409")
	assert.Contains(t, sets, queued[0])
}

func TestPollSigningKey_SigningFailureWithholdsTheWholeResponse(t *testing.T) {
	h, _ := newPollKeyHarness(t, "1h")
	stream := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := stream.StreamConfiguration.Id
	queued := h.queuePollEvents(t, sid, 2)

	// A cached key that cannot sign this stream's RS256 SETs.
	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cacheKey := signingCacheKey(pollKeyIssuer, "")
	h.router.mu.Lock()
	h.router.issuerKeys[cacheKey] = wrong
	h.router.issuerKids[cacheKey] = "wrong"
	h.router.mu.Unlock()

	sets, status := h.poll(sid)

	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Empty(t, sets, "no SET is sent, and none is silently left out of a partial response")
	rec := h.stored(t, sid)
	assert.Equal(t, model.StreamStatePause, rec.Status)
	assert.NotNil(t, rec.KeyUnavailableSince)
	assert.ElementsMatch(t, queued, pendingJtis(t, h, sid), "both events stay queued")
	h.router.mu.RLock()
	_, cached := h.router.issuerKeys[cacheKey]
	h.router.mu.RUnlock()
	assert.False(t, cached, "the key that failed is evicted, so the retries read the key store")
}

func TestPollSigningKey_ForwardTransmitterNeedsNoKey(t *testing.T) {
	h, _ := newPollKeyHarness(t, "1h")
	stream := h.createSigningPollStream(t, "https://no-key.example", model.RouteModeForward)
	sid := stream.StreamConfiguration.Id
	queued := h.queuePollEvents(t, sid, 1)

	sets, status := h.poll(sid)

	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, sets, queued[0])
	rec := h.stored(t, sid)
	assert.Equal(t, model.StreamStateEnabled, rec.Status)
	assert.Nil(t, rec.KeyUnavailableSince)
}
