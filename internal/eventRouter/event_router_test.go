package eventRouter

import (
    "context"
    "testing"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/i2-open/i2goSignals/internal/authUtil"
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/testutil"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// --- resolvePollTimeoutEnv unit tests ---------------------------------------

func TestResolvePollTimeoutEnv_UnsetUsesDefaults(t *testing.T) {
    // t.Setenv guarantees both vars are explicitly unset (overrides any
    // environment leakage from the shell that started `go test`).
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "")
    t.Setenv("POLL_DEFAULT_TIMEOUT", "")
    t.Setenv("POLL_MAX_TIMEOUT", "")

    defaultSecs, maxSecs := resolvePollTimeoutEnv()

    assert.Equal(t, pollDefaultTimeoutSecsDefault, defaultSecs)
    assert.Equal(t, pollMaxTimeoutSecsDefault, maxSecs)
}

func TestResolvePollTimeoutEnv_ValidIntegersParsed(t *testing.T) {
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "45")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "120")

    defaultSecs, maxSecs := resolvePollTimeoutEnv()

    assert.Equal(t, 45, defaultSecs)
    assert.Equal(t, 120, maxSecs)
}

func TestResolvePollTimeoutEnv_LegacyNamesAccepted(t *testing.T) {
    // Legacy POLL_DEFAULT_TIMEOUT / POLL_MAX_TIMEOUT names are accepted
    // via envcompat and emit a deprecation WARN. Confirms the old names
    // introduced before the v0.11.0 rename still work.
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "")
    t.Setenv("POLL_DEFAULT_TIMEOUT", "45")
    t.Setenv("POLL_MAX_TIMEOUT", "120")

    defaultSecs, maxSecs := resolvePollTimeoutEnv()

    assert.Equal(t, 45, defaultSecs)
    assert.Equal(t, 120, maxSecs)
}

func TestResolvePollTimeoutEnv_ZerosHonoured(t *testing.T) {
    // The 0 escape hatch must round-trip: 0 means "disable", not "use default".
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "0")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "0")

    defaultSecs, maxSecs := resolvePollTimeoutEnv()

    assert.Equal(t, 0, defaultSecs)
    assert.Equal(t, 0, maxSecs)
}

func TestResolvePollTimeoutEnv_InvalidStringFallsBack(t *testing.T) {
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "not-an-integer")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "5m")

    defaultSecs, maxSecs := resolvePollTimeoutEnv()

    assert.Equal(t, pollDefaultTimeoutSecsDefault, defaultSecs,
        "unparseable I2SIG_POLL_DEFAULT_TIMEOUT should fall back to code default")
    assert.Equal(t, pollMaxTimeoutSecsDefault, maxSecs,
        "unparseable I2SIG_POLL_MAX_TIMEOUT should fall back to code default")
}

func TestResolvePollTimeoutEnv_NegativeFallsBack(t *testing.T) {
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "-5")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "-1")

    defaultSecs, maxSecs := resolvePollTimeoutEnv()

    assert.Equal(t, pollDefaultTimeoutSecsDefault, defaultSecs)
    assert.Equal(t, pollMaxTimeoutSecsDefault, maxSecs)
}

func TestResolvePollTimeoutEnv_DefaultExceedsMaxClamped(t *testing.T) {
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "600")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "60")

    defaultSecs, maxSecs := resolvePollTimeoutEnv()

    assert.Equal(t, 60, defaultSecs, "default should be clamped down to max")
    assert.Equal(t, 60, maxSecs)
}

func TestResolvePollTimeoutEnv_DefaultExceedsMaxNotClampedWhenMaxZero(t *testing.T) {
    // I2SIG_POLL_MAX_TIMEOUT=0 means "cap disabled"; the default-exceeds-max
    // clamp only applies when the cap is active (max > 0).
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "600")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "0")

    defaultSecs, maxSecs := resolvePollTimeoutEnv()

    assert.Equal(t, 600, defaultSecs, "default must not be clamped when max is disabled")
    assert.Equal(t, 0, maxSecs)
}

// --- end-to-end: env values reach the per-stream EventPollBuffer ------------

func TestNewRouter_PollBufferUsesEnvTimeoutValues(t *testing.T) {
    // Set I2SIG_POLL_DEFAULT_TIMEOUT=1 so we can observe the resolved value
    // applied at the per-stream buffer by timing a GetEvents call. This
    // proves the parsed values reach CreateEventPollBuffer end-to-end —
    // observed via buffer behaviour, not by reading internal fields.
    t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "1")
    t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "300")
    t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())

    persistence, err := dbProviders.OpenPersistence("memorydb:", "poll_timeout_env_test")
    require.NoError(t, err)
    t.Cleanup(func() {
        if persistence.Storage != nil {
            _ = persistence.Storage.Close()
        }
    })

    r := NewRouter(RouterDeps{
        StreamService: persistence.StreamService,
        KeyService:    persistence.KeyService,
        EventService:  persistence.EventService,
        Coordinator:   persistence.Coordinator,
    }, "node-poll-env-test").(*router)
    t.Cleanup(r.Shutdown)

    // Build a poll-transmitter stream and let the router build the buffer
    // via the production UpdateStreamState path.
    projectId := projectIdFromHarness(t, &testHarness{
        router:        r,
        streamService: persistence.StreamService,
        keyService:    persistence.KeyService,
    })
    cfg := model.StreamConfiguration{
        Iss:             "DEFAULT",
        Aud:             []string{"https://receiver.example.com"},
        EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
        Delivery: &model.OneOfStreamConfigurationDelivery{
            PollTransmitMethod: &model.PollTransmitMethod{
                Method:      model.DeliveryPoll,
                EndpointUrl: "https://transmitter.example.com/events",
            },
        },
    }
    ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authUtil.ConvertProject(projectId))
    created, err := persistence.StreamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
    require.NoError(t, err)
    state, err := persistence.StreamService.GetStreamState(context.Background(), created.Id)
    require.NoError(t, err)
    r.UpdateStreamState(state)

    r.mu.RLock()
    pollBuf, ok := r.pollBuffers[created.Id]
    r.mu.RUnlock()
    require.True(t, ok, "expected poll buffer for stream %s", created.Id)

    start := time.Now()
    jtis, _ := pollBuf.GetEvents(model.PollParameters{
        ReturnImmediately: false,
        TimeoutSecs:       0, // forces use of configured default
    })
    elapsed := time.Since(start)

    assert.Nil(t, jtis, "no events available, expected nil")
    assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond,
        "buffer should have applied the env-configured 1s default, got %v", elapsed)
    assert.Less(t, elapsed, 2*time.Second,
        "buffer should not have applied any larger fallback, got %v", elapsed)
}

// projectIdFromHarness is defined in push_state_test.go; both files share the
// eventRouter package and reuse the same helper.

// --- JTI dedup short-circuit -----------------------------------------------

const (
    typeAcctDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
    dupTestIssuer    = "https://issuer.example.com"
)

// dedupTestSetup wires up a router with prometheus counters and a poll-transmit
// stream — poll buffers do not auto-drain (unlike push), so pollBuffer.Cnt()
// is a stable observation point across the test.
type dedupTestSetup struct {
    t            *testing.T
    h            *testHarness
    streamID     string
    audience     string
    inCounter    *prometheus.CounterVec
    outCounter   *prometheus.CounterVec
    pollBufferCh func() int
}

func setupDedupRouterPollStream(t *testing.T) *dedupTestSetup {
    t.Helper()
    h := newTestRouter(t)

    inCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "test_events_in_total",
        Help: "test",
    }, []string{"type", "iss", "tfr", "stream_id"})
    outCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "test_events_out_total",
        Help: "test",
    }, []string{"type", "iss", "tfr", "stream_id"})
    h.router.SetEventCounter(inCounter, outCounter)

    audience := "https://receiver.example.com"
    projectId := projectIdFromHarness(t, h)
    // EventsRequested drives EventsDelivered through the stream service's
    // request/supported intersection — passing EventsDelivered alone is ignored.
    cfg := model.StreamConfiguration{
        Iss:              dupTestIssuer,
        Aud:              []string{audience},
        EventsRequested:  []string{typeAcctDisabled},
        Delivery: &model.OneOfStreamConfigurationDelivery{
            PollTransmitMethod: &model.PollTransmitMethod{
                Method:      model.DeliveryPoll,
                EndpointUrl: "https://transmitter.example.com/events",
            },
        },
    }
    ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authUtil.ConvertProject(projectId))
    created, err := h.streamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
    require.NoError(t, err)
    state, err := h.streamService.GetStreamState(context.Background(), created.Id)
    require.NoError(t, err)
    h.router.UpdateStreamState(state)

    pollBufferCnt := func() int {
        h.router.mu.RLock()
        buf, ok := h.router.pollBuffers[created.Id]
        h.router.mu.RUnlock()
        if !ok {
            return -1
        }
        return buf.Cnt()
    }

    return &dedupTestSetup{
        t:            t,
        h:            h,
        streamID:     created.Id,
        audience:     audience,
        inCounter:    inCounter,
        outCounter:   outCounter,
        pollBufferCh: pollBufferCnt,
    }
}

func newRiscToken(jti string, iss string, audience string) *goSet.SecurityEventToken {
    token := &goSet.SecurityEventToken{
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:   iss,
            Audience: jwt.ClaimStrings{audience},
        },
        Events: map[string]interface{}{typeAcctDisabled: map[string]interface{}{}},
    }
    token.ID = jti
    return token
}

func inCounterValue(t *testing.T, vec *prometheus.CounterVec, sid string) float64 {
    t.Helper()
    return testutil.ToFloat64(vec.With(prometheus.Labels{
        "type":      typeAcctDisabled,
        "iss":       dupTestIssuer,
        "tfr":       "POLL",
        "stream_id": sid,
    }))
}

// TestHandleEvent_DuplicateJTI_NoSideEffects: ingest the same JTI twice via
// HandleEvent. The first call increments eventsIn once and submits one
// pending entry to the matching poll stream's buffer. The second call (same
// JTI) must NOT increment the counter again and must NOT add a second buffer
// entry.
func TestHandleEvent_DuplicateJTI_NoSideEffects(t *testing.T) {
    s := setupDedupRouterPollStream(t)

    token := newRiscToken("dup-handle-jti", dupTestIssuer, s.audience)

    // First ingestion.
    err := s.h.router.HandleEvent(token, `{"first":true}`, s.streamID)
    require.NoError(t, err, "first HandleEvent")
    // SubmitEvent posts to an internal channel drained by a goroutine; wait
    // briefly for the poll buffer to observe the submission.
    require.Eventually(t, func() bool { return s.pollBufferCh() == 1 },
        time.Second, 5*time.Millisecond,
        "first ingestion must submit exactly one event")
    require.InDelta(t, 1.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001,
        "first ingestion increments eventsIn once")

    // Second ingestion — same JTI. The router must return nil (idempotent
    // 202 to the receiver) but must NOT touch the counter or the buffer.
    err = s.h.router.HandleEvent(token, `{"second":true}`, s.streamID)
    require.NoError(t, err, "second HandleEvent must be idempotent (return nil)")
    // Give any (unwanted) async submission a window to surface, then assert
    // the count is still 1.
    time.Sleep(50 * time.Millisecond)
    assert.Equal(t, 1, s.pollBufferCh(),
        "duplicate JTI must not be added to the outbound buffer")
    assert.InDelta(t, 1.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001,
        "duplicate JTI must not increment eventsIn a second time")
}

// TestSubmitOperationalEvent_DuplicateJTI_NoSideEffects: same idempotency
// contract for the operational-event path. The first submission counts and
// submits; the second is a silent no-op observable as a single info log.
func TestSubmitOperationalEvent_DuplicateJTI_NoSideEffects(t *testing.T) {
    s := setupDedupRouterPollStream(t)

    token := newRiscToken("dup-op-jti", dupTestIssuer, s.audience)

    rec, err := s.h.router.SubmitOperationalEvent(s.streamID, token, `{"first":true}`)
    require.NoError(t, err, "first SubmitOperationalEvent")
    require.NotNil(t, rec, "first SubmitOperationalEvent returns the new record")
    require.Eventually(t, func() bool { return s.pollBufferCh() == 1 },
        time.Second, 5*time.Millisecond,
        "first operational submission queues one event")
    require.InDelta(t, 1.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001,
        "first operational submission increments eventsIn once")

    // Second operational submission with the same JTI: the receiver-facing
    // caller still gets a record back (the existing one), but no
    // observable side effect on counter or buffer.
    rec2, err := s.h.router.SubmitOperationalEvent(s.streamID, token, `{"second":true}`)
    require.NoError(t, err, "second SubmitOperationalEvent must succeed silently")
    require.NotNil(t, rec2,
        "second SubmitOperationalEvent must still return the existing record")
    assert.Equal(t, rec.Jti, rec2.Jti, "the returned record must be the existing one")
    time.Sleep(50 * time.Millisecond)
    assert.Equal(t, 1, s.pollBufferCh(),
        "duplicate operational JTI must not be added to the outbound buffer")
    assert.InDelta(t, 1.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001,
        "duplicate operational JTI must not increment eventsIn a second time")
}
