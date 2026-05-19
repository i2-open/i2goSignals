package eventRouter

import (
    "context"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/authUtil"
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
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
