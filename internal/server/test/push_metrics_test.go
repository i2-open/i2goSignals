package test

import (
    "encoding/json"
    "net/http"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/pkg/goSetPush"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/prometheus/client_golang/prometheus/testutil"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestPushMetrics_FailureAndStateTransitionCounters drives a 403 disable scenario and asserts
// that both push_failures_total{err_class="Forbidden"} and push_state_transitions_total
// {from="enabled",to="disabled"} increment for the affected stream.
//
// Per-test isolation: counters are keyed by stream_id, and createPushStream produces a fresh
// MongoDB ObjectID per test, so there's no risk of cross-test contamination on the global
// prometheus registry.
func TestPushMetrics_FailureAndStateTransitionCounters(t *testing.T) {
    events := func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusForbidden)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_metrics_403", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    waitStreamStatus(t, instance, sid, model.StreamStateDisable)

    require.NotNil(t, instance.app.Stats, "Stats handler must be initialized after NewApplication")

    // push_failures_total{stream_id=<sid>, err_class="Forbidden"} should be exactly 1.
    failures := testutil.ToFloat64(
        instance.app.Stats.PushFailures.WithLabelValues(sid, goSetPush.ClassForbidden.String()),
    )
    assert.EqualValues(t, 1, failures, "push_failures_total should record one Forbidden failure")

    // push_state_transitions_total{stream_id=<sid>, from="enabled", to="disabled"} should be 1.
    transitions := testutil.ToFloat64(
        instance.app.Stats.PushStateTransitions.WithLabelValues(sid, model.StreamStateEnabled, model.StreamStateDisable),
    )
    assert.EqualValues(t, 1, transitions, "push_state_transitions_total should record enabled→disabled")
}

// TestPushMetrics_IdleVerifyAcked drives the T3 idle keepalive against a happy receiver and
// asserts push_idle_verify_total{outcome="acked"} increments for the stream.
func TestPushMetrics_IdleVerifyAcked(t *testing.T) {
    t.Setenv("I2SIG_PUSH_IDLE_VERIFY_INTERVAL", "300ms")

    events := func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusAccepted)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_metrics_idle_acked", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    // No business events — only T3 should produce traffic.

    require.NotNil(t, instance.app.Stats)

    require.Eventually(t, func() bool {
        v := testutil.ToFloat64(
            instance.app.Stats.PushIdleVerifyOutcomes.WithLabelValues(sid, "acked"),
        )
        return v >= 1
    }, 5*time.Second, 50*time.Millisecond, "push_idle_verify_total{outcome=acked} should reach 1 within the test deadline")
}

// TestPushMetrics_RecoveryDurationObserved triggers a transient transport failure that resolves
// to enabled, and asserts the recovery duration histogram observes at least one sample.
func TestPushMetrics_RecoveryDurationObserved(t *testing.T) {
    var statusReturnsPaused = make(chan struct{})
    events := func(w http.ResponseWriter, _ *http.Request) {
        // Fail 5xx so the failure dispatch enters TransportBackoff recovery.
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        // Recovery probes /status. Returning enabled lets recoveryLoop resolve immediately
        // (Resumed), which produces a clean ObservePushRecoveryDuration call.
        select {
        case <-statusReturnsPaused:
        default:
        }
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_metrics_recovery_duration", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    require.NotNil(t, instance.app.Stats)

    // The histogram exposes count-of-observations via testutil.CollectAndCount, which counts
    // the metric children. We just need at least one observation to exist.
    require.Eventually(t, func() bool {
        return testutil.CollectAndCount(instance.app.Stats.PushRecoveryDuration) > 0
    }, 5*time.Second, 50*time.Millisecond, "push_recovery_duration_seconds histogram should record at least one observation")
}
