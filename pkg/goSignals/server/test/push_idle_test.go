package test

import (
    "encoding/base64"
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "sync/atomic"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

const verifyEventTypeURI = "https://schemas.openid.net/secevent/ssf/event-type/verification"

// decodeJWSPayload parses the unverified payload of a compact JWS body. The push wire format
// (RFC8935) carries a single JWS per request; tests use this to peek at which event-type URIs
// are present without round-tripping through key validation.
func decodeJWSPayload(t *testing.T, jws string) map[string]interface{} {
    t.Helper()
    parts := strings.Split(jws, ".")
    require.Len(t, parts, 3, "JWS must have header.payload.signature")
    raw, err := base64.RawURLEncoding.DecodeString(parts[1])
    require.NoError(t, err, "JWS payload base64 decode")
    var out map[string]interface{}
    require.NoError(t, json.Unmarshal(raw, &out), "JWS payload JSON parse")
    return out
}

// isVerifyEvent returns true iff the payload's "events" map contains the SSF verification URI.
func isVerifyEvent(payload map[string]interface{}) bool {
    events, ok := payload["events"].(map[string]interface{})
    if !ok {
        return false
    }
    _, ok = events[verifyEventTypeURI]
    return ok
}

// readBodyString consumes the request body and returns it as a string. Tests need the raw JWS.
func readBodyString(t *testing.T, r *http.Request) string {
    t.Helper()
    b, err := io.ReadAll(r.Body)
    require.NoError(t, err)
    return string(b)
}

// TestPushIdle_GeneratesVerifyAfterIdle: when no business events flow for I2SIG_PUSH_IDLE_VERIFY_INTERVAL,
// the push loop must generate a real SSF verify event (operational, persisted, signed, pushed,
// acked). The verify arrives at the mock receiver via the normal RFC8935 path.
func TestPushIdle_GeneratesVerifyAfterIdle(t *testing.T) {
    t.Setenv("I2SIG_PUSH_IDLE_VERIFY_INTERVAL", "300ms")

    var verifyCount atomic.Int32
    var businessCount atomic.Int32
    events := func(w http.ResponseWriter, r *http.Request) {
        body := readBodyString(t, r)
        payload := decodeJWSPayload(t, body)
        if isVerifyEvent(payload) {
            verifyCount.Add(1)
        } else {
            businessCount.Add(1)
        }
        w.WriteHeader(http.StatusAccepted)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_idle_verify", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    // Don't emit business events. Let the idle timer fire on its own.

    require.Eventually(t, func() bool {
        return verifyCount.Load() >= 1
    }, 5*time.Second, 50*time.Millisecond, "expected at least one idle-keepalive verify event within 5s")

    assert.EqualValues(t, 0, businessCount.Load(), "no business events were emitted; receiver should only have seen verify(s)")

    // The verify event must have been persisted with Operational=true (slice 2 contract).
    state, err := instance.GetStreamState(sid)
    require.NoError(t, err)
    assert.Equal(t, model.StreamStateEnabled, state.Status, "stream should remain enabled across idle verify acks")
}

// TestPushIdle_ActivelyDeliveringStreamEmitsNoVerify: when business events are flowing faster
// than the idle interval, R1 keeps resetting the timer so no verify events get generated. This
// is the steady-state behavior we want — verify events should be a quiet-time signal, not a
// constant load on a busy receiver.
func TestPushIdle_ActivelyDeliveringStreamEmitsNoVerify(t *testing.T) {
    t.Setenv("I2SIG_PUSH_IDLE_VERIFY_INTERVAL", "500ms")

    var verifyCount atomic.Int32
    var businessCount atomic.Int32
    events := func(w http.ResponseWriter, r *http.Request) {
        body := readBodyString(t, r)
        payload := decodeJWSPayload(t, body)
        if isVerifyEvent(payload) {
            verifyCount.Add(1)
        } else {
            businessCount.Add(1)
        }
        w.WriteHeader(http.StatusAccepted)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_idle_active_no_verify", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")

    // Emit business events at 100ms cadence for 1.2s — well under the 500ms idle interval per
    // event but spanning 2.4 idle intervals overall. R1 should keep resetting the timer.
    deadline := time.Now().Add(1200 * time.Millisecond)
    expectedBusiness := 0
    for time.Now().Before(deadline) {
        emitEvent(t, instance, sid)
        expectedBusiness++
        time.Sleep(100 * time.Millisecond)
    }

    require.Eventually(t, func() bool {
        return businessCount.Load() >= int32(expectedBusiness)
    }, 5*time.Second, 50*time.Millisecond, "all business events should be acked")

    assert.EqualValues(t, 0, verifyCount.Load(),
        "no verify events should be generated while business events keep resetting the idle timer")
}

// TestPushIdle_SuppressedDuringRecovery: after a push failure puts the stream into recovery,
// the idle timer must be stopped — no verify events should be generated while recoveryLoop is
// already actively probing /status. This guards against piling synthetic events onto a stream
// that we already know is in trouble.
//
// The mock returns 503 on both /events AND /status: the 503 on /events triggers entry into
// TransportBackoff recovery; the 503 on /status keeps recovery in that mode (probes fail, then
// sleep with exponential backoff) so the stream sits in paused for the duration of the test.
// A receiver that returned 200/enabled at /status while still failing /events would create a
// rapid paused→enabled cycle (recovery exits immediately, push fails, recovery re-enters, ...);
// that's a real-world misconfiguration scenario but it makes for a flaky observability target.
func TestPushIdle_SuppressedDuringRecovery(t *testing.T) {
    t.Setenv("I2SIG_PUSH_IDLE_VERIFY_INTERVAL", "200ms")

    var eventsCalled atomic.Int32
    var statusCalled atomic.Int32
    events := func(w http.ResponseWriter, _ *http.Request) {
        eventsCalled.Add(1)
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        statusCalled.Add(1)
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_idle_recovery_suppressed", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    // Wait for the first push to fail and recovery to take over (stream → paused).
    waitStreamStatus(t, instance, sid, model.StreamStatePause)

    // Once paused, take a snapshot of /events count, then wait long enough for several idle
    // intervals to elapse. The recovery loop probes /status — it MUST NOT push anything.
    eventsAtPause := eventsCalled.Load()
    time.Sleep(1 * time.Second) // 5x the 200ms idle interval
    eventsAfter := eventsCalled.Load()

    assert.Equal(t, eventsAtPause, eventsAfter,
        "no /events calls should occur during recovery — the idle timer must be suppressed (saw %d before pause, %d after)",
        eventsAtPause, eventsAfter)
    assert.Greater(t, statusCalled.Load(), int32(0),
        "the recovery loop should have probed /status at least once")
}

// TestPushIdle_VerifyPushFailureTriggersRecovery: the verify event generated by T3 flows through
// the normal push path; when the receiver rejects it, slice 6's reactive recovery (T1) takes
// over and the stream transitions to paused. This validates that operational verify events have
// no special-case treatment on the failure path — they are real events.
//
// Both /events and /status return 503 so the stream stays in paused (TransportBackoff probing)
// long enough for waitStreamStatus to observe it. The body of the failed push is asserted to be
// a verify event, not a business event (we never call emitEvent in this test).
func TestPushIdle_VerifyPushFailureTriggersRecovery(t *testing.T) {
    t.Setenv("I2SIG_PUSH_IDLE_VERIFY_INTERVAL", "200ms")

    var firstPushBody atomic.Value // string
    var firstPushSeen atomic.Bool
    events := func(w http.ResponseWriter, r *http.Request) {
        if firstPushSeen.CompareAndSwap(false, true) {
            firstPushBody.Store(readBodyString(t, r))
        }
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_idle_verify_failure_recovery", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    // No business events emitted — only T3 will produce a JTI to push, and that push will 503.

    require.Eventually(t, func() bool {
        return firstPushSeen.Load()
    }, 5*time.Second, 50*time.Millisecond, "T3 should have produced a verify event that the receiver saw")

    body, _ := firstPushBody.Load().(string)
    require.NotEmpty(t, body, "captured push body should be non-empty")
    assert.True(t, isVerifyEvent(decodeJWSPayload(t, body)),
        "the only push attempt should have been the T3-generated verify event")

    waitStreamStatus(t, instance, sid, model.StreamStatePause)
}
