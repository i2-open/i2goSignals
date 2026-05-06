package test

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "sync"
    "sync/atomic"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/authUtil"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/i2-open/i2goSignals/pkg/goSetPush"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// pushRecoveryTestSubject is a fixed event subject used by all push-recovery integration tests.
func pushRecoveryTestSubject() *goSet.EventSubject {
    return &goSet.EventSubject{
        SubjectIdentifier: goSet.SubjectIdentifier{
            Format:                    "scim",
            UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/push-recovery-test"},
        },
    }
}

// startMockReceiver starts an httptest server that routes by path: "/events/{anything}" goes to the
// caller's events handler, "/status" goes to the status handler. Returns the server and a teardown.
func startMockReceiver(t *testing.T, eventsHandler, statusHandler http.HandlerFunc) (*httptest.Server, func()) {
    t.Helper()
    mux := http.NewServeMux()
    mux.HandleFunc("/status", statusHandler)
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if strings.HasPrefix(r.URL.Path, "/events/") {
            eventsHandler(w, r)
            return
        }
        http.NotFound(w, r)
    })
    srv := httptest.NewServer(mux)
    return srv, srv.Close
}

// createPushStream creates an outbound push transmitter pointing to the given events endpoint
// and registers it with the live event router. Returns the resulting stream id.
func createPushStream(t *testing.T, instance *ssfInstance, eventsURL string) string {
    t.Helper()
    streamConfig := model.StreamConfiguration{
        Iss:             instance.app.GetDefIssuer(),
        Aud:             []string{"https://mock-receiver.example.com"},
        EventsSupported: []string{"*"},
        EventsRequested: []string{"*"},
        Delivery: &model.OneOfStreamConfigurationDelivery{
            PushTransmitMethod: &model.PushTransmitMethod{
                Method:              model.DeliveryPush,
                EndpointUrl:         eventsURL,
                AuthorizationHeader: "Bearer test-token",
            },
        },
    }
    atx := authUtil.AuthContext{ProjectId: instance.projectId}
    created, err := instance.provider.CreateStream(streamConfig, &atx)
    require.NoError(t, err)
    state, err := instance.provider.GetStreamState(created.Id)
    require.NoError(t, err)
    instance.app.EventRouter.UpdateStreamState(state)
    return created.Id
}

// emitEvent generates and submits a SET to the live router for the named stream id.
func emitEvent(t *testing.T, instance *ssfInstance, sid string) {
    t.Helper()
    state, err := instance.provider.GetStreamState(sid)
    require.NoError(t, err)
    set := goSet.CreateSet(pushRecoveryTestSubject(), state.Iss, state.Aud)
    set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        map[string]interface{}{"reason": "push-recovery-test"})
    require.NoError(t, instance.app.EventRouter.HandleEvent(&set, "", sid))
}

// waitStreamStatus polls the provider until the stream reaches `target` or the test deadline expires.
func waitStreamStatus(t *testing.T, instance *ssfInstance, sid, target string) *model.StreamStateRecord {
    t.Helper()
    var got *model.StreamStateRecord
    require.Eventually(t, func() bool {
        st, err := instance.provider.GetStreamState(sid)
        if err != nil || st == nil {
            return false
        }
        got = st
        return st.Status == target
    }, 5*time.Second, 50*time.Millisecond, "expected stream %s to reach status %q", sid, target)
    return got
}

// TestPushRecovery_T2PreflightPaused: receiver reports paused at /status before any push attempt.
// The stream should enter `paused` without the events handler being called.
func TestPushRecovery_T2PreflightPaused(t *testing.T) {
    var eventsCalled atomic.Int32
    events := func(w http.ResponseWriter, _ *http.Request) {
        eventsCalled.Add(1)
        w.WriteHeader(http.StatusAccepted)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStatePause, Reason: "by operator"})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_recovery_t2_paused", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    st := waitStreamStatus(t, instance, sid, model.StreamStatePause)
    // After T2 enters PausedByRemote recovery, the loop's own /status re-checks overwrite the
    // initial T2-pre-flight reason with its own more-current text. Either reason form mentions
    // "paused" — the invariant we need is that the receiver is reachable and self-paused.
    assert.Contains(t, st.ErrorMsg, "paused")
    assert.Contains(t, st.ErrorMsg, "by operator")
    assert.EqualValues(t, 0, eventsCalled.Load(), "no push should have been attempted while receiver paused")
}

// TestPushRecovery_T2PreflightDisabled: receiver reports disabled before any push attempt.
// The stream should disable without the events handler being called.
func TestPushRecovery_T2PreflightDisabled(t *testing.T) {
    var eventsCalled atomic.Int32
    events := func(w http.ResponseWriter, _ *http.Request) {
        eventsCalled.Add(1)
        w.WriteHeader(http.StatusAccepted)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateDisable, Reason: "decommissioned"})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_recovery_t2_disabled", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    st := waitStreamStatus(t, instance, sid, model.StreamStateDisable)
    assert.Contains(t, st.ErrorMsg, "T2 pre-flight")
    assert.Contains(t, st.ErrorMsg, "decommissioned")
    assert.EqualValues(t, 0, eventsCalled.Load(), "no push should have been attempted while receiver disabled")
}

// TestPushRecovery_Forbidden: receiver returns 403 to push. Stream should disable immediately.
func TestPushRecovery_Forbidden(t *testing.T) {
    events := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_recovery_forbidden", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    st := waitStreamStatus(t, instance, sid, model.StreamStateDisable)
    assert.Contains(t, st.ErrorMsg, "403 Forbidden")
}

// TestPushRecovery_RFC8935InvalidAudience: receiver returns 400 + invalid_audience. Stream should disable.
func TestPushRecovery_RFC8935InvalidAudience(t *testing.T) {
    events := func(w http.ResponseWriter, _ *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(goSetPush.DeliveryErr{
            ErrCode:     goSetPush.ErrInvalidAudience,
            Description: "audience mismatch",
        })
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_recovery_rfc8935", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    st := waitStreamStatus(t, instance, sid, model.StreamStateDisable)
    assert.Contains(t, st.ErrorMsg, goSetPush.ErrInvalidAudience)
    assert.Contains(t, st.ErrorMsg, "audience mismatch")
}

// TestPushRecovery_JwsSignatureFailedKeyFlushRetry: first push returns 400 jws_signature_failed,
// retry returns 202. The router must invalidate the cached key, reload, re-sign, and retry once;
// the JTI should then be acked and the stream stays enabled.
func TestPushRecovery_JwsSignatureFailedKeyFlushRetry(t *testing.T) {
    var attempts atomic.Int32
    events := func(w http.ResponseWriter, _ *http.Request) {
        n := attempts.Add(1)
        if n == 1 {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusBadRequest)
            _ = json.NewEncoder(w).Encode(goSetPush.DeliveryErr{
                ErrCode:     goSetPush.ErrJwsSignatureFailed,
                Description: "signature did not verify",
            })
            return
        }
        w.WriteHeader(http.StatusAccepted)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_recovery_jws_retry", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    // Wait for the JTI to be acked (no pending events left).
    require.Eventually(t, func() bool {
        ids, _ := instance.provider.GetEventIds(sid, model.PollParameters{ReturnImmediately: true})
        return len(ids) == 0 && attempts.Load() >= 2
    }, 5*time.Second, 50*time.Millisecond, "JTI should be acked after key-flush retry succeeds")

    st, err := instance.provider.GetStreamState(sid)
    require.NoError(t, err)
    assert.Equal(t, model.StreamStateEnabled, st.Status, "stream should remain enabled after successful retry")
    assert.GreaterOrEqual(t, attempts.Load(), int32(2), "expected at least one retry after key flush")
}

// TestPushRecovery_RateLimitedRetryAfterHonored: receiver returns 429 with Retry-After: 1 once,
// then 202. The router should sleep, then re-attempt and ack the JTI.
func TestPushRecovery_RateLimitedRetryAfterHonored(t *testing.T) {
    var attempts atomic.Int32
    var firstAt, secondAt time.Time
    var mu sync.Mutex
    events := func(w http.ResponseWriter, _ *http.Request) {
        n := attempts.Add(1)
        mu.Lock()
        if n == 1 {
            firstAt = time.Now()
        } else if n == 2 {
            secondAt = time.Now()
        }
        mu.Unlock()
        if n == 1 {
            w.Header().Set("Retry-After", "1")
            w.WriteHeader(http.StatusTooManyRequests)
            return
        }
        w.WriteHeader(http.StatusAccepted)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    defer teardown()

    instance, err := createServer(t, "push_recovery_rate_limited", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    sid := createPushStream(t, instance, srv.URL+"/events/streamX")
    emitEvent(t, instance, sid)

    require.Eventually(t, func() bool {
        ids, _ := instance.provider.GetEventIds(sid, model.PollParameters{ReturnImmediately: true})
        return len(ids) == 0 && attempts.Load() >= 2
    }, 8*time.Second, 50*time.Millisecond, "JTI should be acked after Retry-After delay")

    mu.Lock()
    gap := secondAt.Sub(firstAt)
    mu.Unlock()
    assert.GreaterOrEqual(t, gap, 800*time.Millisecond, "second attempt should respect Retry-After (allow 200ms slack)")

    st, err := instance.provider.GetStreamState(sid)
    require.NoError(t, err)
    assert.Equal(t, model.StreamStateEnabled, st.Status, "stream should remain enabled after rate-limit retry succeeds")
}
