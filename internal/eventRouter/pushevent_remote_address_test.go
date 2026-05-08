package eventRouter

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/i2-open/i2goSignals/internal/authUtil"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/i2-open/i2goSignals/pkg/goSetPush"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// mustCreateForwardModeStream creates a DeliveryPush stream in RouteModeForward (no signing key needed)
// pointing at the supplied endpoint URL.
func mustCreateForwardModeStream(t *testing.T, h *testHarness, projectId, endpoint string) *model.StreamStateRecord {
    t.Helper()
    cfg := model.StreamConfiguration{
        Iss:             "DEFAULT",
        Aud:             []string{"https://receiver.example.com"},
        EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
        RouteMode:       model.RouteModeForward,
        Delivery: &model.OneOfStreamConfigurationDelivery{
            PushTransmitMethod: &model.PushTransmitMethod{
                Method:      model.DeliveryPush,
                EndpointUrl: endpoint,
            },
        },
    }
    ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authUtil.ConvertProject(projectId))
    created, err := h.streamService.CreateStream(ctx, cfg, projectId, nil)
    require.NoError(t, err)
    state, err := h.streamService.GetStreamState(context.Background(), created.Id)
    require.NoError(t, err)
    require.NotNil(t, state)
    return state
}

// TestPushEvent_UpdatesLocalRemoteAddressOnFirstPush verifies that after a successful push,
// the local stream pointer's RemoteAddress field is updated alongside the persisted value.
//
// Without this, the in-memory stream held by runPushLoop drifts out of sync with the DB,
// and the only-when-changed guard in pushEvent triggers a redundant DB write on every
// subsequent push (since stream.RemoteAddress stays nil from the loop's perspective).
func TestPushEvent_UpdatesLocalRemoteAddressOnFirstPush(t *testing.T) {
    receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusAccepted)
    }))
    defer receiver.Close()

    h := newTestRouter(t)
    projectId := projectIdFromHarness(t, h)
    stream := mustCreateForwardModeStream(t, h, projectId, receiver.URL+"/events/test")
    require.Nil(t, stream.RemoteAddress, "precondition: RemoteAddress is nil before any push")

    event := &model.AgEventRecord{
        Jti:      "jti-1",
        Original: "raw-token-string",
        Event:    goSet.SecurityEventToken{},
    }

    cls := h.router.pushEvent(stream, event, nil, "")
    require.Equal(t, goSetPush.ClassAccepted, cls.Class, "push to mock receiver should classify as accepted")

    // The fix: local stream pointer must reflect the persisted remote address so the next
    // pushEvent's Equals() check can short-circuit.
    require.NotNil(t, stream.RemoteAddress, "stream.RemoteAddress should be populated locally after push")
    assert.NotEmpty(t, stream.RemoteAddress.IP, "captured IP should be non-empty")
    assert.Equal(t, "http", stream.RemoteAddress.Protocol, "scheme should match the endpoint URL")

    // Also confirm the persisted record matches — this is the existing contract from #26.
    persisted, err := h.streamService.GetStreamState(context.Background(), stream.StreamConfiguration.Id)
    require.NoError(t, err)
    require.NotNil(t, persisted.RemoteAddress)
    assert.Equal(t, stream.RemoteAddress.IP, persisted.RemoteAddress.IP, "in-memory and persisted IP must match")
}

// TestPushEvent_SecondPushSamePeerIsNoop verifies the only-when-changed optimization:
// when the local stream's RemoteAddress already matches the captured peer, pushEvent
// must not issue another UpdateRemoteAddress call.
//
// We assert this indirectly by checking that the local stream pointer's RemoteAddress
// stays equal across the two calls — if the fix is in place, the second call's Equals()
// check returns true and the provider call is skipped.
func TestPushEvent_SecondPushSamePeerIsNoop(t *testing.T) {
    receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusAccepted)
    }))
    defer receiver.Close()

    h := newTestRouter(t)
    projectId := projectIdFromHarness(t, h)
    stream := mustCreateForwardModeStream(t, h, projectId, receiver.URL+"/events/test")

    event1 := &model.AgEventRecord{Jti: "jti-1", Original: "raw-1"}
    event2 := &model.AgEventRecord{Jti: "jti-2", Original: "raw-2"}

    cls1 := h.router.pushEvent(stream, event1, nil, "")
    require.Equal(t, goSetPush.ClassAccepted, cls1.Class)
    require.NotNil(t, stream.RemoteAddress, "first push should populate RemoteAddress")
    firstAddr := *stream.RemoteAddress

    cls2 := h.router.pushEvent(stream, event2, nil, "")
    require.Equal(t, goSetPush.ClassAccepted, cls2.Class)
    require.NotNil(t, stream.RemoteAddress, "second push must not clear RemoteAddress")

    assert.True(t, stream.RemoteAddress.Equals(&firstAddr),
        "second push to same peer must leave local RemoteAddress unchanged")
}
