package eventRouter

import (
	"testing"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #306: a push runner captures its signing issuer, route mode and
// endpoint from the record it was started on. UpdateStreamState syncs the
// router's map copy for fan-out matching, but the runner goroutine never reads
// that copy, so a changed setting must restart the runner — close its buffer
// and start a fresh one on the updated record — while a status-only sync
// leaves the running runner alone.

func (h *testHarness) pushBufferFor(sid string) *buffer.EventPushBuffer {
	h.router.mu.RLock()
	defer h.router.mu.RUnlock()
	return h.router.pushBuffers[sid]
}

func TestUpdateStreamState_PushRunnerRestartsOnTransmitSettingChange(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)
	sid := stream.StreamConfiguration.Id

	h.router.UpdateStreamState(stream)
	first := h.pushBufferFor(sid)
	require.NotNil(t, first, "first registration starts a runner")

	// Status-only sync: same runner, same buffer.
	statusOnly := stream.DeepCopy()
	statusOnly.Status = model.StreamStatePause
	statusOnly.ErrorMsg = "operator paused"
	h.router.UpdateStreamState(statusOnly)
	same := h.pushBufferFor(sid)
	require.NotNil(t, same)
	assert.Same(t, first, same, "a status sync must not bounce the runner")
	assert.False(t, first.IsClosed())

	// route_mode change: the runner is restarted on a fresh buffer.
	changed := stream.DeepCopy()
	changed.StreamConfiguration.RouteMode = model.RouteModeForward
	h.router.UpdateStreamState(changed)
	second := h.pushBufferFor(sid)
	require.NotNil(t, second, "the restarted runner has a buffer")
	assert.NotSame(t, first, second, "a changed transmit setting starts a new runner")
	assert.True(t, first.IsClosed(), "the previous runner's buffer is closed so it exits")

	h.router.mu.RLock()
	synced := h.router.pushStreams[sid]
	h.router.mu.RUnlock()
	assert.Equal(t, model.RouteModeForward, synced.GetRouteMode(), "the map copy carries the new mode for fan-out matching")

	// iss change restarts too; aud change restarts too.
	issChanged := changed.DeepCopy()
	issChanged.StreamConfiguration.Iss = "https://other-issuer.example"
	h.router.UpdateStreamState(issChanged)
	third := h.pushBufferFor(sid)
	require.NotNil(t, third)
	assert.NotSame(t, second, third)
	assert.True(t, second.IsClosed())
}

func TestPushRunnerSettingsChanged(t *testing.T) {
	base := model.StreamConfiguration{
		Iss:       "https://iss.example",
		Aud:       []string{"a", "b"},
		RouteMode: model.RouteModePublish,
		Delivery: &model.OneOfStreamConfigurationDelivery{PushTransmitMethod: &model.PushTransmitMethod{
			Method: model.DeliveryPush, EndpointUrl: "https://rx.example/events", AuthorizationHeader: "Bearer x",
		}},
	}
	mutate := func(f func(c *model.StreamConfiguration)) model.StreamConfiguration {
		c := base.DeepCopy()
		f(&c)
		return c
	}
	assert.False(t, pushRunnerSettingsChanged(base, base.DeepCopy()), "identical settings")
	assert.False(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.Description = "x" })), "description is not a runner setting")
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.RouteMode = model.RouteModeForward })))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.Iss = "https://new.example" })))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.Aud = []string{"a"} })))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.SigningAlg = "ES256" })))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) {
		c.Delivery.PushTransmitMethod.EndpointUrl = "https://rx2.example/events"
	})))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) {
		c.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer y"
	})))
}
