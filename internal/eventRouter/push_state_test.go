package eventRouter

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testHarness bundles the router under test and the services it shares with
// tests, replacing the old DbProviderInterface-typed handle.
type testHarness struct {
	router        *router
	streamService *services.StreamService
	keyService    *services.KeyService
}

func newTestRouter(t *testing.T) *testHarness {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "push_state_test")
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
	}, "node-test").(*router)
	t.Cleanup(r.Shutdown)
	return &testHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
	}
}

func mustCreateTestStream(t *testing.T, h *testHarness, projectId string) *model.StreamStateRecord {
	t.Helper()
	cfg := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"https://receiver.example.com"},
		EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{
				Method:      model.DeliveryPush,
				EndpointUrl: "https://receiver.example.com/events",
			},
		},
	}
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := h.streamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
	require.NoError(t, err)
	state, err := h.streamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	require.NotNil(t, state)
	return state
}

func projectIdFromHarness(t *testing.T, h *testHarness) string {
	t.Helper()
	iat, err := h.keyService.GetAuthIssuer().IssueProjectIat(nil)
	require.NoError(t, err)
	parsed, err := h.keyService.GetAuthIssuer().ParseAuthToken(iat)
	require.NoError(t, err)
	return parsed.ProjectId
}

func TestUpdateStream_PersistsAndMutatesInMemory(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)
	require.Equal(t, model.StreamStateEnabled, stream.Status)

	h.router.updateStream(stream, model.StreamStateDisable, "PUSH-SRV: forbidden by receiver")

	assert.Equal(t, model.StreamStateDisable, stream.Status, "in-memory stream record must reflect new status")
	assert.Equal(t, "PUSH-SRV: forbidden by receiver", stream.ErrorMsg, "in-memory stream record must reflect new reason")

	persisted, err := h.streamService.GetStreamState(context.Background(), stream.StreamConfiguration.Id)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, persisted.Status, "persisted status must match")
	assert.Equal(t, "PUSH-SRV: forbidden by receiver", persisted.ErrorMsg, "persisted reason must match")
}

func TestUpdateStream_NoOpWhenSameStateAndReason(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)

	// First transition.
	h.router.updateStream(stream, model.StreamStatePause, "remote paused")

	// Capture persisted state, then do a same-state same-reason call.
	beforeStatus := stream.Status
	beforeReason := stream.ErrorMsg
	h.router.updateStream(stream, model.StreamStatePause, "remote paused")

	assert.Equal(t, beforeStatus, stream.Status, "no-op when state unchanged")
	assert.Equal(t, beforeReason, stream.ErrorMsg, "no-op when reason unchanged")
}

func TestUpdateStream_TransitionsBetweenAllStates(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)

	transitions := []struct {
		state  string
		reason string
	}{
		{model.StreamStatePause, "T2 pre-flight: receiver paused"},
		{model.StreamStateEnabled, "recovery resolved"},
		{model.StreamStateDisable, "401 retry budget exhausted"},
	}
	for _, tr := range transitions {
		h.router.updateStream(stream, tr.state, tr.reason)
		assert.Equal(t, tr.state, stream.Status)
		assert.Equal(t, tr.reason, stream.ErrorMsg)
	}
}

func TestUpdateStream_NilStreamSafe(t *testing.T) {
	h := newTestRouter(t)
	// Should not panic.
	h.router.updateStream(nil, model.StreamStateDisable, "should not panic")
}
