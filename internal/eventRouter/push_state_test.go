package eventRouter

import (
	"testing"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRouter(t *testing.T) (*router, dbProviders.DbProviderInterface) {
	t.Helper()
	t.Setenv("MEM_DIRECTORY", t.TempDir())
	provider, err := dbProviders.OpenProvider("memorydb:", "push_state_test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })
	r := NewRouter(provider, "node-test").(*router)
	t.Cleanup(r.Shutdown)
	return r, provider
}

func mustCreateTestStream(t *testing.T, provider dbProviders.DbProviderInterface, projectId string) *model.StreamStateRecord {
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
	created, err := provider.CreateStream(cfg, authUtil.ConvertProject(projectId))
	require.NoError(t, err)
	state, err := provider.GetStreamState(created.Id)
	require.NoError(t, err)
	require.NotNil(t, state)
	return state
}

func projectIdFromProvider(t *testing.T, provider dbProviders.DbProviderInterface) string {
	t.Helper()
	iat, err := provider.GetAuthIssuer().IssueProjectIat(nil)
	require.NoError(t, err)
	parsed, err := provider.GetAuthIssuer().ParseAuthToken(iat)
	require.NoError(t, err)
	return parsed.ProjectId
}

func TestUpdateStream_PersistsAndMutatesInMemory(t *testing.T) {
	r, provider := newTestRouter(t)
	projectId := projectIdFromProvider(t, provider)
	stream := mustCreateTestStream(t, provider, projectId)
	require.Equal(t, model.StreamStateEnabled, stream.Status)

	r.updateStream(stream, model.StreamStateDisable, "PUSH-SRV: forbidden by receiver")

	assert.Equal(t, model.StreamStateDisable, stream.Status, "in-memory stream record must reflect new status")
	assert.Equal(t, "PUSH-SRV: forbidden by receiver", stream.ErrorMsg, "in-memory stream record must reflect new reason")

	persisted, err := provider.GetStreamState(stream.StreamConfiguration.Id)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, persisted.Status, "persisted status must match")
	assert.Equal(t, "PUSH-SRV: forbidden by receiver", persisted.ErrorMsg, "persisted reason must match")
}

func TestUpdateStream_NoOpWhenSameStateAndReason(t *testing.T) {
	r, provider := newTestRouter(t)
	projectId := projectIdFromProvider(t, provider)
	stream := mustCreateTestStream(t, provider, projectId)

	// First transition.
	r.updateStream(stream, model.StreamStatePause, "remote paused")

	// Capture persisted state, then do a same-state same-reason call.
	beforeStatus := stream.Status
	beforeReason := stream.ErrorMsg
	r.updateStream(stream, model.StreamStatePause, "remote paused")

	assert.Equal(t, beforeStatus, stream.Status, "no-op when state unchanged")
	assert.Equal(t, beforeReason, stream.ErrorMsg, "no-op when reason unchanged")
}

func TestUpdateStream_TransitionsBetweenAllStates(t *testing.T) {
	r, provider := newTestRouter(t)
	projectId := projectIdFromProvider(t, provider)
	stream := mustCreateTestStream(t, provider, projectId)

	transitions := []struct {
		state  string
		reason string
	}{
		{model.StreamStatePause, "T2 pre-flight: receiver paused"},
		{model.StreamStateEnabled, "recovery resolved"},
		{model.StreamStateDisable, "401 retry budget exhausted"},
	}
	for _, tr := range transitions {
		r.updateStream(stream, tr.state, tr.reason)
		assert.Equal(t, tr.state, stream.Status)
		assert.Equal(t, tr.reason, stream.ErrorMsg)
	}
}

func TestUpdateStream_NilStreamSafe(t *testing.T) {
	r, _ := newTestRouter(t)
	// Should not panic.
	r.updateStream(nil, model.StreamStateDisable, "should not panic")
}
