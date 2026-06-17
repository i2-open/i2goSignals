package test

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pollStreamConfig returns a minimal transmitter POLL stream config with no aud,
// so CreateStream exercises the transmitter-side default-aud resolution.
func pollStreamConfig() model.StreamConfiguration {
	return model.StreamConfiguration{
		EventsRequested: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}
}

// TestCreateStreamDefaultsAudToClientId pins the transmitter contract: when the
// receiver asserts no aud, the transmitter populates it from the most specific
// stable receiver identity available — the registered client_id of a locally
// issued token. aud is Read-Only / transmitter-asserted (SSF 1.0 §7.1.1) and is
// echoed into every SET, so it must never be empty.
func TestCreateStreamDefaultsAudToClientId(t *testing.T) {
	instance, err := createServer(t, "stream_aud_default_clientid_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	authCtx := &authSupport.AuthContext{
		ProjectId: instance.projectId,
		Eat:       &authSupport.EventAuthToken{ClientId: "client-abc123", ProjectId: instance.projectId},
	}

	created, err := instance.CreateStream(pollStreamConfig(), authCtx)
	require.NoError(t, err)
	assert.Equal(t, []string{"client-abc123"}, created.Aud,
		"a locally issued token's client_id must become the default aud")
}

// TestCreateStreamDefaultsAudToProjectIdFloor pins the floor: an OAuth/STS caller
// carries no local EAT (and therefore no client_id), so the default aud falls back
// to the project id, which is always present.
func TestCreateStreamDefaultsAudToProjectIdFloor(t *testing.T) {
	instance, err := createServer(t, "stream_aud_default_projectid_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// ConvertProject yields an AuthContext with ProjectId set and no Eat — the
	// shape of an OAuth/STS-validated caller.
	created, err := instance.CreateStream(pollStreamConfig(), authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err)
	assert.Equal(t, []string{instance.projectId}, created.Aud,
		"with no client_id the default aud must fall back to the project id")
}

// TestCreateStreamHonorsRequestedAud pins that a receiver-asserted aud (e.g. a
// domain) is never overwritten by the default — the request wins.
func TestCreateStreamHonorsRequestedAud(t *testing.T) {
	instance, err := createServer(t, "stream_aud_honor_request_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	cfg := pollStreamConfig()
	cfg.Aud = []string{"https://rp.example.com"}

	authCtx := &authSupport.AuthContext{
		ProjectId: instance.projectId,
		Eat:       &authSupport.EventAuthToken{ClientId: "client-abc123", ProjectId: instance.projectId},
	}

	created, err := instance.CreateStream(cfg, authCtx)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://rp.example.com"}, created.Aud,
		"a receiver-asserted aud must be preserved, not replaced by the default")
}
