package test

import (
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestPollBackoffRetry(t *testing.T) {
	// Set short backoff for testing
	t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "0.1")
	t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "0.3")
	t.Setenv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "2.0")
	t.Setenv("I2SIG_POLL_RETRY_LIMIT", "1.0") // 1.0 second retry limit

	// Create server with mock provider
	instance, err := createServer(t, "test_backoff", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream with a bogus URL
	streamID := "test-poll-backoff"
	streamConfig := model.StreamConfiguration{
		Id:            streamID,
		Iss:           "transmitter.example.com",
		IssuerJWKSUrl: "http://localhost:12345/.well-known/jwks.json", // Valid URL format but will cause connection error (temporary)
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: "http://localhost:12345/bogus", // Likely to cause connection error
				PollConfig: &model.PollParameters{
					ReturnImmediately: true,
				},
			},
		},
	}

	atx := authUtil.AuthContext{
		ProjectId: instance.projectId,
	}
	// Add stream to provider
	createdConfig, err := instance.CreateStream(streamConfig, &atx)
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get the initial state from provider
	streamState, err := instance.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.NotNil(t, streamState)

	// Start the receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Poll for the transient Pause state (retry in progress, base delay 0.1s)
	// rather than sleeping a fixed interval.
	assert.Eventually(t, func() bool {
		st, err := instance.GetStreamState(streamID)
		return err == nil && st.Status == model.StreamStatePause &&
			strings.Contains(st.ErrorMsg, "retry being attempted")
	}, 2*time.Second, 20*time.Millisecond, "stream should pause with a retry-in-progress message")

	// After the retry limit (1.0s) is exceeded the stream must be disabled.
	assert.Eventually(t, func() bool {
		st, err := instance.GetStreamState(streamID)
		return err == nil && st.Status == model.StreamStateDisable
	}, 3*time.Second, 20*time.Millisecond, "stream should disable after exceeding the retry limit")

	finalState, err := instance.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Contains(t, finalState.ErrorMsg, "connection error")
}

func TestPollReceiverPermanentJwksError(t *testing.T) {
	// Create server with mock provider
	instance, err := createServer(t, "test_jwks_error", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream with an invalid JWKS URL (permanent error)
	streamID := "test-jwks-permanent-error"
	streamConfig := model.StreamConfiguration{
		Id:            streamID,
		Iss:           "invalid-protocol-in-issuer",
		IssuerJWKSUrl: "invalid-protocol://invalid-protocol-in-issuer", // This will create an invalid JWKS URL path
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: "http://localhost:8888/poll",
				PollConfig: &model.PollParameters{
					ReturnImmediately: true,
				},
			},
		},
	}
	atx := authUtil.AuthContext{
		ProjectId: instance.projectId,
	}

	// Add stream to provider
	createdConfig, err := instance.CreateStream(streamConfig, &atx)
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// A permanent JWKS error disables the stream almost immediately; poll for it
	// rather than sleeping a fixed interval.
	assert.Eventually(t, func() bool {
		st, err := instance.GetStreamState(streamID)
		return err == nil && st != nil && st.Status == model.StreamStateDisable
	}, 2*time.Second, 20*time.Millisecond, "permanent JWKS error should disable the stream")

	// Get the stream state - it should be disabled due to permanent JWKS error
	streamState, err := instance.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.NotNil(t, streamState)
	assert.Equal(t, model.StreamStateDisable, streamState.Status)
	assert.Contains(t, streamState.ErrorMsg, "Error retrieving issuer JWKS public key")
	assert.Contains(t, streamState.ErrorMsg, "unsupported protocol scheme")
}
