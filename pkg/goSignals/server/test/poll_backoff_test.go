package test

import (
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestPollBackoffRetry(t *testing.T) {
	// Set short backoff for testing
	t.Setenv("POLL_RETRY_BASE_DELAY", "0.1")
	t.Setenv("POLL_RETRY_MAX_DELAY", "0.3")
	t.Setenv("POLL_RETRY_BACKOFF_FACTOR", "2.0")
	t.Setenv("POLL_RETRY_LIMIT", "1.0") // 1 second retry limit

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
	createdConfig, err := instance.provider.CreateStream(streamConfig, &atx)
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get the initial state from provider
	streamState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.NotNil(t, streamState)

	// Start the receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait for first retry
	// Delay 0 is 0.1s
	time.Sleep(200 * time.Millisecond)

	// Check provider status - it should be "paused" with "retry being attempted"
	updatedState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "retry being attempted")

	// Wait for more retries and eventually exceeding the limit
	// retryLimit is 1s.
	time.Sleep(2000 * time.Millisecond)

	// Now it should be disabled
	finalState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, finalState.Status)
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
				EndpointUrl: "http://localhost:9080/poll",
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
	createdConfig, err := instance.provider.CreateStream(streamConfig, &atx)
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Give it a moment to process
	time.Sleep(100 * time.Millisecond)

	// Get the stream state - it should be disabled due to permanent JWKS error
	streamState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.NotNil(t, streamState)

	// Stream should be disabled immediately due to permanent error
	assert.Equal(t, model.StreamStateDisable, streamState.Status)
	assert.Contains(t, streamState.ErrorMsg, "Error retrieving issuer JWKS public key")
	assert.Contains(t, streamState.ErrorMsg, "unsupported protocol scheme")
}
