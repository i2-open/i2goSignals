package test

import (
	"os"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestPollBackoffRetry(t *testing.T) {
	// Set short backoff for testing
	os.Setenv("POLL_RETRY_BASE_DELAY", "0.1")
	os.Setenv("POLL_RETRY_MAX_DELAY", "0.3")
	os.Setenv("POLL_RETRY_BACKOFF_FACTOR", "2.0")
	os.Setenv("POLL_RETRY_LIMIT", "1.0") // 1 second retry limit
	defer os.Unsetenv("POLL_RETRY_BASE_DELAY")
	defer os.Unsetenv("POLL_RETRY_MAX_DELAY")
	defer os.Unsetenv("POLL_RETRY_BACKOFF_FACTOR")
	defer os.Unsetenv("POLL_RETRY_LIMIT")

	// Create server with mock provider
	instance, err := createServer(t, "test_backoff", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream with a bogus URL
	streamID := "test-poll-backoff"
	streamConfig := model.StreamConfiguration{
		Id:  streamID,
		Iss: "http://transmitter.example.com",
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

	// Add stream to provider
	createdConfig, err := instance.provider.CreateStream(streamConfig, instance.projectId)
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
	updatedState, _ := instance.provider.GetStreamState(streamID)
	assert.Equal(t, model.StreamStatePause, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "retry being attempted")

	// Wait for more retries and eventually exceeding the limit
	// retryLimit is 1s. We've already waited 0.2s.
	// 0.1s (retry 1) + 0.2s (retry 2) + 0.3s (retry 3) = 0.6s total delay so far roughly.
	// Total time elapsed since first error will reach 1s soon.

	time.Sleep(1500 * time.Millisecond)

	// Now it should be disabled
	finalState, _ := instance.provider.GetStreamState(streamID)
	assert.Equal(t, model.StreamStateDisable, finalState.Status)
	assert.Contains(t, finalState.ErrorMsg, "connection error")
}
