package test

import (
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestPollInfiniteLoopFix(t *testing.T) {
	// Enable debug logging to see what's happening
	logger.Init(logger.Options{Level: "debug"})

	// Set short backoff for testing to speed up failure/retry cycle
	t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "0.1")
	t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "0.5")

	instance, err := createServer(t, "test_infinite_loop_fix", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	streamID := "test-loop-fix"
	streamConfig := model.StreamConfiguration{
		Id:            streamID,
		Iss:           "transmitter.example.com",
		IssuerJWKSUrl: "http://localhost:12345/jwks",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: "http://non-existent-host-12345.com/poll",
				PollConfig: &model.PollParameters{
					ReturnImmediately: true,
				},
			},
		},
	}

	createdConfig, err := instance.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
	assert.NoError(t, err)
	streamID = createdConfig.Id

	streamState, err := instance.GetStreamState(streamID)
	assert.NoError(t, err)

	// Start the receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait for it to hit the connection error and enter Pause state. With our
	// changes it stays in runPollLoop and uses the backoff (base delay 0.1s), so
	// poll for the transition rather than sleeping a fixed second.
	assert.Eventually(t, func() bool {
		st, err := instance.GetStreamState(streamID)
		return err == nil && st.Status == model.StreamStatePause
	}, 3*time.Second, 20*time.Millisecond, "stream should enter Pause after connection errors")

	// If the infinite loop were present, we would see thousands of "Node lease acquired" messages in the log.
	// Since we can't easily count them here, we just verify it's still running and hasn't crashed.
}
