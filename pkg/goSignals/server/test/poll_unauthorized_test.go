package test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestPollUnauthorizedTightLoop(t *testing.T) {
	var pollCount int32

	// Mock transmitter returning 401 Unauthorized
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/poll" {
			atomic.AddInt32(&pollCount, 1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
	}))
	defer ts.Close()

	// Create server with mock provider
	instance, err := createServer(t, "test_unauthorized", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream
	streamID := "test-poll-unauthorized"
	streamConfig := model.StreamConfiguration{
		Id:            streamID,
		Iss:           "transmitter.example.com",
		IssuerJWKSUrl: ts.URL + "/jwks",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: ts.URL + "/poll",
				PollConfig:  &model.PollParameters{},
			},
		},
	}

	// Add stream to provider
	createdConfig, err := instance.provider.CreateStream(streamConfig, instance.projectId)
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait a bit to observe the loop
	time.Sleep(500 * time.Millisecond)

	finalCount := atomic.LoadInt32(&pollCount)
	t.Logf("Poll count after 500ms: %d", finalCount)

	// Check that it's in Disable state
	updatedState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "Unauthorized")

	// If it's a tight loop, the count will be very high (hundreds or thousands)
	assert.True(t, finalCount < 10, "Should not be in a tight loop. Count: %d", finalCount)
}
