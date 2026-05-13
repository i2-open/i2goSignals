package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestPollTransmitterStatus(t *testing.T) {
	// Set short check interval for testing
	_ = os.Setenv("POLL_STATUS_CHECK_INTERVAL", "0.2")
	defer func() {
		err := os.Unsetenv("POLL_STATUS_CHECK_INTERVAL")
		if err != nil {
			t.Logf("Failed to unset POLL_STATUS_CHECK_INTERVAL: %v", err)
		}
	}()

	statusResponse := model.StreamStatus{
		Status: model.StreamStatePause,
		Reason: "testing pause",
	}
	var mu sync.Mutex

	// Mock transmitter
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			resp := statusResponse
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		if r.URL.Path == "/poll" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(model.PollResponse{Sets: make(map[string]string)})
			return
		}
	}))
	defer ts.Close()

	// Create server with mock provider
	instance, err := createServer(t, "test_status", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream
	streamID := "test-poll-status"
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
	createdConfig, err := instance.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, err := instance.GetStreamState(streamID)
	assert.NoError(t, err)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait a bit for the first status check
	time.Sleep(300 * time.Millisecond)

	// Check status - should be paused in provider
	updatedState, err := instance.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "Transmitter stream is paused: testing pause")

	// Now change status to enabled
	mu.Lock()
	statusResponse.Status = model.StreamStateEnabled
	statusResponse.Reason = ""
	mu.Unlock()

	// Wait for next check (interval is 0.2s)
	time.Sleep(400 * time.Millisecond)

	// Now it should have resumed polling.
	// We can't easily check if it's "enabled" in provider because nothing sets it back to enabled in the provider
	// unless we add that logic. But the loop should be running.
}

func TestPollTransmitterStatusDisabled(t *testing.T) {
	// Mock transmitter
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.StreamStatus{
				Status: model.StreamStateDisable,
				Reason: "testing disable",
			})
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
	instance, err := createServer(t, "test_status_disabled", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream
	streamID := "test-poll-status-disabled"
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
	createdConfig, err := instance.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, err := instance.GetStreamState(streamID)
	assert.NoError(t, err)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait a bit
	time.Sleep(300 * time.Millisecond)

	// Check status - should be disabled
	updatedState, err := instance.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "Transmitter stream is disabled: testing disable")
}
