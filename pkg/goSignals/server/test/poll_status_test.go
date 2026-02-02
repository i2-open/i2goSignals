package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestPollTransmitterStatus(t *testing.T) {
	// Set short check interval for testing
	os.Setenv("POLL_STATUS_CHECK_INTERVAL", "0.2")
	defer os.Unsetenv("POLL_STATUS_CHECK_INTERVAL")

	statusResponse := model.StreamStatus{
		Status: model.StreamStatePause,
		Reason: "testing pause",
	}

	// Mock transmitter
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(statusResponse)
			return
		}
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[]}`))
			return
		}
		if r.URL.Path == "/poll" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(model.PollResponse{Sets: make(map[string]string)})
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
	createdConfig, err := instance.provider.CreateStream(streamConfig, instance.projectId)
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, _ := instance.provider.GetStreamState(streamID)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait a bit for the first status check
	time.Sleep(300 * time.Millisecond)

	// Check status - should be paused in provider
	updatedState, _ := instance.provider.GetStreamState(streamID)
	assert.Equal(t, model.StreamStatePause, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "Transmitter stream is paused: testing pause")

	// Now change status to enabled
	statusResponse.Status = model.StreamStateEnabled
	statusResponse.Reason = ""

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
			json.NewEncoder(w).Encode(model.StreamStatus{
				Status: model.StreamStateDisable,
				Reason: "testing disable",
			})
			return
		}
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[]}`))
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
	createdConfig, err := instance.provider.CreateStream(streamConfig, instance.projectId)
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, _ := instance.provider.GetStreamState(streamID)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait a bit
	time.Sleep(300 * time.Millisecond)

	// Check status - should be disabled
	updatedState, _ := instance.provider.GetStreamState(streamID)
	assert.Equal(t, model.StreamStateDisable, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "Transmitter stream is disabled: testing disable")
}
