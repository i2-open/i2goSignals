package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	statusChecks := 0

	// Mock transmitter
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			statusChecks++
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

	// Poll for the receiver to observe the transmitter's paused status rather
	// than sleeping a fixed interval (check interval is 0.2s).
	assert.Eventually(t, func() bool {
		st, err := instance.GetStreamState(streamID)
		return err == nil && st.Status == model.StreamStatePause &&
			strings.Contains(st.ErrorMsg, "Transmitter stream is paused: testing pause")
	}, 2*time.Second, 20*time.Millisecond, "receiver should reflect the transmitter's paused status")

	// Now change status to enabled and confirm the status-check loop keeps
	// running (it must poll /status at least once more) instead of sleeping.
	mu.Lock()
	checksBefore := statusChecks
	statusResponse.Status = model.StreamStateEnabled
	statusResponse.Reason = ""
	mu.Unlock()

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return statusChecks > checksBefore
	}, 2*time.Second, 20*time.Millisecond, "status-check loop should keep polling after status flips to enabled")
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

	// Poll for the receiver to observe the transmitter's disabled status rather
	// than sleeping a fixed interval.
	assert.Eventually(t, func() bool {
		st, err := instance.GetStreamState(streamID)
		return err == nil && st.Status == model.StreamStateDisable &&
			strings.Contains(st.ErrorMsg, "Transmitter stream is disabled: testing disable")
	}, 2*time.Second, 20*time.Millisecond, "receiver should reflect the transmitter's disabled status")
}
