package test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestPollUnauthorizedTightLoop(t *testing.T) {
	// Ensure default delay is used or set it explicitly
	_ = os.Unsetenv("POLL_UNAUTHORIZED_RETRY_DELAY")

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
	createdConfig, err := instance.provider.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait a bit to observe the loop
	time.Sleep(100 * time.Millisecond)

	finalCount := atomic.LoadInt32(&pollCount)
	t.Logf("Poll count after 100ms: %d", finalCount)

	// Check that it's in Pause state
	updatedState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "unauthorized")

	// If it's a tight loop, the count will be very high (hundreds or thousands)
	assert.True(t, finalCount < 10, "Should not be in a tight loop. Count: %d", finalCount)
}

func TestPollUnauthorizedRetry(t *testing.T) {
	// Set a short retry delay for the test
	t.Setenv("POLL_UNAUTHORIZED_RETRY_DELAY", "0.2")
	t.Setenv("POLL_UNAUTHORIZED_RETRY_LIMIT", "2")

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
	instance, err := createServer(t, "test_unauthorized_retry", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream
	streamID := "test-poll-unauthorized-retry"
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
	createdConfig, err := instance.provider.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait long enough for at least 1 failure but not enough for 2 failures
	time.Sleep(100 * time.Millisecond)

	finalCount := atomic.LoadInt32(&pollCount)
	t.Logf("Poll count after 100ms: %d", finalCount)

	// Check that it's in Pause state after the first failure
	updatedState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "unauthorized")

	// Now wait for the second failure which should disable the stream
	time.Sleep(200 * time.Millisecond)

	updatedState, err = instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "unauthorized attempts")

	finalCount = atomic.LoadInt32(&pollCount)
	assert.Equal(t, int32(2), finalCount, "Should have attempted 2 times")
}

func TestPollUnauthorizedLimit(t *testing.T) {
	// Set a very short retry delay for the test
	t.Setenv("POLL_UNAUTHORIZED_RETRY_DELAY", "0.01")
	t.Setenv("POLL_UNAUTHORIZED_RETRY_LIMIT", "2")

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
	instance, err := createServer(t, "test_unauthorized_limit", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream
	streamID := "test-poll-unauthorized-limit"
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
	createdConfig, err := instance.provider.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait enough time for 2 attempts (initial + 1 retry)
	// 0.01s delay * 1 retry = 0.01s + some processing time.
	// 100ms should be plenty.
	time.Sleep(100 * time.Millisecond)

	finalCount := atomic.LoadInt32(&pollCount)
	t.Logf("Poll count: %d", finalCount)

	// Check that it's in Disable state
	updatedState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, updatedState.Status, "Should be disabled after 2 attempts")
	assert.Contains(t, updatedState.ErrorMsg, "unauthorized attempts")

	// Should have attempted exactly 2 times
	// Attempt 1: 401, count=1, retry
	// Attempt 2: 401, count=2, disable
	assert.Equal(t, int32(2), finalCount, "Should have attempted 2 times")
}

func TestPollUnauthorizedLimitDefault(t *testing.T) {
	// Set a very short retry delay for the test
	t.Setenv("POLL_UNAUTHORIZED_RETRY_DELAY", "0.01")
	// Use default limit (now 10)

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
	instance, err := createServer(t, "test_unauthorized_default", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a polling receiver stream
	streamID := "test-poll-unauthorized-default"
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
	createdConfig, err := instance.provider.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
	assert.NoError(t, err)
	streamID = createdConfig.Id

	// Get state
	streamState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)

	// Start receiver
	ps := instance.app.HandleReceiver(streamState)
	assert.NotNil(t, ps)

	// Wait for at least 3 attempts to prove it didn't stop at 2
	time.Sleep(100 * time.Millisecond)

	finalCount := atomic.LoadInt32(&pollCount)
	t.Logf("Poll count after 100ms: %d", finalCount)

	// Check that it's NOT disabled yet
	updatedState, err := instance.provider.GetStreamState(streamID)
	assert.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, updatedState.Status, "Should still be in Pause state after 3+ attempts")

	assert.True(t, finalCount >= 3, "Should have attempted at least 3 times. Count: %d", finalCount)
}
