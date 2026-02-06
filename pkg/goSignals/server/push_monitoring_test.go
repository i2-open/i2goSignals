package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/stretchr/testify/assert"
)

func TestClientPushStream_Verification(t *testing.T) {
	mu := sync.Mutex{}
	verifyCount := 0
	verifyState := ""
	statusCount := 0

	mockTx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.URL.Path == "/verify" {
			verifyCount++
			var params model.VerificationParameters
			_ = json.NewDecoder(r.Body).Decode(&params)
			verifyState = params.State
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/status" {
			statusCount++
			status := model.StreamStatus{
				Status: model.StreamStateEnabled,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(status)
			return
		}
		if r.URL.Path == "/.well-known/sse-configuration" {
			txConfig := model.TransmitterConfiguration{
				Issuer:               "mock-tx",
				StatusEndpoint:       r.Host + "/status", // Note: r.Host doesn't have scheme
				VerificationEndpoint: "http://" + r.Host + "/verify",
			}
			// Fix status endpoint to have scheme
			txConfig.StatusEndpoint = "http://" + r.Host + "/status"

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(txConfig)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockTx.Close()

	wellKnownUrl := mockTx.URL + "/.well-known/sse-configuration"

	streamConfig := model.StreamConfiguration{
		Id:                      "test-stream",
		Iss:                     "mock-tx",
		MinVerificationInterval: 1,
		TxWellKnownUrl:          &wellKnownUrl,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
	}

	streamState := &model.StreamStateRecord{
		StreamConfiguration: streamConfig,
		Status:              model.StreamStateEnabled,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider, _ := dbProviders.OpenProvider("", "test_verification")
	pcs := &ReceiverPushStream{
		sa:          &SignalsApplication{Provider: provider},
		stream:      streamState,
		ctx:         ctx,
		cancel:      cancel,
		active:      true,
		eventChan:   make(chan struct{}, 1),
		lastEventAt: time.Now(),
	}

	go pcs.monitorPushStream()

	// Wait for verification request
	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return verifyCount > 0
	}, 5*time.Second, 100*time.Millisecond, "Should have initiated verification")

	mu.Lock()
	state := verifyState
	mu.Unlock()
	assert.NotEmpty(t, state)

	// Simulate receiving verification event
	pcs.handleVerificationEvent(state)

	// verifyCount should still be 1 after reset and another interval
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	currentCount := verifyCount
	mu.Unlock()
	assert.Equal(t, 1, currentCount)

	// Wait for another interval
	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return verifyCount > 1
	}, 5*time.Second, 100*time.Millisecond, "Should have initiated verification again")
}

func TestClientPushStream_FallbackToStatus(t *testing.T) {
	mu := sync.Mutex{}
	statusCount := 0

	mockTx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.URL.Path == "/status" {
			statusCount++
			status := model.StreamStatus{
				Status: model.StreamStateEnabled,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(status)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockTx.Close()

	streamConfig := model.StreamConfiguration{
		Id: "test-stream",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
	}
	// Manually set statusUrl to avoid discovery
	statusUrl := mockTx.URL + "/status"

	provider, _ := dbProviders.OpenProvider("", "test_fallback")
	pcs := &ReceiverPushStream{
		sa:        &SignalsApplication{Provider: provider},
		stream:    &model.StreamStateRecord{StreamConfiguration: streamConfig},
		statusUrl: statusUrl,
		active:    true,
		ctx:       context.Background(),
	}

	pcs.fallbackToStatusCheck()

	mu.Lock()
	assert.Equal(t, 1, statusCount)
	mu.Unlock()
}

func TestReceiverPushStream_Recovery(t *testing.T) {
	provider, _ := dbProviders.OpenProvider("", "test_recovery")
	sid := "recovery-stream"

	streamConfig := model.StreamConfiguration{
		Id: sid,
	}

	// Create the stream in provider so UpdateStreamStatus doesn't fail
	created, _ := provider.CreateStream(streamConfig, "test-project")
	sid = created.Id

	streamState := &model.StreamStateRecord{
		StreamConfiguration: created,
		Status:              model.StreamStatePause,
		ErrorMsg:            "Initial error",
	}

	provider.UpdateStreamStatus(sid, model.StreamStatePause, "Initial error")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rps := &ReceiverPushStream{
		sa:          &SignalsApplication{Provider: provider},
		stream:      streamState,
		ctx:         ctx,
		cancel:      cancel,
		active:      true,
		eventChan:   make(chan struct{}, 1),
		lastEventAt: time.Now(),
	}

	// 1. Test recovery via verification
	rps.mu.Lock()
	rps.verifying = true
	rps.verifyState = "test-state"
	rps.mu.Unlock()

	rps.handleVerificationEvent("test-state")

	assert.Equal(t, model.StreamStateEnabled, rps.stream.Status)
	assert.Empty(t, rps.stream.ErrorMsg)

	// Check provider
	st, _ := provider.GetStreamState(sid)
	assert.Equal(t, model.StreamStateEnabled, st.Status)
	assert.Empty(t, st.ErrorMsg)

	// 2. Test recovery via event
	provider.UpdateStreamStatus(sid, model.StreamStatePause, "Another error")
	rps.mu.Lock()
	rps.stream.Status = model.StreamStatePause
	rps.stream.ErrorMsg = "Another error"
	rps.mu.Unlock()

	rps.notifyEvent()

	// We need to run monitorPushStream to process eventChan
	go rps.monitorPushStream()

	assert.Eventually(t, func() bool {
		rps.mu.RLock()
		defer rps.mu.RUnlock()
		return rps.stream.Status == model.StreamStateEnabled && rps.stream.ErrorMsg == ""
	}, 2*time.Second, 100*time.Millisecond)

	// Check provider
	st, _ = provider.GetStreamState(sid)
	assert.Equal(t, model.StreamStateEnabled, st.Status)
	assert.Empty(t, st.ErrorMsg)
}
