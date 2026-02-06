package server

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestReceiverPushStream_RFC8935Only(t *testing.T) {
	sa := &SignalsApplication{
		pushClients: make(map[string]*ReceiverPushStream),
	}

	streamId := "rfc8935-only-stream"

	streamConfig := model.StreamConfiguration{
		Id:                      streamId,
		MinVerificationInterval: 1,
		InactivityTimeout:       2,
		TxWellKnownUrl:          nil, // SSF disabled
	}

	streamState := &model.StreamStateRecord{
		StreamConfiguration: streamConfig,
		Status:              model.StreamStateEnabled,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rps := &ReceiverPushStream{
		sa:          sa,
		stream:      streamState,
		active:      true,
		ctx:         ctx,
		cancel:      cancel,
		eventChan:   make(chan struct{}, 1),
		lastEventAt: time.Now(),
	}

	go rps.monitorPushStream()

	// Wait for intervals to pass
	time.Sleep(2500 * time.Millisecond)

	rps.mu.RLock()
	verifying := rps.verifying
	rps.mu.RUnlock()

	assert.False(t, verifying, "Should NOT be verifying in RFC8935 only mode")
}

func TestReceiverPushStream_SSFEnabled(t *testing.T) {
	sa := &SignalsApplication{
		pushClients: make(map[string]*ReceiverPushStream),
	}

	streamId := "ssf-enabled-stream"
	wellKnown := "http://example.com/.well-known/sse-configuration"

	streamConfig := model.StreamConfiguration{
		Id:                      streamId,
		MinVerificationInterval: 1,
		TxWellKnownUrl:          &wellKnown,
	}

	streamState := &model.StreamStateRecord{
		StreamConfiguration: streamConfig,
		Status:              model.StreamStateEnabled,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rps := &ReceiverPushStream{
		sa:          sa,
		stream:      streamState,
		active:      true,
		ctx:         ctx,
		cancel:      cancel,
		eventChan:   make(chan struct{}, 1),
		lastEventAt: time.Now(),
		verifyUrl:   "http://example.com/verify",
	}

	// We expect initiateVerification to be called, which will eventually set verifying = true
	// even if it fails later due to missing endpoints.
	go rps.monitorPushStream()

	// Wait for interval to pass
	assert.Eventually(t, func() bool {
		rps.mu.RLock()
		defer rps.mu.RUnlock()
		return rps.verifying
	}, 3*time.Second, 100*time.Millisecond, "Should be verifying in SSF enabled mode")
}

func TestSignalsApplication_handleClientPushReceiver_Logging(t *testing.T) {
	sa := &SignalsApplication{
		pushClients: make(map[string]*ReceiverPushStream),
	}

	streamId := "log-test-stream"
	streamConfig := model.StreamConfiguration{
		Id:             streamId,
		TxWellKnownUrl: nil,
	}
	streamState := &model.StreamStateRecord{
		StreamConfiguration: streamConfig,
	}

	// This will trigger the Info log
	rps := sa.handleClientPushReceiver(streamState)
	assert.NotNil(t, rps)

	// Cleanup
	rps.Close()
}
