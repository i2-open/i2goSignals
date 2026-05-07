package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestClientPollStream_Recovery(t *testing.T) {
	provider, _ := dbProviders.OpenProvider("", "test_poll_recovery")
	sid := "recovery-poll-stream"

	serverShouldFail := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serverShouldFail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sets": {}}`)
	}))
	defer ts.Close()

	streamConfig := model.StreamConfiguration{
		Id: sid,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: ts.URL,
				PollConfig: &model.PollParameters{
					ReturnImmediately: true,
				},
			},
		},
	}

	// Create the stream in provider
	created, _ := provider.CreateStream(streamConfig, authUtil.ConvertProject("test-project"))
	sid = created.Id

	streamState := &model.StreamStateRecord{
		StreamConfiguration: created,
		Status:              model.StreamStateEnabled,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ps := &ClientPollStream{
		sa:     newTestApplication(provider),
		stream: streamState,
		active: true,
		ctx:    ctx,
		cancel: cancel,
	}

	// 1. Trigger a failure
	go ps.runPollLoop(sid)

	assert.Eventually(t, func() bool {
		ps.mu.RLock()
		defer ps.mu.RUnlock()
		return ps.stream.Status == model.StreamStatePause && ps.stream.ErrorMsg != ""
	}, 2*time.Second, 100*time.Millisecond, "Should be paused on failure")

	// Verify provider too
	st, _ := provider.GetStreamState(sid)
	assert.Equal(t, model.StreamStatePause, st.Status)

	// 2. Make it succeed
	serverShouldFail = false

	// Wait for recovery
	assert.Eventually(t, func() bool {
		ps.mu.RLock()
		defer ps.mu.RUnlock()
		return ps.stream.Status == model.StreamStateEnabled && ps.stream.ErrorMsg == ""
	}, 5*time.Second, 200*time.Millisecond, "Should be recovered to enabled")

	// Verify provider
	st, _ = provider.GetStreamState(sid)
	assert.Equal(t, model.StreamStateEnabled, st.Status)
	assert.Empty(t, st.ErrorMsg)
}
