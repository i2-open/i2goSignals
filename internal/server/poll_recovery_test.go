package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

// TestClientPollStream_Recovery: a receiver retrying a failed poll has not
// paused (#310). While it retries, its status stays enabled and the reason says
// why; the next successful poll clears the reason.
func TestClientPollStream_Recovery(t *testing.T) {
	cases := []struct {
		name       string
		failStatus int
		reason     string
	}{
		{"connection error", http.StatusServiceUnavailable, "retry being attempted"},
		{"unauthorized", http.StatusUnauthorized, "unauthorized response (401), retrying"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
			t.Setenv("I2SIG_POLL_AUTH_RETRY_DELAY", "0.2")
			persistence, _ := dbProviders.OpenPersistence("", "test_poll_recovery")
			sid := "recovery-poll-stream"

			var serverShouldFail atomic.Bool
			serverShouldFail.Store(true)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serverShouldFail.Load() {
					w.WriteHeader(tc.failStatus)
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

			// Create the stream via the StreamService.
			atx := authSupport.ConvertProject("test-project")
			createCtx := context.WithValue(context.Background(), authSupport.AuthContextKey, atx)
			created, _ := persistence.StreamService.CreateStream(createCtx, model.StreamStateRecord{StreamConfiguration: streamConfig}, atx.ProjectId, nil)
			sid = created.Id

			streamState := &model.StreamStateRecord{
				StreamConfiguration: created,
				Status:              model.StreamStateEnabled,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ps := &ClientPollStream{
				sa:     newTestApplication(persistence),
				stream: streamState,
				active: true,
				ctx:    ctx,
				cancel: cancel,
			}

			// 1. Trigger a failure
			go ps.runPollLoop(sid)

			assert.Eventually(t, func() bool {
				st, err := persistence.StreamService.GetStreamState(context.Background(), sid)
				return err == nil && st.Status == model.StreamStateEnabled && strings.Contains(st.ErrorMsg, tc.reason)
			}, 2*time.Second, 50*time.Millisecond, "a retrying receiver stays enabled with a reason")

			// 2. Make it succeed
			serverShouldFail.Store(false)

			// Wait for recovery: the next successful poll clears the reason.
			assert.Eventually(t, func() bool {
				st, err := persistence.StreamService.GetStreamState(context.Background(), sid)
				return err == nil && st.Status == model.StreamStateEnabled && st.ErrorMsg == ""
			}, 5*time.Second, 50*time.Millisecond, "a successful poll clears the retry reason")
		})
	}
}
