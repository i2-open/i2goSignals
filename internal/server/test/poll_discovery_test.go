package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestPollStatusDiscovery(t *testing.T) {
	var requestedUrl string
	var mu sync.Mutex
	var statusEndpoint string

	ts_final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		path := r.URL.Path
		mu.Unlock()

		if path == "/.well-known/sse-configuration" {
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			endpoint := statusEndpoint
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
				StatusEndpoint: endpoint,
			})
			return
		}
		if path == "/discovered-status" {
			mu.Lock()
			requestedUrl = r.URL.String()
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
			return
		}
		if path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		if path == "/poll" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.PollResponse{Sets: make(map[string]string)})
			return
		}
	}))
	defer ts_final.Close()

	tests := []struct {
		name           string
		statusEndpoint string
		expectedQuery  string
	}{
		{
			name:           "No stream_id in discovery",
			statusEndpoint: "http://" + ts_final.Listener.Addr().String() + "/discovered-status",
			expectedQuery:  "stream_id=", // will be followed by actual ID
		},
		{
			name:           "Already has stream_id in discovery",
			statusEndpoint: "http://" + ts_final.Listener.Addr().String() + "/discovered-status?stream_id=existing-id",
			expectedQuery:  "stream_id=existing-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mu.Lock()
			requestedUrl = ""
			statusEndpoint = tt.statusEndpoint
			mu.Unlock()

			instance, err := createServer(t, "test_discovery_"+tt.name, true)
			assert.NoError(t, err)
			defer instance.app.Shutdown()

			wellKnownUrl := ts_final.URL + "/.well-known/sse-configuration"
			streamConfig := model.StreamConfiguration{
				Id:             "test-stream-" + tt.name,
				TxWellKnownUrl: &wellKnownUrl,
				Iss:            "transmitter.example.com",
				IssuerJWKSUrl:  ts_final.URL + "/jwks",
				Delivery: &model.OneOfStreamConfigurationDelivery{
					PollReceiveMethod: &model.PollReceiveMethod{
						Method:      model.ReceivePoll,
						EndpointUrl: ts_final.URL + "/poll",
						PollConfig: &model.PollParameters{
							ReturnImmediately: true,
						},
					},
				},
			}

			createdConfig, err := instance.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
			assert.NoError(t, err)

			streamState, err := instance.GetStreamState(createdConfig.Id)
			assert.NoError(t, err)
			ps := instance.app.HandleReceiver(streamState)
			assert.NotNil(t, ps)

			// Wait for status check
			assert.Eventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()
				return requestedUrl != ""
			}, 5*time.Second, 100*time.Millisecond)

			mu.Lock()
			actualUrl := requestedUrl
			mu.Unlock()

			if tt.name == "No stream_id in discovery" {
				assert.Contains(t, actualUrl, "stream_id="+createdConfig.Id)
			} else {
				assert.Contains(t, actualUrl, tt.expectedQuery)
				assert.NotContains(t, actualUrl, "stream_id="+createdConfig.Id)
			}

			instance.app.CloseReceiver(createdConfig.Id)
		})
	}
}
