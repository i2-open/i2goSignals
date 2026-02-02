package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestPollStatusUrlTransformation(t *testing.T) {
	var requestedUrl string
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}

		// Capture the URL called for status (GET)
		if r.Method == http.MethodGet {
			mu.Lock()
			requestedUrl = r.URL.String()
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.StreamStatus{
				Status: model.StreamStateEnabled,
			})
			return
		}

		// Poll requests (POST)
		if r.Method == http.MethodPost {
			time.Sleep(100 * time.Millisecond) // Slow down the loop
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(model.PollResponse{Sets: make(map[string]string)})
			return
		}
	}))
	defer ts.Close()

	instance, err := createServer(t, "test_url_transform", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	tests := []struct {
		name        string
		endpointUrl string
		expectedUrl string
	}{
		{
			name:        "Path parameter format",
			endpointUrl: ts.URL + "/poll/123",
			expectedUrl: "/status?stream_id=123",
		},
		{
			name:        "Query parameter format",
			endpointUrl: ts.URL + "/poll?stream_id=456",
			expectedUrl: "/status?stream_id=456",
		},
		{
			name:        "With prefix and path parameter",
			endpointUrl: ts.URL + "/api/v1/poll/789",
			expectedUrl: "/api/v1/status?stream_id=789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mu.Lock()
			requestedUrl = ""
			mu.Unlock()

			streamID := "test-" + tt.name
			streamConfig := model.StreamConfiguration{
				Id:            streamID,
				Iss:           "transmitter.example.com",
				IssuerJWKSUrl: ts.URL + "/jwks",
				Delivery: &model.OneOfStreamConfigurationDelivery{
					PollReceiveMethod: &model.PollReceiveMethod{
						Method:      model.ReceivePoll,
						EndpointUrl: tt.endpointUrl,
						PollConfig:  &model.PollParameters{},
					},
				},
			}

			createdConfig, err := instance.provider.CreateStream(streamConfig, instance.projectId)
			assert.NoError(t, err)

			streamState, _ := instance.provider.GetStreamState(createdConfig.Id)
			ps := instance.app.HandleReceiver(streamState)
			assert.NotNil(t, ps)

			// Wait for status check
			assert.Eventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()
				return requestedUrl != ""
			}, 2*time.Second, 100*time.Millisecond)

			mu.Lock()
			actualUrl := requestedUrl
			mu.Unlock()

			assert.Contains(t, actualUrl, tt.expectedUrl)

			// Clean up for next test case
			instance.app.CloseReceiver(createdConfig.Id)
		})
	}
}
