package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestCreateStream_TxTokenResilience(t *testing.T) {
	tests := []struct {
		name           string
		inputToken     string
		expectedHeader string
	}{
		{
			name:           "Token without prefix",
			inputToken:     "test-token",
			expectedHeader: "Bearer test-token",
		},
		{
			name:           "Token with Bearer prefix",
			inputToken:     "Bearer test-token",
			expectedHeader: "Bearer test-token",
		},
		{
			name:           "Token with bearer prefix lowercase",
			inputToken:     "bearer test-token",
			expectedHeader: "bearer test-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 1. Setup Mock Transmitter
			eventsDelivered := []string{"urn:ietf:params:sse:event-type:risc:account-enabled"}
			transmitterConfig := model.TransmitterConfiguration{
				Issuer:                "http://transmitter.com",
				ConfigurationEndpoint: "", // will be set later
			}

			mux := http.NewServeMux()

			// Well-known endpoint
			mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(transmitterConfig)
			})

			// Stream configuration endpoint
			mux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.expectedHeader, r.Header.Get("Authorization"))

				var req model.StreamConfiguration
				err := json.NewDecoder(r.Body).Decode(&req)
				assert.NoError(t, err)

				// Return updated configuration
				req.EventsDelivered = eventsDelivered
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(req)
			})

			ts := httptest.NewServer(mux)
			defer ts.Close()

			transmitterConfig.ConfigurationEndpoint = ts.URL + "/streams"
			wellKnownUrl := ts.URL + "/.well-known/ssf-configuration"

			// 2. Setup StreamService
			streamDAO := memory.NewStreamDAO()
			keyDAO := memory.NewKeyDAO()
			keyService := NewKeyService(keyDAO, "http://receiver.com", nil)

			err := keyService.InitializeTokenKey(context.Background(), "http://receiver.com")
			assert.NoError(t, err)

			svc := NewStreamService(streamDAO, keyService, "http://receiver.com")
			baseUrl, _ := url.Parse("http://receiver.com")
			svc.SetBaseUrl(baseUrl)

			// 3. Call CreateStream
			request := model.StreamConfiguration{
				Iss:             "http://transmitter.com",
				Aud:             []string{"http://receiver.com"},
				EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
				Delivery: &model.OneOfStreamConfigurationDelivery{
					PushReceiveMethod: &model.PushReceiveMethod{
						Method: model.ReceivePush,
					},
				},
				TxWellKnownUrl: &wellKnownUrl,
				TxToken:        &tt.inputToken,
			}

			ctx := context.Background()
			_, err = svc.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: request}, "test-project", nil)

			// 4. Verify Results
			assert.NoError(t, err)
		})
	}
}
