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

func TestCreateStream_AutomaticRegistration(t *testing.T) {
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
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		var req model.StreamConfiguration
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		// Verify that the EndpointUrl is absolute
		assert.Contains(t, req.Delivery.PushTransmitMethod.EndpointUrl, "http://receiver.com/events/")

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
	keyService := NewKeyService(keyDAO, "http://receiver.com")

	// We need to initialize token keys for the key service to have an auth issuer
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
		TxToken:        &[]string{"test-token"}[0],
	}

	ctx := context.Background()
	config, err := svc.CreateStream(ctx, request, "test-project", nil)

	// 4. Verify Results
	assert.NoError(t, err)
	assert.Equal(t, eventsDelivered, config.EventsDelivered)
}

func TestCreateStream_AutomaticPollRegistration(t *testing.T) {
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
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		var req model.StreamConfiguration
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		// Verify that it requested Poll delivery
		assert.Equal(t, model.DeliveryPoll, req.Delivery.GetMethod())

		// Return updated configuration with Poll details
		req.EventsDelivered = eventsDelivered
		req.Delivery = &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method:              model.DeliveryPoll,
				EndpointUrl:         "http://transmitter.com/poll/123",
				AuthorizationHeader: "Bearer status-token",
			},
		}

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
	keyService := NewKeyService(keyDAO, "http://receiver.com")

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
			PollReceiveMethod: &model.PollReceiveMethod{
				Method: model.ReceivePoll,
			},
		},
		TxWellKnownUrl: &wellKnownUrl,
		TxToken:        &[]string{"test-token"}[0],
	}

	ctx := context.Background()
	config, err := svc.CreateStream(ctx, request, "test-project", nil)

	// 4. Verify Results
	assert.NoError(t, err)
	assert.Equal(t, eventsDelivered, config.EventsDelivered)
	assert.NotNil(t, config.Delivery.PollReceiveMethod)
	assert.Equal(t, "http://transmitter.com/poll/123", config.Delivery.PollReceiveMethod.EndpointUrl)
	assert.Equal(t, "Bearer status-token", config.Delivery.PollReceiveMethod.AuthorizationHeader)
	assert.NotNil(t, config.TxToken)
	assert.Equal(t, "Bearer status-token", *config.TxToken)
}
