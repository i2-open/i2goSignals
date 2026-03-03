package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestCreateStream_TxAliasPersistence(t *testing.T) {
	// 1. Setup StreamService
	streamDAO := memory.NewStreamDAO()
	keyDAO := memory.NewKeyDAO()
	keyService := NewKeyService(keyDAO, "http://receiver.com")

	err := keyService.InitializeTokenKey(context.Background(), "http://receiver.com")
	assert.NoError(t, err)

	svc := NewStreamService(streamDAO, keyService, "http://receiver.com")

	// 2. Call CreateStream with TxAlias
	txAlias := "my-transmitter"
	request := model.StreamConfiguration{
		Iss: "http://transmitter.com",
		Aud: []string{"http://receiver.com"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
		TxAlias: &txAlias,
	}

	ctx := context.Background()
	config, err := svc.CreateStream(ctx, request, "test-project", nil)

	// 3. Verify Results
	assert.NoError(t, err)
	assert.NotNil(t, config.TxAlias)
	assert.Equal(t, txAlias, *config.TxAlias)

	// Verify it's persisted in DAO
	persisted, err := streamDAO.FindByID(ctx, config.Id)
	assert.NoError(t, err)
	assert.NotNil(t, persisted.StreamConfiguration.TxAlias)
	assert.Equal(t, txAlias, *persisted.StreamConfiguration.TxAlias)
}

func TestCreateStream_OAuthClientCredentialRegistration(t *testing.T) {
	// 1. Setup Mock OAuth Token Server
	tokenMux := http.NewServeMux()
	tokenMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		// Basic auth check (ClientID:ClientSecret)
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "test-client-id", user)
		assert.Equal(t, "test-client-secret", pass)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "oauth-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	tokenServer := httptest.NewServer(tokenMux)
	defer tokenServer.Close()

	// 2. Setup Mock Transmitter
	eventsDelivered := []string{"urn:ietf:params:sse:event-type:risc:account-enabled"}
	transmitterConfig := model.TransmitterConfiguration{
		Issuer:                "http://transmitter.com",
		ConfigurationEndpoint: "", // will be set later
	}

	txMux := http.NewServeMux()
	txMux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Verify OAuth token was used
		assert.Equal(t, "Bearer oauth-access-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transmitterConfig)
	})

	txMux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer oauth-access-token", r.Header.Get("Authorization"))

		var req model.StreamConfiguration
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		req.EventsDelivered = eventsDelivered
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
	})

	txServerMock := httptest.NewServer(txMux)
	defer txServerMock.Close()

	transmitterConfig.ConfigurationEndpoint = txServerMock.URL + "/streams"

	// 3. Setup StreamService
	streamDAO := memory.NewStreamDAO()
	keyDAO := memory.NewKeyDAO()
	keyService := NewKeyService(keyDAO, "http://receiver.com")
	err := keyService.InitializeTokenKey(context.Background(), "http://receiver.com")
	assert.NoError(t, err)

	svc := NewStreamService(streamDAO, keyService, "http://receiver.com")

	// 4. Create Server object with OAuthClientConfig
	server := &model.Server{
		Alias: "test-transmitter",
		Host:  txServerMock.URL,
		OAuthClientConfig: &model.OAuthClientConfig{
			TokenURL:     tokenServer.URL + "/token",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	}

	// 5. Call CreateStream
	request := model.StreamConfiguration{
		Iss:             "http://transmitter.com",
		Aud:             []string{"http://receiver.com"},
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method: model.ReceivePoll,
			},
		},
	}

	ctx := context.Background()
	config, err := svc.CreateStream(ctx, request, "test-project", server)

	// 6. Verify Results
	assert.NoError(t, err)
	assert.Equal(t, eventsDelivered, config.EventsDelivered)
}

func TestCreateStream_OAuthClientCredentialPushRegistration(t *testing.T) {
	// 1. Setup Mock OAuth Token Server
	tokenMux := http.NewServeMux()
	tokenMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "oauth-push-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	tokenServer := httptest.NewServer(tokenMux)
	defer tokenServer.Close()

	// 2. Setup Mock Transmitter
	eventsDelivered := []string{"urn:ietf:params:sse:event-type:risc:account-enabled"}
	transmitterConfig := model.TransmitterConfiguration{
		Issuer:                "http://transmitter.com",
		ConfigurationEndpoint: "", // will be set later
	}

	txMux := http.NewServeMux()
	txMux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer oauth-push-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transmitterConfig)
	})

	txMux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer oauth-push-token", r.Header.Get("Authorization"))

		var req model.StreamConfiguration
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		req.EventsDelivered = eventsDelivered
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
	})

	txServerMock := httptest.NewServer(txMux)
	defer txServerMock.Close()

	transmitterConfig.ConfigurationEndpoint = txServerMock.URL + "/streams"

	// 3. Setup StreamService
	streamDAO := memory.NewStreamDAO()
	keyDAO := memory.NewKeyDAO()
	keyService := NewKeyService(keyDAO, "http://receiver.com")
	err := keyService.InitializeTokenKey(context.Background(), "http://receiver.com")
	assert.NoError(t, err)

	svc := NewStreamService(streamDAO, keyService, "http://receiver.com")

	// 4. Create Server object with OAuthClientConfig
	server := &model.Server{
		Alias: "test-transmitter-push",
		Host:  txServerMock.URL,
		OAuthClientConfig: &model.OAuthClientConfig{
			TokenURL:     tokenServer.URL + "/token",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	}

	// 5. Call CreateStream
	request := model.StreamConfiguration{
		Iss:             "http://transmitter.com",
		Aud:             []string{"http://receiver.com"},
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
	}

	ctx := context.Background()
	config, err := svc.CreateStream(ctx, request, "test-project", server)

	// 6. Verify Results
	assert.NoError(t, err)
	assert.Equal(t, eventsDelivered, config.EventsDelivered)
}
