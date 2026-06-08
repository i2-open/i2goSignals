package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestUpdateStream_AllTxFieldsPersistence(t *testing.T) {
	// 1. Setup Mock Transmitter
	txStreamId := "remote-stream-123"
	transmitterConfig := model.TransmitterConfiguration{
		Issuer: "http://transmitter.com",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transmitterConfig)
	})
	mux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		var req model.StreamConfiguration
		_ = json.NewDecoder(r.Body).Decode(&req)
		req.Id = txStreamId
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()
	transmitterConfig.ConfigurationEndpoint = ts.URL + "/streams"
	wellKnownUrl := ts.URL + "/.well-known/ssf-configuration"
	txToken := "test-token"

	dao := memory.NewStreamDAO()
	keyDao := memory.NewKeyDAO()
	ks := NewKeyService(keyDao, "http://localhost", nil, nil)
	svc := NewStreamService(dao, ks, "http://localhost", StreamServiceConfig{})
	ctx := context.Background()

	// Initial configuration with all Tx-related fields
	txAlias := "transmitter-alias"

	initialConfig := model.StreamConfiguration{
		Iss:            "http://transmitter.com",
		Aud:            []string{"http://receiver.com"},
		TxAlias:        &txAlias,
		TxWellKnownUrl: &wellKnownUrl,
		TxToken:        &txToken,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method: model.ReceivePoll,
			},
		},
	}

	// Create stream (simulating discovery already happened)
	created, err := svc.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: initialConfig}, "test-project", nil)
	assert.NoError(t, err)
	assert.NotNil(t, created.TxAlias)
	assert.Equal(t, txAlias, *created.TxAlias)
	if created.RemoteStreamId == nil {
		t.Errorf("Expected RemoteStreamId to be set, got nil")
	} else {
		assert.Equal(t, txStreamId, *created.RemoteStreamId)
	}

	// Now update the stream, but don't include TxAlias in the update request (typical for SSF updates)
	updateReq := model.StreamStateRecord{StreamConfiguration: created.DeepCopy()}
	updateReq.Description = "Updated description"
	// Ensure TxAlias is still there in our "request" object
	assert.NotNil(t, updateReq.TxAlias)

	updated, err := svc.UpdateStream(ctx, created.Id, "test-project", updateReq)
	assert.NoError(t, err)
	assert.NotNil(t, updated.TxAlias, "TxAlias should not be lost after update")
	assert.Equal(t, txAlias, *updated.TxAlias)
	if updated.RemoteStreamId == nil {
		t.Errorf("Expected RemoteStreamId to be set, got nil")
	} else {
		assert.Equal(t, txStreamId, *updated.RemoteStreamId)
	}

	assert.Equal(t, "Updated description", updated.Description)

	// Verify in DAO
	stored, _ := dao.FindByID(ctx, created.Id)
	assert.NotNil(t, stored.TxAlias)
	assert.Equal(t, txAlias, *stored.TxAlias)
}

func TestCreateStream_NoDiscovery_TxAliasPreserved(t *testing.T) {
	dao := memory.NewStreamDAO()
	keyDao := memory.NewKeyDAO()
	ks := NewKeyService(keyDao, "http://localhost", nil, nil)
	svc := NewStreamService(dao, ks, "http://localhost", StreamServiceConfig{})
	ctx := context.Background()

	txAlias := "manual-alias"
	config := model.StreamConfiguration{
		Iss:     "http://transmitter.com",
		Aud:     []string{"http://receiver.com"},
		TxAlias: &txAlias,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: "http://receiver.com/poll",
			},
		},
	}

	created, err := svc.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: config}, "test-project", nil)
	assert.NoError(t, err)
	assert.NotNil(t, created.TxAlias)
	assert.Equal(t, txAlias, *created.TxAlias)
}
