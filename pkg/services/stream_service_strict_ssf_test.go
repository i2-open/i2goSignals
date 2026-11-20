package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStrictTransmitter stands up an httptest SSF transmitter (well-known +
// configuration endpoint) and captures the publisher-leg registration body the
// server-side create-stream handler POSTs. It returns a *model.Server (already
// strict per `strict`) the test passes straight to CreateStream, exercising the
// resolved-TxAlias production path that reads StrictSsf off the server record.
func mockStrictTransmitter(t *testing.T, strict bool, captured *model.StreamConfiguration) (*model.Server, func()) {
	t.Helper()

	transmitterConfig := model.TransmitterConfiguration{
		Issuer:                "http://transmitter.com",
		ConfigurationEndpoint: "",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transmitterConfig)
	})
	mux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		var req model.StreamConfiguration
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		*captured = req
		// Echo a valid response so the handler completes successfully.
		req.Id = "remote-stream-strict"
		if req.Delivery != nil && req.Delivery.PollTransmitMethod != nil {
			req.Delivery.PollTransmitMethod.EndpointUrl = "http://transmitter.com/poll/strict"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
	})

	ts := httptest.NewServer(mux)
	transmitterConfig.ConfigurationEndpoint = ts.URL + "/streams"
	// A properly-administered strict transmitter advertises issuer == the
	// location its discovery document is served from (SSF §7.2.4); bind it so
	// this stripping-focused test isn't tripped by the issuer-binding check.
	transmitterConfig.Issuer = ts.URL

	token := "test-token"
	server := &model.Server{
		Alias:       "strict-tx",
		Host:        ts.URL,
		ClientToken: &token,
		ProjectId:   "test-project",
		StrictSsf:   strict,
	}
	return server, ts.Close
}

func newStrictTestStreamService(t *testing.T) *StreamService {
	t.Helper()
	streamDAO := memory.NewStreamDAO()
	keyDAO := memory.NewKeyDAO()
	keyService := NewKeyService(keyDAO, "http://receiver.com", nil, nil)
	require.NoError(t, keyService.InitializeTokenKey(context.Background(), "http://receiver.com"))
	svc := NewStreamService(streamDAO, keyService, "http://receiver.com", StreamServiceConfig{})
	baseUrl, _ := url.Parse("http://receiver.com")
	svc.SetBaseUrl(baseUrl)
	return svc
}

// TestCreateStream_StrictTxAlias_StripsTransmitterSupplied pins the server-side
// production caller: the create-stream handler resolving a strict transmitter
// must call StripTransmitterSupplied before POSTing, so the publisher-leg body
// carries no operator-asserted iss/aud (SSF §8.1.1.1). This drives the REAL
// CreateStream path, not the pure helper in isolation.
func TestCreateStream_StrictTxAlias_StripsTransmitterSupplied(t *testing.T) {
	var captured model.StreamConfiguration
	server, closeFn := mockStrictTransmitter(t, true, &captured)
	defer closeFn()

	svc := newStrictTestStreamService(t)

	request := model.StreamConfiguration{
		Iss:             "http://operator-asserted-issuer.com",
		Aud:             []string{"http://operator-asserted-aud.com"},
		IssuerJWKSUrl:   "http://operator-asserted-issuer.com/jwks.json",
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}

	_, err := svc.CreateStream(context.Background(),
		model.StreamStateRecord{StreamConfiguration: request}, "test-project", server)
	require.NoError(t, err)

	// The publisher-leg body the strict transmitter received must NOT carry the
	// operator-asserted iss/aud/issuerJWKSUrl.
	assert.Equal(t, "", captured.Iss, "Iss must be stripped on strict publisher-leg POST")
	assert.Empty(t, captured.Aud, "Aud must be stripped on strict publisher-leg POST")
	assert.Equal(t, "", captured.IssuerJWKSUrl, "IssuerJWKSUrl must be stripped on strict publisher-leg POST")
}

// TestCreateStream_FlexibleTxAlias_PreservesTransmitterSupplied is the
// non-strict counterpart: a flexible (goSignals-cluster) transmitter must
// receive the operator-asserted iss/aud unchanged, preserving operator intent.
func TestCreateStream_FlexibleTxAlias_PreservesTransmitterSupplied(t *testing.T) {
	var captured model.StreamConfiguration
	server, closeFn := mockStrictTransmitter(t, false, &captured)
	defer closeFn()

	svc := newStrictTestStreamService(t)

	request := model.StreamConfiguration{
		Iss:             "http://operator-asserted-issuer.com",
		Aud:             []string{"http://operator-asserted-aud.com"},
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}

	_, err := svc.CreateStream(context.Background(),
		model.StreamStateRecord{StreamConfiguration: request}, "test-project", server)
	require.NoError(t, err)

	assert.Equal(t, "http://operator-asserted-issuer.com", captured.Iss, "Iss must be preserved on flexible publisher-leg POST")
	assert.Equal(t, []string{"http://operator-asserted-aud.com"}, captured.Aud, "Aud must be preserved on flexible publisher-leg POST")
}
