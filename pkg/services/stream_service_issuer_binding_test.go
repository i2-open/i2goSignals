package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBindingTransmitter stands up an SSF transmitter whose discovery document
// advertises issuerOverride as its `issuer` (or, when issuerOverride == "", the
// server's own URL — a consistent binding). jwks_uri is FREE-FORM on an
// unrelated host. It drives the §7.2.4 issuer↔discovery-location check on the
// receiver-side CreateStream path off the per-peer StrictSsf posture.
func mockBindingTransmitter(t *testing.T, strict bool, issuerOverride string) (*model.Server, func()) {
	t.Helper()

	cfg := model.TransmitterConfiguration{
		JwksUri: "https://keys.elsewhere.example/jwks.json",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		var req model.StreamConfiguration
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		req.Id = "remote-binding-stream"
		if req.Delivery != nil && req.Delivery.PollTransmitMethod != nil {
			req.Delivery.PollTransmitMethod.EndpointUrl = "http://transmitter.com/poll/x"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
	})

	ts := httptest.NewServer(mux)
	cfg.ConfigurationEndpoint = ts.URL + "/streams"
	if issuerOverride != "" {
		cfg.Issuer = issuerOverride
	} else {
		cfg.Issuer = ts.URL // issuer == discovery location
	}

	token := "test-token"
	server := &model.Server{
		Alias:       "binding-tx",
		Host:        ts.URL,
		ClientToken: &token,
		ProjectId:   "test-project",
		StrictSsf:   strict,
	}
	return server, ts.Close
}

func bindingReceiveRequest() model.StreamStateRecord {
	return model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
}

// TestCreateStream_StrictIssuerMismatch_Fails: the receiver-side create against
// a strict transmitter whose advertised issuer != its discovery location must
// abort the registration (SSF §7.2.4).
func TestCreateStream_StrictIssuerMismatch_Fails(t *testing.T) {
	server, closeFn := mockBindingTransmitter(t, true, "https://impersonator.example.com")
	defer closeFn()

	svc := newStrictTestStreamService(t)
	_, err := svc.CreateStream(context.Background(), bindingReceiveRequest(), "test-project", server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer binding")
}

// TestCreateStream_FlexibleIssuerMismatch_Succeeds: a flexible transmitter with
// a mismatched issuer only warns; the stream is still created.
func TestCreateStream_FlexibleIssuerMismatch_Succeeds(t *testing.T) {
	server, closeFn := mockBindingTransmitter(t, false, "https://different.example.com")
	defer closeFn()

	svc := newStrictTestStreamService(t)
	cfg, err := svc.CreateStream(context.Background(), bindingReceiveRequest(), "test-project", server)
	require.NoError(t, err)
	assert.NotEmpty(t, cfg.Id)
}

// TestCreateStream_StrictIssuerMatch_Succeeds: a strict transmitter advertising
// issuer == its discovery location binds cleanly; the free-form jwks_uri on a
// different host is irrelevant to the check.
func TestCreateStream_StrictIssuerMatch_Succeeds(t *testing.T) {
	server, closeFn := mockBindingTransmitter(t, true, "") // issuer == discovery location
	defer closeFn()

	svc := newStrictTestStreamService(t)
	cfg, err := svc.CreateStream(context.Background(), bindingReceiveRequest(), "test-project", server)
	require.NoError(t, err)
	assert.NotEmpty(t, cfg.Id)
}
