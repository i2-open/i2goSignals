package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signingOnlyReceiveRequest builds a ReceivePoll receiver create/update request
// carrying the signing-only posture (#184) with the given trust anchor.
func signingOnlyReceiveRequest(iss, jwksUrl string) model.StreamStateRecord {
	return model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss:             iss,
		IssuerJWKSUrl:   jwksUrl,
		SigningOnly:     true,
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
}

// emptyJwksServer serves a valid (empty) JWKS document so a receiver create can
// resolve IssuerJWKSUrl without a real transmitter and without a network hang.
func emptyJwksServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The create-time guardrail rejects signingOnly:true unless BOTH iss and
// issuerJWKSUrl are supplied — there is no trust anchor otherwise.
func TestCreateStream_SigningOnlyRequiresIssAndJwks(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		iss     string
		jwksUrl string
	}{
		{"missing both", "", ""},
		{"missing jwks", "https://issuer.example.com", ""},
		{"missing iss", "", "https://issuer.example.com/jwks.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateStream(ctx, signingOnlyReceiveRequest(tc.iss, tc.jwksUrl), "test-project", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "signingOnly")
		})
	}
}

// With both anchor fields present the signing-only stream is created and the
// posture persists on the returned config.
func TestCreateStream_SigningOnlyWithAnchorSucceeds(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()
	jwks := emptyJwksServer(t)

	cfg, err := svc.CreateStream(ctx, signingOnlyReceiveRequest("https://issuer.example.com", jwks.URL), "test-project", nil)
	require.NoError(t, err)
	assert.True(t, cfg.SigningOnly)
	assert.Equal(t, "https://issuer.example.com", cfg.Iss)
	assert.Equal(t, jwks.URL, cfg.IssuerJWKSUrl)
}

// A default (flag-off) receiver create needs no issuer/jwks anchor and is
// unaffected by the guardrail.
func TestCreateStream_DefaultPostureUnaffectedByGuardrail(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()

	req := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
	cfg, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)
	assert.False(t, cfg.SigningOnly)
}

// The same guardrail applies on update: enabling signingOnly:true on a stream
// that lacks a JWKS anchor is rejected, while a stream that already carries the
// anchor accepts the flip.
func TestUpdateStream_SigningOnlyGuardrail(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()
	jwks := emptyJwksServer(t)

	// Stream A: created with an anchor but flag off → flipping on succeeds.
	anchored := signingOnlyReceiveRequest("https://issuer.example.com", jwks.URL)
	anchored.SigningOnly = false
	cfgA, err := svc.CreateStream(ctx, anchored, "test-project", nil)
	require.NoError(t, err)
	require.False(t, cfgA.SigningOnly)

	flip := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		SigningOnly: true,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
	updated, err := svc.UpdateStream(ctx, cfgA.Id, "test-project", flip)
	require.NoError(t, err)
	assert.True(t, updated.SigningOnly)

	// Stream B: created with no JWKS anchor → flipping signingOnly on is rejected.
	plain := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
	cfgB, err := svc.CreateStream(ctx, plain, "test-project", nil)
	require.NoError(t, err)

	flipB := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		SigningOnly: true,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
	_, err = svc.UpdateStream(ctx, cfgB.Id, "test-project", flipB)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signingOnly")
}
