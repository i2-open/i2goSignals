package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #308: creating, updating or re-enabling a signing transmitter with no
// active signing key for its iss and signing_alg is a 400 naming the issuer and
// algorithm, and nothing changes; once the key is active the same request
// succeeds.

const reEnableIssuer = "https://re-enable.example"

func (s *ServerProvisioningAuthzSuite) TestStreamCreate_SigningTransmitterWithoutKeyIs400() {
	cfg := model.StreamStateRecord{}
	cfg.Iss = "https://keyless.example"
	cfg.Aud = []string{"http://receiver.example.com"}
	cfg.Delivery = &model.OneOfStreamConfigurationDelivery{
		PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
	}
	body, _ := json.Marshal(cfg)

	rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", s.streamToken("proj-A"), body, nil)
	s.Equal(http.StatusBadRequest, rr.Code, rr.Body.String())
	s.Contains(rr.Body.String(), "no active signing key for issuer https://keyless.example (RS256)")
	s.Empty(s.app.StreamService.ListStreams(context.Background()), "nothing is saved")

	baseUrl, err := url.Parse("https://local.example")
	s.Require().NoError(err)
	s.app.StreamService.SetBaseUrl(baseUrl) // the SSTP responder derives its endpoint from it
	sstp := sstpBootstrapBody(s.T(), "https://keyless.example")
	rr = s.do(s.app.StreamCreate, http.MethodPost, "/stream", s.streamToken("proj-A"), sstp, nil)
	s.Equal(http.StatusBadRequest, rr.Code, rr.Body.String())
	s.Contains(rr.Body.String(), "no active signing key for issuer https://keyless.example (RS256)")
	s.Empty(s.app.StreamService.ListStreams(context.Background()), "nothing is saved")
}

// sstpBootstrapBody is a local-only responder bootstrap whose primary re-signs
// as iss.
func sstpBootstrapBody(t *testing.T, iss string) []byte {
	t.Helper()
	body, err := json.Marshal(model.SstpPairBootstrap{
		Role:    model.SstpRoleResponder,
		Primary: model.SstpDirection{Iss: iss, Aud: []string{"https://peer.example"}, Mode: model.SstpModePublish},
		Inbound: model.SstpDirection{Iss: "https://peer.example", Aud: []string{iss}, Mode: model.SstpModeImport},
	})
	require.NoError(t, err)
	return body
}

func TestStreamUpdate_MissingSigningKeyIs400UntilFixed(t *testing.T) {
	app := newStatusRefreshApp(t)
	ctx := context.Background()
	_, err := app.KeyService.CreateKeyPair(ctx, reEnableIssuer, "sig", statusTestProject)
	require.NoError(t, err)
	persistStatusPlainIss(t, app, reEnableIssuer, model.StreamStateEnabled, "")
	_, _, err = app.KeyService.SetKeyStatus(ctx, reEnableIssuer, "", interfaces.KeyStatusSuspended)
	require.NoError(t, err)
	bearer := app.adminBearer(t)

	rr := app.putStream(t, bearer, statusPlainSid, model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{Description: "unrelated edit"},
	})
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "no active signing key for issuer "+reEnableIssuer+" (RS256)")
	assert.Empty(t, app.router.updated, "a refused update changes nothing")

	rr = app.putStream(t, bearer, statusPlainSid, model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{RouteMode: model.RouteModeForward},
	})
	require.Equal(t, http.StatusOK, rr.Code, "switching to Forward is the fix: %s", rr.Body.String())
}

func TestUpdateStatus_ReEnableNeedsAnActiveSigningKey(t *testing.T) {
	app := newStatusRefreshApp(t)
	ctx := context.Background()
	_, err := app.KeyService.CreateKeyPair(ctx, reEnableIssuer, "sig", statusTestProject)
	require.NoError(t, err)
	persistStatusPlainIss(t, app, reEnableIssuer, model.StreamStateDisable, "stopped")
	bearer := app.adminBearer(t)

	_, _, err = app.KeyService.SetKeyStatus(ctx, reEnableIssuer, "", interfaces.KeyStatusSuspended)
	require.NoError(t, err)

	rr := app.postStatus(t, bearer, statusPlainSid, model.StreamStateEnabled, "")
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "no active signing key for issuer "+reEnableIssuer+" (RS256)")
	assert.Equal(t, 0, app.refreshes(), "a refused re-enable changes nothing")
	assert.Equal(t, model.StreamStatus{Status: model.StreamStateDisable, Reason: "stopped"},
		app.getStatus(t, bearer, statusPlainSid), "the status is unchanged")

	// Pausing or disabling needs no key.
	rr = app.postStatus(t, bearer, statusPlainSid, model.StreamStatePause, "operator")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	_, _, err = app.KeyService.SetKeyStatus(ctx, reEnableIssuer, "", interfaces.KeyStatusActive)
	require.NoError(t, err)
	app.resetRefreshes()

	rr = app.postStatus(t, bearer, statusPlainSid, model.StreamStateEnabled, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, model.StreamStatus{Status: model.StreamStateEnabled}, decodeStatus(t, rr))
	assert.Equal(t, []string{statusPlainSid}, app.router.updated, "the re-enable reaches the router")
}

func TestUpdateStatus_ReEnableForwardTransmitterNeedsNoKey(t *testing.T) {
	app := newStatusRefreshApp(t)
	rec := statusPlainRecord(reEnableIssuer, model.StreamStateDisable, "stopped")
	rec.StreamConfiguration.RouteMode = model.RouteModeForward
	require.NoError(t, app.StreamService.PersistStreamStateRecord(context.Background(), rec))

	rr := app.postStatus(t, app.adminBearer(t), statusPlainSid, model.StreamStateEnabled, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, model.StreamStatus{Status: model.StreamStateEnabled}, decodeStatus(t, rr))
}

func TestUpdateStatus_ReEnableSstpPairNeedsAnActiveSigningKey(t *testing.T) {
	app := newStatusRefreshApp(t)
	ctx := context.Background()
	_, err := app.KeyService.CreateKeyPair(ctx, reEnableIssuer, "sig", statusTestProject)
	require.NoError(t, err)
	persistStatusPairIss(t, app, reEnableIssuer, model.StreamStateDisable, "stopped", model.StreamStateDisable, "stopped")
	_, _, err = app.KeyService.SetKeyStatus(ctx, reEnableIssuer, "", interfaces.KeyStatusSuspended)
	require.NoError(t, err)
	bearer := app.pairBearer(t)

	for _, sid := range []string{statusPairTxSid, statusPairRxSid} {
		rr := app.postStatus(t, bearer, sid, model.StreamStateEnabled, "")
		require.Equal(t, http.StatusBadRequest, rr.Code, "re-enable via %s: %s", sid, rr.Body.String())
		assert.Contains(t, rr.Body.String(), "no active signing key for issuer "+reEnableIssuer+" (RS256)")
	}
	assert.Equal(t, 0, app.refreshes())
	stopped := model.StreamStatus{Status: model.StreamStateDisable, Reason: "stopped"}
	assert.Equal(t, stopped, app.getStatus(t, bearer, statusPairTxSid))
	assert.Equal(t, stopped, app.getStatus(t, bearer, statusPairRxSid))
}
