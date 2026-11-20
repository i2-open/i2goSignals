package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #306 (part 2): PUT /stream accepts route_mode, iss, aud and the issuer
// JWKS URL. A route_mode outside the stream's role (PB|FW for a transmitter,
// IM|FW for a receiver) is a 400 whose body names route_mode, and the stored
// value is left alone. The handler passes the fields through to UpdateStream
// and refreshes the router with the patched record.

func routeModePatch(mode string) model.StreamStateRecord {
	return model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{RouteMode: mode}}
}

func TestUpdateStream_RouteModeRejectedByRoleIs400(t *testing.T) {
	t.Run("IM on a poll transmitter", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPlain(t, app, model.StreamStateEnabled, "")

		rr := app.putStream(t, app.adminBearer(t), statusPlainSid, routeModePatch(model.RouteModeImport))
		require.Equal(t, http.StatusBadRequest, rr.Code, "body: %s", rr.Body.String())
		assert.Contains(t, rr.Body.String(), "route_mode")
		assert.Empty(t, app.router.updated, "a rejected patch must not refresh the router")

		rec, err := app.StreamService.GetStreamStateBySID(context.Background(), statusPlainSid)
		require.NoError(t, err)
		assert.Empty(t, rec.GetRouteMode(), "stored route_mode unchanged")
	})

	t.Run("PB on the pair's inbound side", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")

		rr := app.putStream(t, app.adminBearer(t), statusPairRxSid, routeModePatch(model.RouteModePublish))
		require.Equal(t, http.StatusBadRequest, rr.Code, "body: %s", rr.Body.String())
		assert.Contains(t, rr.Body.String(), "route_mode")

		rec, err := app.StreamService.GetStreamStateBySID(context.Background(), statusPairTxSid)
		require.NoError(t, err)
		assert.Empty(t, rec.SstpInbound.RouteMode, "stored inbound route_mode unchanged")
	})
}

func TestUpdateStream_RouteModeAndIdentityLandOnTheNamedSide(t *testing.T) {
	t.Run("plain transmitter", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPlain(t, app, model.StreamStateEnabled, "")

		patch := routeModePatch(model.RouteModeForward)
		patch.StreamConfiguration.Iss = "https://issuer.example/tx"
		patch.StreamConfiguration.Aud = []string{"https://aud.example"}
		patch.StreamConfiguration.IssuerJWKSUrl = "https://issuer.example/tx/jwks.json"
		rr := app.putStream(t, app.adminBearer(t), statusPlainSid, patch)
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
		assert.Equal(t, []string{statusPlainSid}, app.router.updated, "router refreshed with the patched record")

		rec, err := app.StreamService.GetStreamStateBySID(context.Background(), statusPlainSid)
		require.NoError(t, err)
		assert.Equal(t, model.RouteModeForward, rec.GetRouteMode())
		assert.Equal(t, "https://issuer.example/tx", rec.Iss)
		assert.Equal(t, []string{"https://aud.example"}, rec.Aud)
		assert.Equal(t, "https://issuer.example/tx/jwks.json", rec.IssuerJWKSUrl)
	})

	t.Run("pair inbound side by rx SID", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")

		patch := routeModePatch(model.RouteModeForward)
		patch.StreamConfiguration.IssuerJWKSUrl = "https://peer.example/jwks.json"
		rr := app.putStream(t, app.adminBearer(t), statusPairRxSid, patch)
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

		rec, err := app.StreamService.GetStreamStateBySID(context.Background(), statusPairTxSid)
		require.NoError(t, err)
		assert.Equal(t, model.RouteModeForward, rec.SstpInbound.RouteMode)
		assert.Equal(t, "https://peer.example/jwks.json", rec.SstpInbound.IssuerJWKSUrl)
		assert.Empty(t, rec.StreamConfiguration.RouteMode, "tx side untouched")
		assert.Empty(t, rec.StreamConfiguration.IssuerJWKSUrl, "tx side untouched")
	})
}
