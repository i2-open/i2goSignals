package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #306 (part 2): the goSignals-specific stream settings — route_mode,
// iss, aud and the issuer JWKS URL — are updatable after creation, on every
// delivery method and on each SSTP side addressed by its own SID. route_mode
// is validated by role: a transmitter accepts PB|FW, a receiver IM|FW; anything
// else is a 400-shaped ErrInvalidRequest naming route_mode. Empty means
// unchanged throughout.

// persistedPlainStream stores a plain (non-SSTP) stream of the given delivery
// method with the given route mode and returns its SID.
func persistedPlainStream(t *testing.T, svc *StreamService, method, routeMode string) string {
	t.Helper()
	rec := newReceiverFixture(t, method, routeMode, method)
	rec.StreamConfiguration.Aud = []string{"https://aud.example"}
	require.NoError(t, svc.streamDAO.Create(context.Background(), rec))
	return rec.StreamConfiguration.Id
}

func patchRouteMode(mode string) model.StreamStateRecord {
	return model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{RouteMode: mode}}
}

func TestUpdateStream_RouteModeByRole(t *testing.T) {
	cases := []struct {
		method   string
		initial  string
		accepted []string
		rejected []string
	}{
		{model.DeliveryPush, model.RouteModePublish, []string{model.RouteModeForward, model.RouteModePublish}, []string{model.RouteModeImport, "XX"}},
		{model.DeliveryPoll, model.RouteModePublish, []string{model.RouteModeForward, model.RouteModePublish}, []string{model.RouteModeImport, "publish"}},
		{model.ReceivePush, model.RouteModeImport, []string{model.RouteModeForward, model.RouteModeImport}, []string{model.RouteModePublish, "XX"}},
		{model.ReceivePoll, model.RouteModeImport, []string{model.RouteModeForward, model.RouteModeImport}, []string{model.RouteModePublish, "import"}},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			svc, _ := streamServiceFixture(t)
			ctx := context.Background()
			sid := persistedPlainStream(t, svc, tc.method, tc.initial)

			for _, mode := range tc.accepted {
				cfg, err := svc.UpdateStream(ctx, sid, "test-project", patchRouteMode(mode))
				require.NoError(t, err, "route_mode %q must be accepted on %s", mode, tc.method)
				assert.Equal(t, mode, cfg.RouteMode)
				got, err := svc.GetStreamState(ctx, sid)
				require.NoError(t, err)
				assert.Equal(t, mode, got.GetRouteMode(), "route_mode %q must persist", mode)
			}

			before, err := svc.GetStreamState(ctx, sid)
			require.NoError(t, err)
			for _, mode := range tc.rejected {
				_, err := svc.UpdateStream(ctx, sid, "test-project", patchRouteMode(mode))
				require.Error(t, err, "route_mode %q must be rejected on %s", mode, tc.method)
				assert.True(t, errors.Is(err, ErrInvalidRequest), "rejection must be 400-shaped: %v", err)
				assert.Contains(t, err.Error(), "route_mode", "the reason must name the field")
				got, err := svc.GetStreamState(ctx, sid)
				require.NoError(t, err)
				assert.Equal(t, before.GetRouteMode(), got.GetRouteMode(), "a rejected patch must leave route_mode unchanged")
			}

			// Empty/absent means unchanged.
			_, err = svc.UpdateStream(ctx, sid, "test-project", model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{Description: "only the description"},
			})
			require.NoError(t, err)
			got, err := svc.GetStreamState(ctx, sid)
			require.NoError(t, err)
			assert.Equal(t, before.GetRouteMode(), got.GetRouteMode(), "an absent route_mode must leave the stored value")
			assert.Equal(t, "only the description", got.Description)
		})
	}
}

func TestUpdateStream_IssAudJwksOnEveryDeliveryMethod(t *testing.T) {
	for _, method := range []string{model.DeliveryPush, model.DeliveryPoll, model.ReceivePush, model.ReceivePoll} {
		t.Run(method, func(t *testing.T) {
			svc, _ := streamServiceFixture(t)
			ctx := context.Background()
			initial := model.RouteModePublish
			if method == model.ReceivePush || method == model.ReceivePoll {
				initial = model.RouteModeImport
			}
			sid := persistedPlainStream(t, svc, method, initial)
			// A transmitter's new iss needs an active signing key (#308).
			_, err := svc.keyService.CreateKeyPair(ctx, "https://new-issuer.example", "sig", "")
			require.NoError(t, err)

			patch := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
				Iss:           "https://new-issuer.example",
				Aud:           []string{"https://new-aud.example", "https://other-aud.example"},
				IssuerJWKSUrl: "https://new-issuer.example/jwks.json",
			}}
			cfg, err := svc.UpdateStream(ctx, sid, "test-project", patch)
			require.NoError(t, err)
			assert.Equal(t, patch.Iss, cfg.Iss)
			assert.Equal(t, patch.Aud, cfg.Aud)
			assert.Equal(t, patch.IssuerJWKSUrl, cfg.IssuerJWKSUrl)

			got, err := svc.GetStreamState(ctx, sid)
			require.NoError(t, err)
			assert.Equal(t, patch.Iss, got.Iss)
			assert.Equal(t, patch.Aud, got.Aud)
			assert.Equal(t, patch.IssuerJWKSUrl, got.IssuerJWKSUrl)
			assert.Equal(t, initial, got.GetRouteMode(), "an identity patch must not touch route_mode")

			// Empty means unchanged: a later patch carrying none of the three
			// leaves them where they are.
			_, err = svc.UpdateStream(ctx, sid, "test-project", patchRouteMode(model.RouteModeForward))
			require.NoError(t, err)
			got, err = svc.GetStreamState(ctx, sid)
			require.NoError(t, err)
			assert.Equal(t, patch.Iss, got.Iss)
			assert.Equal(t, patch.Aud, got.Aud)
			assert.Equal(t, patch.IssuerJWKSUrl, got.IssuerJWKSUrl)
		})
	}
}

// TestUpdateStream_ReceiverJwksUrlChangeRefreshesCache: the receiver JWKS
// cache holds a resolved copy of the direction (ADR 0033). Patching iss or the
// issuer JWKS URL must re-resolve the entry from the new values so verification
// picks them up without a restart.
func TestUpdateStream_ReceiverJwksUrlChangeRefreshesCache(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	oldSrv := newFlakyJwksServer(t, "old-kid", &key.PublicKey)
	oldSrv.healthy.Store(true)
	newSrv := newFlakyJwksServer(t, "new-kid", &key.PublicKey)
	newSrv.healthy.Store(true)

	h := newRetryHarness(t)
	svc, ctx := h.svc, context.Background()
	rec := newJwksReceiverFixture(t, "https://old-issuer.example", oldSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id

	require.NotNil(t, svc.GetIssuerJwksForReceiver(ctx, sid), "precondition: the old URL resolves")
	require.Equal(t, int32(1), oldSrv.attempts.Load())

	_, err = svc.UpdateStream(ctx, sid, "test-project", model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss:           "https://new-issuer.example",
		IssuerJWKSUrl: newSrv.URL,
	}})
	require.NoError(t, err)

	jwks := svc.GetIssuerJwksForReceiver(ctx, sid)
	require.NotNil(t, jwks, "the refreshed entry must resolve from the new URL")
	assert.Equal(t, int32(1), newSrv.attempts.Load(), "the update must have re-resolved against the new URL")
	assert.Equal(t, int32(1), oldSrv.attempts.Load(), "the old URL must not be consulted again")

	svc.mu.RLock()
	entry := svc.receiverStreams[sid]
	svc.mu.RUnlock()
	require.NotNil(t, entry)
	assert.Equal(t, newSrv.URL, entry.jwksUrl)
	assert.Equal(t, "https://new-issuer.example", entry.record.StreamConfiguration.Iss)
}

// --- SSTP: per-side route_mode / iss / aud / jwks by SID ---

func TestUpdateSstpPair_RouteModeByRole(t *testing.T) {
	t.Run("tx side accepts PB|FW and rejects IM", func(t *testing.T) {
		svc, rec := createdPair(t)
		ctx := context.Background()
		txSid, inboundBefore := rec.StreamConfiguration.Id, rec.SstpInbound.RouteMode

		for _, mode := range []string{model.RouteModeForward, model.RouteModePublish} {
			_, err := svc.UpdateStream(ctx, txSid, "proj-1", patchRouteMode(mode))
			require.NoError(t, err, "route_mode %q on the tx side", mode)
			got, err := svc.GetStreamStateByPairId(ctx, rec.PairId)
			require.NoError(t, err)
			assert.Equal(t, mode, got.StreamConfiguration.RouteMode)
			assert.Equal(t, inboundBefore, got.SstpInbound.RouteMode, "the inbound side must be untouched")
		}
		for _, mode := range []string{model.RouteModeImport, "XX"} {
			_, err := svc.UpdateStream(ctx, txSid, "proj-1", patchRouteMode(mode))
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidRequest), "%v", err)
			assert.Contains(t, err.Error(), "route_mode")
		}
		got, err := svc.GetStreamStateByPairId(ctx, rec.PairId)
		require.NoError(t, err)
		assert.Equal(t, model.RouteModePublish, got.StreamConfiguration.RouteMode, "a rejected patch leaves the tx mode")
	})

	t.Run("rx side accepts IM|FW and rejects PB", func(t *testing.T) {
		svc, rec := createdPair(t)
		ctx := context.Background()
		rxSid, txBefore := rec.SstpInbound.Id, rec.StreamConfiguration.RouteMode

		for _, mode := range []string{model.RouteModeForward, model.RouteModeImport} {
			_, err := svc.UpdateStream(ctx, rxSid, "proj-1", patchRouteMode(mode))
			require.NoError(t, err, "route_mode %q on the rx side", mode)
			got, err := svc.GetStreamStateByPairId(ctx, rec.PairId)
			require.NoError(t, err)
			assert.Equal(t, mode, got.SstpInbound.RouteMode)
			assert.Equal(t, txBefore, got.StreamConfiguration.RouteMode, "the tx side must be untouched")
		}
		for _, mode := range []string{model.RouteModePublish, "XX"} {
			_, err := svc.UpdateStream(ctx, rxSid, "proj-1", patchRouteMode(mode))
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidRequest), "%v", err)
			assert.Contains(t, err.Error(), "route_mode")
		}
		got, err := svc.GetStreamStateByPairId(ctx, rec.PairId)
		require.NoError(t, err)
		assert.Equal(t, model.RouteModeImport, got.SstpInbound.RouteMode, "a rejected patch leaves the rx mode")
	})
}

func TestUpdateSstpPair_JwksUrlPerSide(t *testing.T) {
	svc, rec := createdPair(t)
	ctx := context.Background()

	_, err := svc.UpdateStream(ctx, rec.StreamConfiguration.Id, "proj-1", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{IssuerJWKSUrl: "https://local.example/jwks.json"},
	})
	require.NoError(t, err)
	got, err := svc.GetStreamStateByPairId(ctx, rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, "https://local.example/jwks.json", got.StreamConfiguration.IssuerJWKSUrl)
	assert.Equal(t, rec.SstpInbound.IssuerJWKSUrl, got.SstpInbound.IssuerJWKSUrl, "inbound untouched by a tx-side patch")

	_, err = svc.UpdateStream(ctx, rec.SstpInbound.Id, "proj-1", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{IssuerJWKSUrl: "https://peer.example/jwks.json"},
	})
	require.NoError(t, err)
	got, err = svc.GetStreamStateByPairId(ctx, rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, "https://peer.example/jwks.json", got.SstpInbound.IssuerJWKSUrl)
	assert.Equal(t, "https://local.example/jwks.json", got.StreamConfiguration.IssuerJWKSUrl, "tx untouched by an rx-side patch")
	assert.Equal(t, rec.SstpInbound.Iss, got.SstpInbound.Iss, "a jwks-only patch leaves iss")
	assert.Equal(t, rec.SstpInbound.Aud, got.SstpInbound.Aud, "a jwks-only patch leaves aud")
}

// TestUpdateSstpPair_InboundJwksChangeRefreshesCache: the pair's receiver-cache
// entry is keyed by the inbound SID (ADR 0018). Patching the inbound side's
// iss/JWKS URL must rebuild that entry from the patched record.
func TestUpdateSstpPair_InboundJwksChangeRefreshesCache(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	srv := newFlakyJwksServer(t, "peer-kid", &key.PublicKey)
	srv.healthy.Store(true)

	svc, rec := createdPair(t)
	ctx := context.Background()
	rxSid := rec.SstpInbound.Id

	// Prime the cache from the pre-patch record (no URL: internal lookup).
	_ = svc.GetIssuerJwksForReceiver(ctx, rxSid)
	svc.mu.RLock()
	primed := svc.receiverStreams[rxSid]
	svc.mu.RUnlock()
	require.NotNil(t, primed)
	require.Empty(t, primed.jwksUrl)

	_, err = svc.UpdateStream(ctx, rxSid, "proj-1", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{Iss: "https://peer2.example", IssuerJWKSUrl: srv.URL},
	})
	require.NoError(t, err)

	svc.mu.RLock()
	entry := svc.receiverStreams[rxSid]
	svc.mu.RUnlock()
	require.NotNil(t, entry)
	assert.Equal(t, srv.URL, entry.jwksUrl, "the entry must carry the patched URL")
	assert.Equal(t, "https://peer2.example", entry.record.SstpInbound.Iss)
	assert.NotNil(t, svc.GetIssuerJwksForReceiver(ctx, rxSid), "material resolves from the patched URL")
	assert.Equal(t, int32(1), srv.attempts.Load())
}
