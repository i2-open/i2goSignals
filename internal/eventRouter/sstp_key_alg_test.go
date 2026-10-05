package eventRouter

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

const sstpKeyAlgIssuer = "https://sstp-key-alg.example"

// Spec #114 through the SSTP runner: a publishing pair with no signing_alg, on
// an issuer that has an RSA key and a newer ES256 key, re-signs its outbound
// SETs ES256 under the ES256 kid.
func TestSstpServer_EmptySigningAlgSignsWithTheNewestKeyType(t *testing.T) {
	h := newTestRouter(t)
	ctx := context.Background()
	_, err := h.keyService.EnsureSigningKeyForAlg(ctx, sstpKeyAlgIssuer, "RS256", "")
	require.NoError(t, err)
	_, err = h.keyService.EnsureSigningKeyForAlg(ctx, sstpKeyAlgIssuer, "ES256", "")
	require.NoError(t, err)
	_, esKid, err := h.keyService.GetSigner(ctx, sstpKeyAlgIssuer, "ES256")
	require.NoError(t, err)

	txSid := "sstp-tx-key-alg"
	rec := sstpServerPairState(txSid, "sstp-rx-key-alg", "pair-key-alg")
	rec.StreamConfiguration.RouteMode = model.RouteModePublish
	rec.StreamConfiguration.Iss = sstpKeyAlgIssuer
	require.Empty(t, rec.StreamConfiguration.SigningAlg)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(ctx, rec))

	jtis := []string{"sstp-key-alg-1", "sstp-key-alg-2"}
	refs := make([]interfaces.PendingRef, 0, len(jtis))
	for _, jti := range jtis {
		token := newRiscToken(jti, dupTestIssuer, "https://peer.example.com")
		_, err := h.router.eventService.AddEvent(ctx, token, txSid, `{"raw":true}`)
		require.NoError(t, err)
		require.NoError(t, h.router.eventService.AddEventToStream(ctx, refOf(jti), txSid))
		refs = append(refs, refOf(jti))
	}

	sets, err := h.router.buildSstpOutboundSets(rec, h.router.resolveOutboundSets(refs))
	require.NoError(t, err)
	require.Len(t, sets, len(jtis))
	for _, token := range sets {
		parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		require.NoError(t, err)
		assert.Equal(t, "ES256", parsed.Header["alg"])
		assert.Equal(t, esKid, parsed.Header["kid"])
	}
}
