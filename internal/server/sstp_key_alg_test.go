package server

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Spec #114 through the SSTP dialer: a publishing pair with no signing_alg, on
// an issuer that has an RSA key and a newer ES256 key, is handed that issuer's
// newest key (the selection LoadSigningKey makes for an empty signing_alg) and
// re-signs its outbound SETs ES256 under the ES256 kid.
func TestBuildSstpSets_EmptySigningAlgSignsWithTheNewestKeyType(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "sstp-dialer-key-alg")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})
	ks := persistence.KeyService
	ctx := context.Background()

	stream := sstpBatchStream(model.RouteModePublish)
	cfg := stream.StreamConfiguration
	require.Empty(t, cfg.SigningAlg)
	_, err = ks.EnsureSigningKeyForAlg(ctx, cfg.Iss, "RS256", "")
	require.NoError(t, err)
	_, err = ks.EnsureSigningKeyForAlg(ctx, cfg.Iss, "ES256", "")
	require.NoError(t, err)
	_, esKid, err := ks.GetSigner(ctx, cfg.Iss, "ES256")
	require.NoError(t, err)

	key, kid, err := ks.GetSigner(ctx, cfg.Iss, cfg.SigningAlg)
	require.NoError(t, err)
	require.Equal(t, esKid, kid, "an empty signing_alg selects the issuer's newest key of any type")

	events := sstpBatchEvents(3)
	sets, err := buildSstpSetsAck(stream, sstpBatchSets(events), key, kid, 2, nil)
	require.NoError(t, err)
	require.Len(t, sets, len(events))
	for _, raw := range sets {
		parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
		require.NoError(t, err)
		assert.Equal(t, "ES256", parsed.Header["alg"])
		assert.Equal(t, esKid, parsed.Header["kid"])
	}
}
