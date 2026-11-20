package eventRouter

import (
	"context"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Spec #114 through the router: a poll stream with no signing_alg, on an
// issuer that has an RSA key and a newer ES256 key (minted by the I2SIG_KEY_ALG
// default), is served ES256 SETs under the ES256 kid.
func TestPollRouter_EmptySigningAlgSignsWithTheNewestKeyType(t *testing.T) {
	t.Setenv(services.KeyAlgEnvVar, "ES256")
	h, _ := newPollKeyHarness(t, "1h")
	_, err := h.keyService.EnsureSigningKeyForAlg(context.Background(), pollKeyIssuer, "RS256", "")
	require.NoError(t, err)

	stream := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish) // mints ES256, the newest
	require.Empty(t, stream.StreamConfiguration.SigningAlg)
	_, esKid, err := h.keyService.GetSigner(context.Background(), pollKeyIssuer, "ES256")
	require.NoError(t, err)

	sid := stream.StreamConfiguration.Id
	h.queuePollEvents(t, sid, 2)
	sets, status := h.poll(sid)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, sets, 2)
	for _, token := range sets {
		parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		require.NoError(t, err)
		assert.Equal(t, "ES256", parsed.Header["alg"])
		assert.Equal(t, esKid, parsed.Header["kid"])
	}
}
