package goSetSstp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

// TestVerifyAll proves the batch helper returns one entry per input SET in
// ascending-JTI order with the same per-SET outcome VerifySET gives, whatever
// the parallelism, and that a bad SET only fails its own entry.
func TestVerifyAll(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	given := keyfunc.NewGivenCustom(&key.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	cfg := goSetSstp.VerifyConfig{
		JWKS:              keyfunc.NewGiven(map[string]keyfunc.GivenKey{"kid-batch": given}),
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
	}
	sign := func(jti, iss string) string {
		set := goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{ID: jti, Issuer: iss, Audience: jwt.ClaimStrings{testAudience}, IssuedAt: jwt.NewNumericDate(time.Now())},
			Events:           map[string]any{"https://example/event": map[string]any{}},
			Kid:              "kid-batch",
		}
		tok, err := set.JWS(jwt.SigningMethodRS256, key)
		require.NoError(t, err)
		return tok
	}

	const n = 25
	sets := make(map[string]string, n)
	for i := 0; i < n; i++ {
		sets[fmt.Sprintf("jti-%03d", i)] = sign(fmt.Sprintf("jti-%03d", i), testIssuer)
	}
	sets["jti-007"] = sign("jti-007", "https://wrong.issuer.example")
	sets["jti-013"] = "not.a.jws"

	for _, par := range []int{0, 1, 4, 100} {
		t.Run(fmt.Sprintf("parallelism=%d", par), func(t *testing.T) {
			out := goSetSstp.VerifyAll(sets, cfg, par)
			require.Len(t, out, n)
			for i, e := range out {
				assert.Equal(t, fmt.Sprintf("jti-%03d", i), e.JTI, "entries must be in ascending JTI order")
				assert.Equal(t, sets[e.JTI], e.Raw)
				switch e.JTI {
				case "jti-007":
					assert.Error(t, e.Err)
					assert.True(t, errors.Is(e.Err, goSetSstp.ErrIssuerCertMismatch), "wrong issuer must classify as ErrIssuerCertMismatch: %v", e.Err)
				case "jti-013":
					assert.True(t, errors.Is(e.Err, goSetSstp.ErrBadSignature), "garbage must classify as ErrBadSignature: %v", e.Err)
				default:
					require.NoError(t, e.Err)
					require.NotNil(t, e.Verified.Token)
					assert.Equal(t, e.JTI, e.Verified.Token.ID)
					assert.Equal(t, "kid-batch", e.Verified.Token.Kid)
				}
			}
		})
	}

	assert.Empty(t, goSetSstp.VerifyAll(nil, cfg, 4), "an empty batch yields no entries")
}
