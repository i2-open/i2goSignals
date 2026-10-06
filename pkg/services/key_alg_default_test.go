package services

// Spec #114 (i2goSignals#370): the newest issuer key decides the SET alg of a
// stream with no signing_alg, I2SIG_KEY_ALG picks the type of a key minted with
// no algorithm (ES256 by default), and the auth-token key stays RSA.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

func TestDefaultKeyAlgFromEnv(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"", "ES256"},
		{"   ", "ES256"},
		{"RS256", "RS256"},
		{"ES256", "ES256"},
		{" ML-DSA-65 ", "ML-DSA-65"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv(KeyAlgEnvVar, tc.raw)
			got, err := DefaultKeyAlgFromEnv()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	for _, bad := range []string{"HS256", "es256", "ES384", "rsa"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			t.Setenv(KeyAlgEnvVar, bad)
			_, err := DefaultKeyAlgFromEnv()
			require.Error(t, err)
			assert.Contains(t, err.Error(), KeyAlgEnvVar)
			assert.Contains(t, err.Error(), bad)
		})
	}
}

func TestDefaultKeyAlg_UnsetIsES256(t *testing.T) {
	t.Setenv(KeyAlgEnvVar, "")
	svc := NewKeyService(memory.NewKeyDAO(), "DEFAULT", nil, nil)
	assert.Equal(t, "ES256", svc.DefaultKeyAlg())

	t.Setenv(KeyAlgEnvVar, "bogus")
	svc = NewKeyService(memory.NewKeyDAO(), "DEFAULT", nil, nil)
	assert.Equal(t, "ES256", svc.DefaultKeyAlg(), "an invalid value falls back to ES256")
}

// newDefaultAlgService builds a KeyService with KeyAlgEnvVar set to alg and its
// token key and default-issuer key initialized.
func newDefaultAlgService(t *testing.T, alg string) *KeyService {
	t.Helper()
	t.Setenv(KeyAlgEnvVar, alg)
	svc := NewKeyService(memory.NewKeyDAO(), "DEFAULT", nil, nil)
	require.NoError(t, svc.InitializeTokenKey(context.Background(), rtIssuer))
	return svc
}

func TestCreateKeyPair_FollowsDefaultKeyAlg(t *testing.T) {
	ctx := context.Background()
	for alg, want := range map[string]string{"RS256": "RS256", "ES256": "ES256", mldsa.Alg: mldsa.Alg} {
		t.Run(alg, func(t *testing.T) {
			svc := newDefaultAlgService(t, alg)
			key, err := svc.CreateKeyPair(ctx, "https://minted.example", "sig", "")
			require.NoError(t, err)
			got, err := SigningAlgOf(key)
			require.NoError(t, err)
			assert.Equal(t, want, got)

			_, kid, err := svc.GetSigner(ctx, "https://minted.example", "")
			require.NoError(t, err)
			if want == "RS256" {
				assert.Equal(t, "https://minted.example", kid, "an RSA key keeps kid == keyName")
			} else {
				assert.NotEqual(t, "https://minted.example", kid)
			}
		})
	}
}

func TestTokenKeyStaysRSAUnderES256Default(t *testing.T) {
	ctx := context.Background()
	svc := newDefaultAlgService(t, "ES256")

	assert.IsType(t, &rsa.PrivateKey{}, svc.tokenKey, "auth tokens are RS256")
	assert.Equal(t, "DEFAULT", svc.tokenKid)
	tokenKey, tokenKid, err := svc.GetPrivateKeyWithKeyname(ctx, "DEFAULT")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, tokenKey)
	assert.Equal(t, "DEFAULT", tokenKid)

	// The default issuer's key follows I2SIG_KEY_ALG.
	issuerKey, _, err := svc.GetSigner(ctx, rtIssuer, "")
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, issuerKey)
}

// An issuer that adds an ES256 key to its RSA key switches every empty-alg
// stream to ES256 under the new kid; the RSA key stays published, so a SET
// signed before the switch still verifies.
func TestEmptyAlgSignsWithTheNewestKeyOfAnyType(t *testing.T) {
	ctx := context.Background()
	svc := newDefaultAlgService(t, "RS256")

	before := transmit(t, svc, "")
	assert.Equal(t, "RS256", decodeJOSEHeader(t, before)["alg"])

	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, "ES256", "")))
	_, esKid, err := svc.GetSigner(ctx, rtIssuer, "ES256")
	require.NoError(t, err)

	after := transmit(t, svc, "")
	header := decodeJOSEHeader(t, after)
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, esKid, header["kid"])

	jwks := receiverJWKS(t, svc)
	assert.Len(t, jwks.KIDs(), 2, "the RSA key stays published")
	for _, token := range []string{before, after} {
		_, err := jwt.Parse(token, jwks.Keyfunc)
		assert.NoError(t, err)
	}
}

// An RSA-only issuer signs an empty-alg stream exactly as before spec #114:
// RS256 under kid == issuer.
func TestEmptyAlgOnAnRSAOnlyIssuerIsUnchanged(t *testing.T) {
	ctx := context.Background()
	svc := newDefaultAlgService(t, "RS256")

	key, kid, err := svc.GetSigner(ctx, rtIssuer, "")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, key)
	assert.Equal(t, rtIssuer, kid)

	unset := transmit(t, svc, "")
	pinned := transmit(t, svc, "RS256")
	assert.Equal(t, decodeJOSEHeader(t, pinned), decodeJOSEHeader(t, unset))
	assert.Equal(t, "RS256", decodeJOSEHeader(t, unset)["alg"])
	assert.Equal(t, rtIssuer, decodeJOSEHeader(t, unset)["kid"])
}

// A pinned signing_alg ignores a newer key of another type.
func TestPinnedAlgIgnoresANewerKeyOfAnotherType(t *testing.T) {
	ctx := context.Background()
	svc := newDefaultAlgService(t, "RS256")
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, "ES256", "")))
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, mldsa.Alg, "")))

	for _, alg := range []string{"RS256", "ES256", mldsa.Alg} {
		header := decodeJOSEHeader(t, transmit(t, svc, alg))
		assert.Equal(t, alg, header["alg"])
	}
	assert.Equal(t, mldsa.Alg, decodeJOSEHeader(t, transmit(t, svc, ""))["alg"], "the ML-DSA key is newest")
}

func TestStreamSigningMethod(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	assert.Equal(t, "RS256", StreamSigningMethod("", rsaKey).Alg())
	assert.Equal(t, "ES256", StreamSigningMethod("", ecKey).Alg())
	assert.Equal(t, "RS256", StreamSigningMethod("", nil).Alg())
	assert.Equal(t, "RS256", StreamSigningMethod("", p384).Alg(), "an unsupported key falls back to RS256 and fails to sign")
	assert.Equal(t, "RS256", StreamSigningMethod("RS256", ecKey).Alg(), "a pinned alg decides")
	assert.Equal(t, "ES256", StreamSigningMethod("ES256", rsaKey).Alg())
}

func TestSigningAlgLabel(t *testing.T) {
	assert.Equal(t, "any key type", SigningAlgLabel(""))
	assert.Equal(t, "ES256", SigningAlgLabel("ES256"))
	assert.Equal(t, "RS256", SigningAlgLabel("RS256"))
}
