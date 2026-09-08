package services

// Transmitter-side ES256 key management (i2goSignals#284).
//
// The per-stream opt-in only works if one issuer can hold an RSA and an EC
// signing key at once and publish both. These tests pin that: minting is
// idempotent and does not disturb the RSA key, the stored record carries the
// EC encodings the DAO contract documents, and the published JWKS carries both
// keys under distinct kids so a receiver resolves by kid as it always has.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

func TestEnsureSigningKeyForAlg_MintsAndPersistsAnECKeyOnFirstOptIn(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)

	created, err := svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")
	require.NoError(t, err)
	assert.True(t, created, "the first ES256 opt-in must mint a key")

	recs, err := dao.FindByKeyName(ctx, rtIssuer)
	require.NoError(t, err)

	var ec *interfaces.JwkKeyRec
	for _, rec := range recs {
		if rec.Alg == es256Alg {
			ec = rec
		}
	}
	require.NotNil(t, ec, "the store must hold a record discriminated ES256")
	assert.NotEmpty(t, ec.KeyBytes, "the record must carry private material to sign with")
	assert.NotEqual(t, rtIssuer, ec.Kid, "the EC key needs a kid of its own; the RSA key already holds the issuer name")
	assert.Equal(t, "sig", ec.Use)

	// The stored bytes must be the encodings pkg/dao documents for ES256:
	// SEC 1 private, PKIX public, both decoding to the same P-256 key pair.
	signer, kid, err := parseSigningRec(ec)
	require.NoError(t, err)
	priv, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "an ES256 record must parse back as an ECDSA private key")
	assert.Equal(t, elliptic.P256(), priv.Curve, "ES256 names P-256; a different curve is a different algorithm")
	assert.Equal(t, ec.Kid, kid)

	pub, err := recPublicKey(ec)
	require.NoError(t, err)
	assert.Equal(t, &priv.PublicKey, pub, "the published public half must be the signing key's own")
}

func TestEnsureSigningKeyForAlg_ES256IsIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)

	created, err := svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")
	require.NoError(t, err)
	require.True(t, created)

	created, err = svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")
	require.NoError(t, err)
	assert.False(t, created, "a second opt-in must reuse the existing key, not rotate it")

	recs, err := dao.FindByKeyName(ctx, rtIssuer)
	require.NoError(t, err)
	count := 0
	for _, rec := range recs {
		if rec.Alg == es256Alg {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

// TestEnsureSigningKeyForAlg_ES256WillNotResurrectARevokedKey mirrors the ADR
// 0028 discipline the ML-DSA path carries: recreating a key an operator just
// revoked would silently restart the signing they stopped.
func TestEnsureSigningKeyForAlg_ES256WillNotResurrectARevokedKey(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")))

	recs, err := dao.FindByKeyName(ctx, rtIssuer)
	require.NoError(t, err)
	for _, rec := range recs {
		if rec.Alg == es256Alg {
			_, _, err = svc.SetKeyStatus(ctx, rtIssuer, rec.Kid, interfaces.KeyStatusRevoked)
			require.NoError(t, err)
		}
	}

	created, err := svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")
	require.NoError(t, err)
	assert.False(t, created, "a revoked ES256 key must not be silently replaced")

	_, _, err = svc.GetSigner(ctx, rtIssuer, es256Alg)
	assert.ErrorIs(t, err, interfaces.ErrKeyNotFound)
}

// TestGetPublicJWKS_PublishesTheRSAAndECKeysSideBySide is the receiver-facing
// half: the EC key has to appear in the issuer's JWKS as a normal EC JWK, next
// to an RSA entry that is unchanged.
func TestGetPublicJWKS_PublishesTheRSAAndECKeysSideBySide(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)

	beforeDoc := svc.GetPublicJWKS(ctx, rtIssuer)
	require.NotNil(t, beforeDoc)
	before := jwksMembers(t, *beforeDoc)
	require.Len(t, before, 1)

	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")))

	afterDoc := svc.GetPublicJWKS(ctx, rtIssuer)
	require.NotNil(t, afterDoc)
	after := jwksMembers(t, *afterDoc)
	require.Len(t, after, 2, "both keys must be published, under distinct kids")

	var ecKeys, rsaKeys int
	for kid, jwk := range after {
		switch jwk["kty"] {
		case "EC":
			ecKeys++
			assert.Equal(t, "P-256", jwk["crv"], "ES256 publishes on P-256")
			assert.NotEmpty(t, jwk["x"])
			assert.NotEmpty(t, jwk["y"])
			assert.NotContains(t, jwk, "d", "the private half must never reach the public JWKS")
		case "RSA":
			rsaKeys++
			assert.Equal(t, before[kid], jwk, "the RSA member must be untouched by the EC opt-in")
		}
	}
	assert.Equal(t, 1, ecKeys)
	assert.Equal(t, 1, rsaKeys)
}

// jwksMembers indexes a rendered JWK Set document by kid.
func jwksMembers(t *testing.T, doc json.RawMessage) map[string]map[string]any {
	t.Helper()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(doc, &set))
	byKid := make(map[string]map[string]any, len(set.Keys))
	for _, jwk := range set.Keys {
		kid, _ := jwk["kid"].(string)
		byKid[kid] = jwk
	}
	return byKid
}
