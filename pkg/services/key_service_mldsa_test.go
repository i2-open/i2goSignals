package services

// Transmitter-side RFC 9964 key management (i2goSignals#278).
//
// The per-stream opt-in only works if one issuer can hold two signing keys at
// once and publish both. These tests pin that: minting is idempotent and does
// not disturb the RSA key, selection is by algorithm rather than by recency,
// and the published JWKS carries both under distinct kids.

import (
	"context"
	cryptomldsa "crypto/mldsa"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

func newMLDSATestService(t *testing.T) (*KeyService, interfaces.KeyDAO) {
	t.Helper()
	dao := memory.NewKeyDAO()
	svc := NewKeyService(dao, "DEFAULT", nil, nil)
	require.NoError(t, svc.InitializeTokenKey(context.Background(), "https://tx.example.com"))
	return svc, dao
}

func TestEnsureSigningKeyForAlg_MintsAndPersistsAnMLDSAKeyOnFirstOptIn(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)

	created, err := svc.EnsureSigningKeyForAlg(ctx, "https://tx.example.com", mldsa.Alg, "")
	require.NoError(t, err)
	assert.True(t, created)

	recs, err := dao.FindByKeyName(ctx, "https://tx.example.com")
	require.NoError(t, err)

	var pq *interfaces.JwkKeyRec
	for _, rec := range recs {
		if rec.Alg == mldsa.Alg {
			pq = rec
		}
	}
	require.NotNil(t, pq, "the opt-in must persist a record the store can identify as ML-DSA")
	assert.Len(t, pq.KeyBytes, cryptomldsa.PrivateKeySize, "the stored private half is the 32-byte FIPS 204 seed")
	assert.Len(t, pq.PubKeyBytes, cryptomldsa.MLDSA65PublicKeySize)
	assert.NotEqual(t, "https://tx.example.com", pq.Kid,
		"the PQ key needs its own kid: both keys are published in the same JWKS")
}

func TestEnsureSigningKeyForAlg_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)

	created, err := svc.EnsureSigningKeyForAlg(ctx, "https://tx.example.com", mldsa.Alg, "")
	require.NoError(t, err)
	require.True(t, created)

	created, err = svc.EnsureSigningKeyForAlg(ctx, "https://tx.example.com", mldsa.Alg, "")
	require.NoError(t, err)
	assert.False(t, created, "a second stream opting in must reuse the issuer's key, not mint a rival one")

	recs, err := dao.FindByKeyName(ctx, "https://tx.example.com")
	require.NoError(t, err)
	pqCount := 0
	for _, rec := range recs {
		if rec.Alg == mldsa.Alg {
			pqCount++
		}
	}
	assert.Equal(t, 1, pqCount)
}

func TestEnsureSigningKeyForAlg_WillNotResurrectARevokedKey(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, "https://tx.example.com", mldsa.Alg, "")))

	recs, err := dao.FindByKeyName(ctx, "https://tx.example.com")
	require.NoError(t, err)
	var pqKid string
	for _, rec := range recs {
		if rec.Alg == mldsa.Alg {
			pqKid = rec.Kid
		}
	}
	require.NotEmpty(t, pqKid)
	_, _, err = svc.SetKeyStatus(ctx, "https://tx.example.com", pqKid, interfaces.KeyStatusRevoked)
	require.NoError(t, err)

	// ADR 0028: minting a fresh key over a revoked one would resurrect exactly
	// the signing the operator just stopped.
	created, err := svc.EnsureSigningKeyForAlg(ctx, "https://tx.example.com", mldsa.Alg, "")
	require.NoError(t, err)
	assert.False(t, created)
}

func err0(_ bool, err error) error { return err }

func TestGetSigner_SelectsByAlgorithmNotByRecency(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, "https://tx.example.com", mldsa.Alg, "")))

	// The ML-DSA record is the NEWEST record for this issuer. An RS256 stream
	// must still get the RSA key: selection is by algorithm, and getting this
	// wrong would sign RS256 tokens with a key RS256 cannot use.
	rsaSigner, rsaKid, err := svc.GetSigner(ctx, "https://tx.example.com", "")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, rsaSigner)

	pqSigner, pqKid, err := svc.GetSigner(ctx, "https://tx.example.com", mldsa.Alg)
	require.NoError(t, err)
	assert.IsType(t, &cryptomldsa.PrivateKey{}, pqSigner)

	assert.NotEqual(t, rsaKid, pqKid, "the two keys must be distinguishable by kid on the wire")

	// An explicit RS256 is the same request as an unset signing_alg.
	explicitSigner, explicitKid, err := svc.GetSigner(ctx, "https://tx.example.com", "RS256")
	require.NoError(t, err)
	assert.Equal(t, rsaKid, explicitKid)
	assert.IsType(t, &rsa.PrivateKey{}, explicitSigner)
}

func TestGetSigner_RejectsAnAlgorithmTheStoreCannotServe(t *testing.T) {
	svc, _ := newMLDSATestService(t)
	_, _, err := svc.GetSigner(context.Background(), "https://tx.example.com", "HS256")
	assert.Error(t, err)
}

func TestGetSigner_MissingPQKeyIsNotSilentlyServedAsRSA(t *testing.T) {
	svc, _ := newMLDSATestService(t)
	// No opt-in has happened, so there is no ML-DSA key. Falling back to the
	// issuer's RSA key here would produce a token whose header says ML-DSA-65
	// and whose signature is RSA — unverifiable by anybody.
	_, _, err := svc.GetSigner(context.Background(), "https://tx.example.com", mldsa.Alg)
	assert.ErrorIs(t, err, interfaces.ErrKeyNotFound)
}

// TestGetPublicJWKS_PublishesTheRSAAndAKPKeysSideBySide is the golden JWKS
// check from the acceptance criteria: shape and membership are asserted
// literally, because this document is the contract with every receiver.
func TestGetPublicJWKS_PublishesTheRSAAndAKPKeysSideBySide(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)

	before := svc.GetPublicJWKS(ctx, "https://tx.example.com")
	require.NotNil(t, before)
	beforeKeys := jwksKeys(t, *before)
	require.Len(t, beforeKeys, 1)
	require.Equal(t, "RSA", beforeKeys[0]["kty"])

	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, "https://tx.example.com", mldsa.Alg, "")))

	after := svc.GetPublicJWKS(ctx, "https://tx.example.com")
	require.NotNil(t, after)
	afterKeys := jwksKeys(t, *after)
	require.Len(t, afterKeys, 2, "the issuer publishes both keys; a non-PQ peer keeps using the RSA one")

	var rsaJWK, akpJWK map[string]any
	for _, key := range afterKeys {
		switch key["kty"] {
		case "RSA":
			rsaJWK = key
		case "AKP":
			akpJWK = key
		}
	}
	require.NotNil(t, rsaJWK)
	require.NotNil(t, akpJWK)

	assert.Equal(t, beforeKeys[0], rsaJWK,
		"adding a post-quantum key must not perturb a single byte of the classical key a receiver already trusts")

	assert.Equal(t, mldsa.Alg, akpJWK["alg"])
	assert.NotEmpty(t, akpJWK["pub"])
	assert.NotContains(t, akpJWK, "priv", "a published JWK must never carry the seed")
	assert.NotEqual(t, rsaJWK["kid"], akpJWK["kid"])
}

func jwksKeys(t *testing.T, doc json.RawMessage) []map[string]any {
	t.Helper()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(doc, &set))
	return set.Keys
}
