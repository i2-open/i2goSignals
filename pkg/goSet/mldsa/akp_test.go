package mldsa_test

import (
	cryptomldsa "crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

// RFC 9964 "AKP" JWK codec (i2goSignals#278).
//
// The wire shape is the contract with every other implementation, so these
// tests assert the JSON members literally rather than only round-tripping
// through this package's own reader — a symmetric bug in Marshal and Unmarshal
// would survive a round-trip test alone.

func TestAKPKey_MarshalsTheRFC9964Members(t *testing.T) {
	sk, err := mldsa.GenerateKey()
	require.NoError(t, err)
	akp, err := mldsa.NewAKPKey("issuer-ML-DSA-65-1", sk)
	require.NoError(t, err)

	raw, err := json.Marshal(akp)
	require.NoError(t, err)

	var members map[string]any
	require.NoError(t, json.Unmarshal(raw, &members))
	assert.Equal(t, "AKP", members["kty"], "RFC 9964 gives every PQ signature scheme the one key type AKP")
	assert.Equal(t, "ML-DSA-65", members["alg"], "the parameter set lives in alg, not kty")
	assert.Equal(t, "issuer-ML-DSA-65-1", members["kid"])
	assert.Contains(t, members, "pub")
	assert.Contains(t, members, "priv")

	// base64url without padding (RFC 7515 §2), not the standard alphabet.
	pub, err := base64.RawURLEncoding.DecodeString(members["pub"].(string))
	require.NoError(t, err, "pub must be unpadded base64url")
	assert.Len(t, pub, cryptomldsa.MLDSA65PublicKeySize)

	priv, err := base64.RawURLEncoding.DecodeString(members["priv"].(string))
	require.NoError(t, err, "priv must be unpadded base64url")
	assert.Len(t, priv, cryptomldsa.PrivateKeySize,
		"RFC 9964's priv is the 32-byte FIPS 204 seed, not the expanded key")
}

func TestAKPKey_RoundTripsThroughJSON(t *testing.T) {
	sk, err := mldsa.GenerateKey()
	require.NoError(t, err)
	akp, err := mldsa.NewAKPKey("kid-1", sk)
	require.NoError(t, err)
	raw, err := json.Marshal(akp)
	require.NoError(t, err)

	var back mldsa.AKPKey
	require.NoError(t, json.Unmarshal(raw, &back))
	assert.Equal(t, *akp, back)

	// The reconstructed private key must be the same key, not merely a
	// well-formed one: the seed is what the store persists.
	recovered, err := back.PrivateKey()
	require.NoError(t, err)
	assert.True(t, recovered.Equal(sk))
	recoveredPub, err := back.PublicKey()
	require.NoError(t, err)
	assert.True(t, recoveredPub.Equal(sk.PublicKey()))
}

func TestAKPKey_PublicJWKCarriesNoPrivateMaterial(t *testing.T) {
	sk, err := mldsa.GenerateKey()
	require.NoError(t, err)
	akp, err := mldsa.NewAKPKey("kid-1", sk)
	require.NoError(t, err)

	raw, err := json.Marshal(akp.PublicJWK())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "priv",
		"a JWKS entry must never carry the seed; omitting the member is the guard")

	var back mldsa.AKPKey
	require.NoError(t, json.Unmarshal(raw, &back))
	_, err = back.PrivateKey()
	assert.Error(t, err, "a public-only JWK must refuse to yield a private key rather than return a zero one")
}

func TestNewAKPPublicKey_MatchesTheStrippedPrivateForm(t *testing.T) {
	sk, err := mldsa.GenerateKey()
	require.NoError(t, err)
	fromPrivate, err := mldsa.NewAKPKey("kid-1", sk)
	require.NoError(t, err)
	fromPublic, err := mldsa.NewAKPPublicKey("kid-1", sk.PublicKey())
	require.NoError(t, err)

	assert.Equal(t, *fromPrivate.PublicJWK(), *fromPublic)
}

func TestUnmarshalJSON_ToleratesPaddedBase64url(t *testing.T) {
	sk, err := mldsa.GenerateKey()
	require.NoError(t, err)
	padded, err := json.Marshal(map[string]string{
		"kty": "AKP",
		"alg": "ML-DSA-65",
		"kid": "kid-1",
		"pub": base64.URLEncoding.EncodeToString(sk.PublicKey().Bytes()),
	})
	require.NoError(t, err)

	// RFC 7515 forbids padding, but producers emit it; refusing the key would
	// cost a receiver an otherwise perfectly good verification.
	var key mldsa.AKPKey
	require.NoError(t, json.Unmarshal(padded, &key))
	pub, err := key.PublicKey()
	require.NoError(t, err)
	assert.True(t, pub.Equal(sk.PublicKey()))
}

func TestParseAKPJWK_SkipsKeysThatAreNotMLDSA65(t *testing.T) {
	rsaJWK := []byte(`{"kty":"RSA","kid":"rsa-1","n":"AQAB","e":"AQAB"}`)
	_, err := mldsa.ParseAKPJWK(rsaJWK)
	assert.ErrorIs(t, err, mldsa.ErrNotAKP, "a JWKS mixes key types; an RSA entry is skipped, not fatal")

	otherParams := []byte(`{"kty":"AKP","alg":"ML-DSA-87","kid":"pq-87","pub":"AAAA"}`)
	_, err = mldsa.ParseAKPJWK(otherParams)
	assert.ErrorIs(t, err, mldsa.ErrNotAKP)
}

func TestParseAKPJWK_RejectsAWrongSizedPublicKey(t *testing.T) {
	truncated := []byte(`{"kty":"AKP","alg":"ML-DSA-65","kid":"pq-1","pub":"AAAA"}`)
	_, err := mldsa.ParseAKPJWK(truncated)
	require.ErrorIs(t, err, mldsa.ErrNotAKP)
	assert.Contains(t, err.Error(), "want 1952")
}

func TestNewAKPKey_RejectsAKeyOfAnotherParameterSet(t *testing.T) {
	sk44, err := cryptomldsa.GenerateKey(cryptomldsa.MLDSA44())
	require.NoError(t, err)
	_, err = mldsa.NewAKPKey("kid-1", sk44)
	assert.ErrorIs(t, err, mldsa.ErrKeyType)
}

func TestSigningMethod_AcceptsAnAKPKeyAsAVerificationKey(t *testing.T) {
	sk, err := mldsa.GenerateKey()
	require.NoError(t, err)
	sig, err := mldsa.SigningMethodMLDSA65.Sign("payload", sk)
	require.NoError(t, err)

	akp, err := mldsa.NewAKPPublicKey("kid-1", sk.PublicKey())
	require.NoError(t, err)
	assert.NoError(t, mldsa.SigningMethodMLDSA65.Verify("payload", sig, akp))
}
