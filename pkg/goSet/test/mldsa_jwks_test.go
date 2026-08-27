package test

// Receiver-side RFC 9964 verification (i2goSignals#278).
//
// keyfunc parses a JWK Set by switching on "kty" and silently skipping types it
// does not know, so a JWKS publishing an RSA key and an ML-DSA "AKP" key side
// by side loads today with the AKP key simply absent — and a PQ-signed SET
// fails with "kid not found", not with anything that says "this receiver cannot
// do ML-DSA". goSet.NewJwksWithAKP closes that gap. The tests below prove the
// dual-key set resolves BOTH kids, that the classical half is untouched, and
// that the algorithm pinning survives the merge.

import (
	cryptomldsa "crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

// dualKeyJWKS builds the document a transmitter with one RS256 stream and one
// ML-DSA-65 stream publishes: one issuer, two keys, two kids.
func dualKeyJWKS(t *testing.T) (raw json.RawMessage, rsaKey *rsa.PrivateKey, pqKey *cryptomldsa.PrivateKey) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pqKey, err = mldsa.GenerateKey()
	require.NoError(t, err)

	akp, err := mldsa.NewAKPPublicKey("issuer-ML-DSA-65-1", pqKey.PublicKey())
	require.NoError(t, err)
	akpJSON, err := json.Marshal(akp)
	require.NoError(t, err)

	rsaJSON, err := json.Marshal(map[string]string{
		"kty": "RSA",
		"kid": "issuer",
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.PublicKey.E)).Bytes()),
	})
	require.NoError(t, err)

	doc, err := json.Marshal(map[string]any{"keys": []json.RawMessage{rsaJSON, akpJSON}})
	require.NoError(t, err)
	return doc, rsaKey, pqKey
}

func signSET(t *testing.T, method jwt.SigningMethod, key any, kid string) string {
	t.Helper()
	set := goSet.CreateSet(nil, "https://tx.example.com", []string{"https://rx.example.com"})
	set.AddEventPayload("urn:example:event:a", map[string]string{"detail": "pq"})
	set.Kid = kid
	token := jwt.NewWithClaims(method, &set)
	token.Header["typ"] = "secevent+jwt"
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestNewJwksWithAKP_ResolvesBothKidsFromOneIssuer(t *testing.T) {
	raw, rsaKey, pqKey := dualKeyJWKS(t)

	jwks, err := goSet.NewJwksWithAKP(raw)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"issuer", "issuer-ML-DSA-65-1"}, jwks.KIDs(),
		"the dual-key JWKS must expose both the classical and the post-quantum kid")

	pqSet, err := goSet.Parse(signSET(t, mldsa.SigningMethodMLDSA65, pqKey, "issuer-ML-DSA-65-1"), jwks)
	require.NoError(t, err)
	assert.Equal(t, "https://tx.example.com", pqSet.Issuer)

	// The RS256 stream on the same issuer keeps verifying exactly as before —
	// that is the whole promise of a per-stream opt-in.
	rsSet, err := goSet.Parse(signSET(t, jwt.SigningMethodRS256, rsaKey, "issuer"), jwks)
	require.NoError(t, err)
	assert.Equal(t, "https://tx.example.com", rsSet.Issuer)
}

func TestNewJwksWithAKP_LeavesAClassicalJWKSAlone(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaJSON, err := json.Marshal(map[string]string{
		"kty": "RSA", "kid": "issuer", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.PublicKey.E)).Bytes()),
	})
	require.NoError(t, err)
	doc, err := json.Marshal(map[string]any{"keys": []json.RawMessage{rsaJSON}})
	require.NoError(t, err)

	jwks, err := goSet.NewJwksWithAKP(doc)
	require.NoError(t, err)
	assert.Equal(t, []string{"issuer"}, jwks.KIDs())

	_, err = goSet.Parse(signSET(t, jwt.SigningMethodRS256, rsaKey, "issuer"), jwks)
	assert.NoError(t, err)
}

func TestNewJwksWithAKP_APQKidCannotBeUsedForAnRS256Header(t *testing.T) {
	raw, rsaKey, _ := dualKeyJWKS(t)
	jwks, err := goSet.NewJwksWithAKP(raw)
	require.NoError(t, err)

	// The AKP given key pins Algorithm=ML-DSA-65, so keyfunc refuses to hand it
	// to a token claiming a different alg — the algorithm-confusion guard
	// applied at the key as well as at the header.
	_, err = goSet.Parse(signSET(t, jwt.SigningMethodRS256, rsaKey, "issuer-ML-DSA-65-1"), jwks)
	assert.Error(t, err)
}

func TestAKPGivenKeys_SkipsUnusableEntriesWithoutLosingTheSet(t *testing.T) {
	raw, _, _ := dualKeyJWKS(t)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &set))
	set.Keys = append(set.Keys, json.RawMessage(`{"kty":"AKP","alg":"ML-DSA-65","kid":"broken","pub":"AAAA"}`))
	doc, err := json.Marshal(set)
	require.NoError(t, err)

	given, err := goSet.AKPGivenKeys(doc)
	require.NoError(t, err, "one malformed key must not cost a receiver the rest of the set")
	assert.Len(t, given, 1)
	assert.Contains(t, given, "issuer-ML-DSA-65-1")
	assert.NotContains(t, given, "broken")
}

func TestSigningMethodFor_MapsTheStreamConfiguredAlg(t *testing.T) {
	rs256, err := goSet.SigningMethodFor("")
	require.NoError(t, err)
	assert.Equal(t, "RS256", rs256.Alg(), "an unset signing_alg keeps a stream on RS256")

	explicit, err := goSet.SigningMethodFor("RS256")
	require.NoError(t, err)
	assert.Equal(t, "RS256", explicit.Alg())

	pq, err := goSet.SigningMethodFor("ML-DSA-65")
	require.NoError(t, err)
	assert.Equal(t, "ML-DSA-65", pq.Alg())

	_, err = goSet.SigningMethodFor("HS256")
	assert.Error(t, err, "an algorithm this transmitter cannot produce is a configuration error")
}

func TestJWS_SignsWithMLDSAThroughTheSharedSigningEntryPoint(t *testing.T) {
	pqKey, err := mldsa.GenerateKey()
	require.NoError(t, err)
	set := goSet.CreateSet(nil, "https://tx.example.com", []string{"https://rx.example.com"})
	set.AddEventPayload("urn:example:event:a", map[string]string{"detail": "pq"})
	set.Kid = "issuer-ML-DSA-65-1"

	method, err := goSet.SigningMethodFor("ML-DSA-65")
	require.NoError(t, err)
	signed, err := set.JWS(method, pqKey)
	require.NoError(t, err)

	// goSet.JWS takes a crypto.Signer precisely so an ML-DSA key needs no new
	// signing entry point (#277); this asserts that seam actually holds.
	peeked, err := goSet.Peek(signed)
	require.NoError(t, err)
	assert.Equal(t, "https://tx.example.com", peeked.Issuer)

	akp, err := mldsa.NewAKPPublicKey("issuer-ML-DSA-65-1", pqKey.PublicKey())
	require.NoError(t, err)
	akpJSON, err := json.Marshal(akp)
	require.NoError(t, err)
	doc, err := json.Marshal(map[string]any{"keys": []json.RawMessage{akpJSON}})
	require.NoError(t, err)
	jwks, err := goSet.NewJwksWithAKP(doc)
	require.NoError(t, err)

	verified, err := goSet.Parse(signed, jwks)
	require.NoError(t, err)
	assert.Equal(t, peeked.ID, verified.ID)
}
