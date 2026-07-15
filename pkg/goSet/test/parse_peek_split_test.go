package test

// ADR-0066 §D3 — verify-only Parse + explicit Peek API split.
//
// These tests pin the trust-path contract that i2goSignals#234 introduced:
//   - goSet.Parse(tokenString, nil) MUST return an error (no silent
//     ParseUnverified fallback; alg=none is never accepted where a signature
//     is expected).
//   - goSet.Peek(tokenString) MUST return the token's claims WITHOUT verifying
//     the signature, and MUST NEVER be treated as an accepted-token API by any
//     caller — the tests here only assert its parse-shape.
//   - goSet.JWS with a nil key MUST be refused — the alg=none production path
//     has been removed; if a test needs an unsigned wire string it must
//     construct it directly via the jwt library.
//
// If any of these tests fail, /pkg/goSet is regressing on ADR-0066 §D3 and no
// receiver in the family can be trusted to reject the "None + unverified"
// injection shape.

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// newSignedSetForSplitTests produces a small signed SET wire string plus the
// JWKS a verifier would need to accept it. Uses RS256 to match production
// posture. Returned separately so tests can wire them in different orders.
func newSignedSetForSplitTests(t *testing.T) (signedString string, jwks *keyfunc.JWKS, kid string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	set := goSet.CreateSet(
		nil,
		"https://issuer.example.com",
		[]string{"https://aud.example.com"},
	)
	set.AddEventPayload("uri:test:event", map[string]interface{}{"a": 1})
	set.Kid = "kid-parse-peek-split"

	signed, err := set.JWS(jwt.SigningMethodRS256, priv)
	require.NoError(t, err)

	pub := priv.PublicKey
	given := keyfunc.NewGivenRSA(&pub, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	j := keyfunc.NewGiven(map[string]keyfunc.GivenKey{set.Kid: given})

	return signed, j, set.Kid
}

// newUnsignedSetForSplitTests constructs an alg=none SET wire string directly
// via the jwt library — the goSet package no longer produces one, per
// ADR-0066 §D3. This exists ONLY to feed Peek and to prove Parse refuses it.
func newUnsignedSetForSplitTests(t *testing.T) string {
	t.Helper()
	set := goSet.CreateSet(
		nil,
		"https://issuer.example.com",
		[]string{"https://aud.example.com"},
	)
	set.AddEventPayload("uri:test:event", map[string]interface{}{"peek": true})
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, &set)
	tok.Header["typ"] = "secevent+jwt"
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return s
}

// TestParse_NilJwks_Rejected pins the ADR-0066 §D3 rule: the verify-only Parse
// API refuses a nil JWKS. If this test starts passing again, the silent
// ParseUnverified fallback has been reintroduced.
func TestParse_NilJwks_Rejected(t *testing.T) {
	signed, _, _ := newSignedSetForSplitTests(t)

	got, err := goSet.Parse(signed, nil)
	require.Error(t, err, "goSet.Parse with nil JWKS must be refused")
	assert.Nil(t, got, "no token must be returned when Parse refuses")
	assert.Contains(t, err.Error(), "JWKS is required", "refusal must cite the ADR-0066 §D3 posture")
	assert.Contains(t, err.Error(), "Peek", "refusal must point callers at the explicit Peek API")
}

// TestParse_SignedTokenAccepted confirms Parse still accepts a well-signed
// SET when a JWKS is provided — the guardrail must be strict, not blanket.
func TestParse_SignedTokenAccepted(t *testing.T) {
	signed, jwks, _ := newSignedSetForSplitTests(t)

	got, err := goSet.Parse(signed, jwks)
	require.NoError(t, err, "signed SET must be accepted when JWKS validates")
	require.NotNil(t, got)
	assert.Equal(t, "https://issuer.example.com", got.Issuer)
}

// TestParse_UnsignedRefusedEvenWithJwks proves alg=none is never accepted
// where a signature is expected: an unsigned SET presented to Parse with a
// real JWKS still fails signature verification.
func TestParse_UnsignedRefusedEvenWithJwks(t *testing.T) {
	unsigned := newUnsignedSetForSplitTests(t)
	_, jwks, _ := newSignedSetForSplitTests(t)

	got, err := goSet.Parse(unsigned, jwks)
	require.Error(t, err, "alg=none must not be accepted where a signature is expected")
	assert.Nil(t, got)
}

// TestPeek_ReturnsUnverifiedClaims confirms Peek exposes the claims for
// routing/dispatch without ever running signature verification.
func TestPeek_ReturnsUnverifiedClaims(t *testing.T) {
	unsigned := newUnsignedSetForSplitTests(t)

	got, err := goSet.Peek(unsigned)
	require.NoError(t, err, "Peek must return unverified claims on an unsigned SET")
	require.NotNil(t, got)
	assert.Equal(t, "https://issuer.example.com", got.Issuer, "iss must be readable for pre-verify routing")
	require.Contains(t, got.Audience, "https://aud.example.com")
}

// TestPeek_OnSignedToken_DoesNotVerify confirms Peek is signature-agnostic —
// it happily returns claims from a signed SET without checking the signature.
// (If Peek starts verifying, callers may mistake its output for an accepted
// token, which is the exact conflation ADR-0066 §D3 rules out.)
func TestPeek_OnSignedToken_DoesNotVerify(t *testing.T) {
	signed, _, _ := newSignedSetForSplitTests(t)

	got, err := goSet.Peek(signed)
	require.NoError(t, err, "Peek must succeed on any well-formed SET, signed or not")
	require.NotNil(t, got)
	assert.Equal(t, "https://issuer.example.com", got.Issuer)
}

// TestPeek_TypeCheckEnforced confirms Peek still enforces the secevent+jwt
// type header — a wrong-typ JWT is rejected even at peek time so misrouted
// tokens can't leak into SET-handling code paths.
func TestPeek_TypeCheckEnforced(t *testing.T) {
	set := goSet.CreateSet(nil, "iss", []string{"aud"})
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, &set)
	tok.Header["typ"] = "jwt" // wrong type
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	got, err := goSet.Peek(s)
	require.Error(t, err, "Peek must still enforce the secevent+jwt type")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "secevent+jwt")
}

// TestJWS_NilKey_Refused pins that goSet.JWS refuses to produce an alg=none
// wire token — the write-side None path was removed with ADR-0066 §D3.
func TestJWS_NilKey_Refused(t *testing.T) {
	set := goSet.CreateSet(nil, "iss", []string{"aud"})
	got, err := set.JWS(jwt.SigningMethodRS256, nil)
	require.Error(t, err, "JWS with nil key must be refused")
	assert.Equal(t, "", got)
	assert.Contains(t, err.Error(), "alg=none production removed", "refusal must cite the ADR-0066 §D3 rationale")
}
