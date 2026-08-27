package test

// Algorithm allow-list on the SET trust path (i2goSignals#271).
//
// ADR-0066 §D3 split Parse (verify-only) from Peek (explicitly unverified).
// That closes the "no signature at all" hole but not the algorithm-confusion
// one: without an allow-list the parser accepts whatever alg the *attacker*
// put in the header and then goes looking for a key that fits it. The classic
// exploit is an HS256 token HMAC'd with the issuer's public RSA modulus, which
// is a value the attacker already has.
//
// goSet.AllowedAlgs + jwt.WithValidMethods make the accepted set explicit and,
// crucially, check it *before* key lookup. The tests below prove both halves:
// that the wrong alg is refused, and that it is refused early — established by
// a control token with the same unknown kid, which fails with a *different*
// error precisely because it got as far as the JWKS.

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

func TestAllowedAlgs_ListsTheAlgorithmsThisProjectSignsWith(t *testing.T) {
	// ML-DSA-65 joined the list with RFC 9964 per-stream signing (#278). It is
	// listed unconditionally because the allow-list gates the token *header*:
	// a receiver must accept a PQ-signed SET from a peer whether or not this
	// node has a stream transmitting one.
	assert.Equal(t, []string{"RS256", "ES256", "ML-DSA-65"}, goSet.AllowedAlgs(),
		"the allow-list must track what JWS actually produces; widening it is a deliberate act")
}

func TestAllowedAlgs_ReturnsAFreshSlice(t *testing.T) {
	got := goSet.AllowedAlgs()
	require.NotEmpty(t, got)
	got[0] = "HS256"

	assert.Equal(t, []string{"RS256", "ES256", "ML-DSA-65"}, goSet.AllowedAlgs(),
		"a caller must not be able to widen the verifier's allow-list by writing to a returned slice")
}

// newAlgConfusionFixture builds a JWKS that knows exactly one kid, and returns
// a helper that mints tokens under a *different* kid. Every token the tests
// produce would therefore fail key lookup — so any error that is not the
// key-lookup error proves the parser rejected the token before getting there.
func newAlgConfusionFixture(t *testing.T) (jwks *keyfunc.JWKS, priv *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pub := priv.PublicKey
	given := keyfunc.NewGivenRSA(&pub, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	return keyfunc.NewGiven(map[string]keyfunc.GivenKey{"the-only-known-kid": given}), priv
}

const unknownKid = "a-kid-the-jwks-has-never-heard-of"

func newSetForAlgTests(t *testing.T) *goSet.SecurityEventToken {
	t.Helper()
	set := goSet.CreateSet(nil, "https://issuer.example.com", []string{"https://aud.example.com"})
	set.AddEventPayload("uri:test:event", map[string]interface{}{"alg": "confusion"})
	return &set
}

func signWith(t *testing.T, method jwt.SigningMethod, key interface{}) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, newSetForAlgTests(t))
	tok.Header["typ"] = "secevent+jwt"
	tok.Header["kid"] = unknownKid
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

// keyLookupErrorFragment is what the JWKS returns for an unknown kid. The
// control assertion below pins it, so if the library ever reworks the message
// the "rejected before key lookup" claim fails loudly rather than passing for
// the wrong reason.
const keyLookupErrorFragment = "key ID"

// TestParse_ControlTokenReachesKeyLookup establishes the control: a token with
// an accepted alg and an unknown kid gets all the way to the JWKS and fails
// there. Without this, "the HS256 token failed" would prove nothing about
// *where* it failed.
func TestParse_ControlTokenReachesKeyLookup(t *testing.T) {
	jwks, priv := newAlgConfusionFixture(t)

	got, err := goSet.Parse(signWith(t, jwt.SigningMethodRS256, priv), jwks)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(keyLookupErrorFragment),
		"an allowed alg with an unknown kid must fail at key lookup — that is the control")
}

// TestParse_HS256RejectedBeforeKeyLookup is the algorithm-confusion case: the
// same unknown kid, but HMAC-signed. It must fail on the algorithm, not on the
// kid, which is only possible if the alg check runs first.
func TestParse_HS256RejectedBeforeKeyLookup(t *testing.T) {
	jwks, priv := newAlgConfusionFixture(t)

	// The attacker's "key": the issuer's own public modulus, which is public.
	hmacKey := priv.PublicKey.N.Bytes()

	got, err := goSet.Parse(signWith(t, jwt.SigningMethodHS256, hmacKey), jwks)
	require.Error(t, err, "an HS256 SET must never be accepted")
	assert.Nil(t, got)
	assert.True(t, errors.Is(err, jwt.ErrTokenSignatureInvalid),
		"rejection must be a signature/method error, got %v", err)
	assert.Contains(t, err.Error(), "signing method HS256 is invalid",
		"the refusal must name the algorithm so an operator can see what was attempted")
	assert.NotContains(t, strings.ToLower(err.Error()), strings.ToLower(keyLookupErrorFragment),
		"the JWKS must never have been consulted: the same kid is unknown, so a key-lookup "+
			"error here would mean the alg check ran too late")
}

// TestParse_NoneRejectedBeforeKeyLookup covers alg=none. ADR-0066 §D3 already
// made this fail; WithValidMethods now makes it fail for the stated reason,
// before any key handling.
func TestParse_NoneRejectedBeforeKeyLookup(t *testing.T) {
	jwks, _ := newAlgConfusionFixture(t)

	got, err := goSet.Parse(signWith(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType), jwks)
	require.Error(t, err, "alg=none must never be accepted where a signature is expected")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "signing method none is invalid")
	assert.NotContains(t, strings.ToLower(err.Error()), strings.ToLower(keyLookupErrorFragment),
		"alg=none must be refused before the JWKS is consulted")
}

// TestParse_AllowedAlgStillAccepted guards against the allow-list being so
// tight that the project can no longer verify its own tokens.
func TestParse_AllowedAlgStillAccepted(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	set := newSetForAlgTests(t)
	set.Kid = "allowed-alg-kid"
	signed, err := set.JWS(jwt.SigningMethodRS256, priv)
	require.NoError(t, err)

	pub := priv.PublicKey
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		set.Kid: keyfunc.NewGivenRSA(&pub, keyfunc.GivenKeyOptions{Algorithm: "RS256"}),
	})

	got, err := goSet.Parse(signed, jwks)
	require.NoError(t, err, "RS256 is on the allow-list and must still verify")
	require.NotNil(t, got)
	assert.Equal(t, "https://issuer.example.com", got.Issuer)
}

// TestPeek_UnaffectedByAllowedAlgs pins the AC's other half: Peek is
// unverified by design and must keep parsing an alg the verifier refuses,
// because push receivers rely on it to read iss/aud before verification.
func TestPeek_UnaffectedByAllowedAlgs(t *testing.T) {
	hs256 := signWith(t, jwt.SigningMethodHS256, []byte("whatever"))

	got, err := goSet.Peek(hs256)
	require.NoError(t, err, "Peek must remain signature- and algorithm-agnostic")
	require.NotNil(t, got)
	assert.Equal(t, "https://issuer.example.com", got.Issuer)
}
