package server

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedSet renders a SET to its compact JWS string using RS256 and returns
// both the wire string and a matching JWKS the receiver can use to verify it.
// Per ADR-0066 §D2 the receiver requires a configured trust anchor — the
// alg=none unsigned test-fixture path is retired (goSet.JWS with nil key is
// now refused, and ParseReceivedSET rejects any SET when JWKS is nil).
func signedSet(t *testing.T, jti, iss, aud string) (string, *keyfunc.JWKS) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	set := goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   iss,
			Audience: jwt.ClaimStrings{aud},
		},
		Events: map[string]interface{}{
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]interface{}{},
		},
	}
	set.ID = jti
	// Force a kid the JWKS below is keyed by.
	set.Kid = "kid-" + jti

	signed, err := set.JWS(jwt.SigningMethodRS256, priv)
	require.NoError(t, err)

	given := keyfunc.NewGivenRSA(&priv.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{set.Kid: given})
	return signed, jwks
}

// TestParseSstpInboundSets_ValidSetIsParsed: each byte-identical RFC8935 SET in
// the SSTP message "sets" map is parsed via goSetPush.ParseReceivedSET and
// returned as an SstpInboundSet carrying the verified token + raw string (Q5.1).
func TestParseSstpInboundSets_ValidSetIsParsed(t *testing.T) {
	const iss, aud = "https://peer.example", "https://local.example"
	raw, jwks := signedSet(t, "jti-ok", iss, aud)
	msg := goSetSstp.Message{Sets: map[string]string{"jti-ok": raw}}

	parsed, setErrs := parseSstpInboundSets(msg, goSetPush.ReceiverConfig{
		JWKS:              jwks,
		ExpectedIssuer:    iss,
		ExpectedAudiences: []string{aud},
	})

	require.Empty(t, setErrs, "a valid SET produces no per-JTI error")
	require.Len(t, parsed, 1)
	assert.Equal(t, "jti-ok", parsed[0].Jti)
	require.NotNil(t, parsed[0].Token)
	assert.Equal(t, "jti-ok", parsed[0].Token.ID)
	assert.Equal(t, raw, parsed[0].Raw)
}

// TestParseSstpInboundSets_BadIssuerYieldsSetErr: a SET whose issuer does not
// match the rx-side expected issuer is rejected per-JTI (mapped to the SSTP §2.3
// vocabulary), not parsed into the inbound batch. The bad-issuer decision fires
// on the pre-verify Peek per ADR-0066 §D3 (which is why no JWKS is needed here —
// the receiver never reaches the verify step).
func TestParseSstpInboundSets_BadIssuerYieldsSetErr(t *testing.T) {
	const aud = "https://local.example"
	raw, jwks := signedSet(t, "jti-bad-iss", "https://attacker.example", aud)
	msg := goSetSstp.Message{Sets: map[string]string{"jti-bad-iss": raw}}

	parsed, setErrs := parseSstpInboundSets(msg, goSetPush.ReceiverConfig{
		JWKS:              jwks,
		ExpectedIssuer:    "https://peer.example",
		ExpectedAudiences: []string{aud},
	})

	assert.Empty(t, parsed, "an invalid SET is not added to the inbound batch")
	require.Contains(t, setErrs, "jti-bad-iss")
	assert.Equal(t, goSetSstp.ErrJwtIss, setErrs["jti-bad-iss"].Err,
		"invalid issuer maps to the jwtIss SSTP error code")
}
