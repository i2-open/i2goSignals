package server

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unsignedSet renders a SET to its compact (alg=none) JWS string so the parse
// helper can validate it with goSetPush.ParseReceivedSET (JWKS=nil verifies an
// alg=none token's claims without a signature).
func unsignedSet(t *testing.T, jti, iss, aud string) string {
	t.Helper()
	tok := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   iss,
			Audience: jwt.ClaimStrings{aud},
		},
		Events: map[string]interface{}{
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]interface{}{},
		},
	}
	tok.ID = jti
	s, err := tok.JWT().SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return s
}

// TestParseSstpInboundSets_ValidSetIsParsed: each byte-identical RFC8935 SET in
// the SSTP message "sets" map is parsed via goSetPush.ParseReceivedSET and
// returned as an SstpInboundSet carrying the verified token + raw string (Q5.1).
func TestParseSstpInboundSets_ValidSetIsParsed(t *testing.T) {
	const iss, aud = "https://peer.example", "https://local.example"
	raw := unsignedSet(t, "jti-ok", iss, aud)
	msg := goSetSstp.Message{Sets: map[string]string{"jti-ok": raw}}

	parsed, setErrs := parseSstpInboundSets(msg, goSetPush.ReceiverConfig{
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
// vocabulary), not parsed into the inbound batch.
func TestParseSstpInboundSets_BadIssuerYieldsSetErr(t *testing.T) {
	const aud = "https://local.example"
	raw := unsignedSet(t, "jti-bad-iss", "https://attacker.example", aud)
	msg := goSetSstp.Message{Sets: map[string]string{"jti-bad-iss": raw}}

	parsed, setErrs := parseSstpInboundSets(msg, goSetPush.ReceiverConfig{
		ExpectedIssuer:    "https://peer.example",
		ExpectedAudiences: []string{aud},
	})

	assert.Empty(t, parsed, "an invalid SET is not added to the inbound batch")
	require.Contains(t, setErrs, "jti-bad-iss")
	assert.Equal(t, goSetSstp.ErrJwtIss, setErrs["jti-bad-iss"].Err,
		"invalid issuer maps to the jwtIss SSTP error code")
}
