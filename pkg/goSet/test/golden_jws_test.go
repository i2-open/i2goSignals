package test

// Golden JWS bytes for the SET signing path (i2goSignals#277).
//
// Widening JWS's key parameter from *rsa.PrivateKey to crypto.Signer is meant
// to be a pure type generalisation: the same key and the same claims must
// still produce the same wire token, byte for byte. Nothing else pins that.
// A signature-only test ("it verifies") would pass even if the header gained a
// field, a claim were dropped, or the RSA padding scheme changed underneath —
// all of which are wire-visible to every receiver already deployed.
//
// RS256 is RSASSA-PKCS1-v1_5, which is deterministic, so a fixed key plus
// fixed claims has exactly one correct compact serialization. That makes an
// exact-string assertion legitimate here in a way it would not be for a
// randomised scheme such as PS256 or ECDSA.
//
// If this test fails, the SET wire format changed. That is either a bug or a
// deliberate, separately-authorised act — never a detail to re-record.

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// goldenSigningKeyPEM is a throwaway RSA-2048 key generated solely for this
// test. It is committed on purpose: the golden token below is only reproducible
// against this exact key, and it signs nothing outside this file.
const goldenSigningKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5GpbAPufi3nVHyaTE4e1m/zzwgZ7q2vzWmiVFhRPqjt63tYA
+0tjR3NCP3b4Y4QqARgmeOgC14EHevPwnVvijmKJiwE3swTi0Z9S3dC29xOVqh5y
zEq5QBvfthWLA3ULivbF/bgPm5KgVzZ++XOCH0KpaEw0NM8zaWviMspqHvKX5GEU
0O+73dC/FFM1cVBfvW7pLc8UaBhl3SNkIXZ2kG2TCTf2b4f51YsgFx87bYCJwP50
0hp7qbZsB53TSUQ5lyiA1W9aPQmciZ+xzRol7kLg9wXcynz+cxr2B764FkVdtkU0
kGshXY8wQGEpbvcfy9yO/dnR17evV1l7O9zrXQIDAQABAoIBACCEGW9i4pv23IWC
Nsa9d3d8w3CX/qvxAqQYpjyN6KdZr0ygl2Qun7Pwrvoc5BA6pMYiG3vzv0/RYPC6
YELubSqK0Xy10CmOZQGlViUYjKtQoOomSn5VltiO/0JK/86er2V5ascLGEGz1lqD
+gBl1py/nyEnU/k+k9mKj5leYkwERQdCLPG96kkMj/0rAuVJOUQ5iPCgRLBgROr4
whqDxePj0SaTFcF+Bs/acu82V71RRn40DGaYWRqhUHAj59wkJVoK72aZBtyiUp/z
Ik6l63nsvXGi7g2o4tATlTtGclMWMhEWqoE/cHiEdJpXRa35GnjG9xdPgmCH56Rn
Tlxhi4sCgYEA+CAiw2ZrUurDFxUKQwxfjLFUFGL7JBjxrQW0oBrwtGiQFiVcUyhP
GREcgoFtPSceftiYbOFAUIitRT1Ei3qrppF5qcc1EdHH6NbE79N9SoJoPm51rc6U
CXz5HW8ZJVnD4JSG50dM9CwS2RX6GFpWi5UrjzKJJ7GjQMHd0OKalvsCgYEA66oW
cT+h8r1Uj0uGy2TlcvtYMiblhN1RdxpP/WiOAbc0iiWAVh2BgL6wpEMNdx2X3v2t
UR5zTgT3j4sTpuKA4VSQjEt5so1G6I3UwUuHNCN5vBVVQ9X539HxIcS82miGj5rQ
tiK3pD4DlpIrd4G76Rog1XlyEUfBJbV+OUqYV4cCgYEAqNp9rcnqKYA3iWK5HA20
jHM0y7bcP6F1/hAO7pHG0o8B1wBPxwt8YIujgjB/3YjcmOffOuFDOkr411Ctb9no
LC99wwsc02aWi550YNzku6rpM+tJzCDz300b3mr3itJ+mTuaXpPIC7ZekTsCekYn
9U9rWETEz610cqI7yGYdW7cCgYEAvNlyXpJljwYVyzb07+0MyhWM2bO93bkVXWJi
k2nD0rAjlEj1DQ1cB/XHy/pHwhqe531V9Fl4gR8N26PRvbxpFykTJLoe7ey01AtE
YRnLYQbEuOpHh7LjKG8u0qa7yDJXEqE3e51amG1xpqm/12bJVMUxZqCJvjtIFpXY
bsTOS+UCgYAwakd9X4zgiZ/9bBGUv0cs9S2e88nRcHhfpOT/jFVX+6jA1td9R9Ou
g3pVsps8UTX9MNGYGMpw7XuQpzrT1trAse3R0bMSdPDmzu8bGhsk7voDQeASVOE6
/q0Cz4eRORkd2CeV2c51LQ8ac4Y4UxS73lkz28IpT511kmd16/NZhQ==
-----END RSA PRIVATE KEY-----`

// goldenSetJWS is the compact serialization JWS must produce for
// goldenSet() signed with goldenSigningKeyPEM under RS256. Recorded on
// release-0.12.0 before #277 widened the key parameter.
const goldenSetJWS = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImdvbGRlbi1raWQiLCJ0eXAiOiJzZWNldmVudCtqd3QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImF1ZCI6WyJodHRwczovL3JlY2VpdmVyLmV4YW1wbGUuY29tIl0sImlhdCI6MTc1MDAwMDAwMCwianRpIjoiZ29sZGVuLWp0aS0wMDAwMDAwMDAwMDAwMDAwIiwidG9lIjoxNzUwMDAwMDAwLCJ0eG4iOiJnb2xkZW4tdHhuLTAwMDEiLCJldmVudHMiOnsiaHR0cHM6Ly9zY2hlbWFzLm9wZW5pZC5uZXQvc2VjZXZlbnQvcmlzYy9ldmVudC10eXBlL2FjY291bnQtZGlzYWJsZWQiOnsicmVhc29uIjoiaGlqYWNraW5nIn19LCJraWQiOiJnb2xkZW4ta2lkIn0.33g8kpvIh8uTVPr9KnEVgiw8tTgwzfDbHRnE0Ic3DKDYCq0ju2jglUVK0OyfqdcyISiXofsmw-qefnUm7gVHiM_kKoQEkXn40S6rxm2qhGQzEeQQZN4OETGweDOQN8vvmnAgWhFFRysl8SbFF-aAkS13xs-UQiIWwzjaKYL1pFPu4alHtog_vGeuGDE_gwNyjv49wDOkAr52t3yaBUj6cd9STaI1pa6PdFrz0y9t-cdmKgwWFmltXD0hwfa3k4_xLfkcH8NDs43hfJX3zo-SqlLlKxE-iCOCzTK_8o3EMBxEAlQqDk-XmcIjo7HzcIXKaW1xkJKocgiUcCb5J2JUDA"

// goldenSigner parses the fixed key. It is returned as a crypto.Signer so the
// test exercises the widened parameter rather than the concrete RSA type.
func goldenSigner(t *testing.T) crypto.Signer {
	t.Helper()
	block, _ := pem.Decode([]byte(goldenSigningKeyPEM))
	require.NotNil(t, block, "golden key PEM must decode")
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key
}

// goldenSet builds a SET with every wire-visible field pinned to a constant.
// Nothing here may come from time.Now, a random JTI, or a map with more than
// one entry — all three would make the serialization vary between runs.
func goldenSet() goSet.SecurityEventToken {
	fixed := time.Unix(1750000000, 0).UTC()
	return goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       "golden-jti-0000000000000000",
			Issuer:   "https://issuer.example.com",
			Audience: []string{"https://receiver.example.com"},
			IssuedAt: jwt.NewNumericDate(fixed),
		},
		TimeOfEvent:   jwt.NewNumericDate(fixed),
		TransactionId: "golden-txn-0001",
		Kid:           "golden-kid",
		Events: map[string]interface{}{
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]interface{}{
				"reason": "hijacking",
			},
		},
	}
}

func TestJWS_GoldenBytesAreStable(t *testing.T) {
	set := goldenSet()

	signed, err := set.JWS(jwt.SigningMethodRS256, goldenSigner(t))
	require.NoError(t, err)

	assert.Equal(t, goldenSetJWS, signed,
		"the SET wire bytes changed; a signing-path refactor must not move them")
}

func TestJWS_GoldenBytesAreReproducible(t *testing.T) {
	gs1 := goldenSet()
	first, err := gs1.JWS(jwt.SigningMethodRS256, goldenSigner(t))
	require.NoError(t, err)
	gs2 := goldenSet()
	second, err := gs2.JWS(jwt.SigningMethodRS256, goldenSigner(t))
	require.NoError(t, err)

	// Guards the golden itself: if RS256 signing were ever non-deterministic,
	// TestJWS_GoldenBytesAreStable would be flaky rather than wrong, and the
	// exact-string assertion above would deserve no trust.
	assert.Equal(t, first, second, "RS256 over fixed claims must be deterministic")
}

func TestJWS_RequiresAKey(t *testing.T) {
	set := goldenSet()

	_, err := set.JWS(jwt.SigningMethodRS256, nil)

	require.Error(t, err, "alg=none production was removed in ADR-0066 D3; a nil key must not silently succeed")
}
