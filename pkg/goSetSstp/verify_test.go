package goSetSstp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

const (
	testIssuer   = "https://issuer.example/"
	testAudience = "https://audience.example/"
)

// signTestSET builds and RS256-signs a SecurityEventToken with the given
// iss/aud and returns the compact token + the JWKS the caller can verify
// against.
func signTestSET(t *testing.T, iss, aud string, key *rsa.PrivateKey) string {
	t.Helper()
	set := goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       "jti-" + iss,
			Issuer:   iss,
			Audience: jwt.ClaimStrings{aud},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Events: map[string]any{"https://example/event/x": map[string]any{}},
		Kid:    "test-kid",
	}
	token, err := set.JWS(jwt.SigningMethodRS256, key)
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	return token
}

func makeTestKeyAndJWKS(t *testing.T, kid string) (*rsa.PrivateKey, *keyfunc.JWKS) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen RSA: %v", err)
	}
	givenKey := keyfunc.NewGivenRSA(&key.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{kid: givenKey})
	return key, jwks
}

// TestVerifySET_HappyPath pins the successful trust-path return: parsed
// SET, correct iss/jti, non-nil Token + non-empty Raw.
func TestVerifySET_HappyPath(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signTestSET(t, testIssuer, testAudience, key)

	got, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
	})
	if err != nil {
		t.Fatalf("VerifySET: %v", err)
	}
	if got.Issuer != testIssuer {
		t.Errorf("Issuer = %q, want %q", got.Issuer, testIssuer)
	}
	if got.JTI != "jti-"+testIssuer {
		t.Errorf("JTI = %q, want jti-%s", got.JTI, testIssuer)
	}
	if got.Token == nil {
		t.Errorf("Token == nil")
	}
	if got.Raw != tok {
		t.Errorf("Raw not preserved")
	}
	if got.Claims["iss"] != testIssuer {
		t.Errorf("Claims[iss] = %v, want %q", got.Claims["iss"], testIssuer)
	}
}

// TestVerifySET_BadSignature pins ErrBadSignature for a token signed with
// a key not in the JWKS.
func TestVerifySET_BadSignature(t *testing.T) {
	_, jwks := makeTestKeyAndJWKS(t, "test-kid")
	rogueKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tok := signTestSET(t, testIssuer, testAudience, rogueKey)
	_, err = goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
	})
	if !errors.Is(err, goSetSstp.ErrBadSignature) {
		t.Errorf("VerifySET rogue-key = %v, want ErrBadSignature", err)
	}
}

// TestVerifySET_WrongAudience pins ErrWrongAudience.
func TestVerifySET_WrongAudience(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signTestSET(t, testIssuer, "https://other-aud.example/", key)
	_, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
	})
	if !errors.Is(err, goSetSstp.ErrWrongAudience) {
		t.Errorf("VerifySET wrong-aud = %v, want ErrWrongAudience", err)
	}
}

// TestVerifySET_IssuerMismatch pins ErrIssuerCertMismatch on the JWKS path
// (ExpectedIssuer set, iss mismatches).
func TestVerifySET_IssuerMismatch(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signTestSET(t, "https://other-issuer.example/", testAudience, key)
	_, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
	})
	if !errors.Is(err, goSetSstp.ErrIssuerCertMismatch) {
		t.Errorf("VerifySET iss-mismatch = %v, want ErrIssuerCertMismatch", err)
	}
}

// TestVerifySET_NilJWKS pins that a nil JWKS is always ErrBadSignature
// (ADR-0066 §D2: no unverified acceptance).
func TestVerifySET_NilJWKS(t *testing.T) {
	key, _ := makeTestKeyAndJWKS(t, "test-kid")
	tok := signTestSET(t, testIssuer, testAudience, key)
	_, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              nil,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
	})
	if !errors.Is(err, goSetSstp.ErrBadSignature) {
		t.Errorf("VerifySET nil-JWKS = %v, want ErrBadSignature", err)
	}
}

// TestVerifySET_AlgAllowlist pins that a signed token whose alg is not in
// the allow-list is rejected as ErrBadSignature — even when the JWKS
// would verify it.
func TestVerifySET_AlgAllowlist(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signTestSET(t, testIssuer, testAudience, key) // RS256

	// Allow only ES256 → RS256 rejected.
	_, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		AllowedAlgs:       []string{"ES256"},
		RequireSignature:  true,
	})
	if !errors.Is(err, goSetSstp.ErrBadSignature) {
		t.Errorf("VerifySET alg-rejected = %v, want ErrBadSignature", err)
	}
}

// TestVerifySET_DefaultAllowsRS256 pins the default AllowedAlgs (RS256 +
// ES256 + EdDSA) accepts community's RS256 business SETs.
func TestVerifySET_DefaultAllowsRS256(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signTestSET(t, testIssuer, testAudience, key)
	_, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
	})
	if err != nil {
		t.Errorf("VerifySET default alg = %v; RS256 must be accepted by default", err)
	}
}

// TestVerifySET_MalformedToken pins that a non-JWS input is ErrBadSignature
// (never a panic).
func TestVerifySET_MalformedToken(t *testing.T) {
	_, err := goSetSstp.VerifySET("not.a.jws", goSetSstp.VerifyConfig{})
	if !errors.Is(err, goSetSstp.ErrBadSignature) {
		t.Errorf("VerifySET malformed = %v, want ErrBadSignature", err)
	}
	_, err = goSetSstp.VerifySET("", goSetSstp.VerifyConfig{})
	if !errors.Is(err, goSetSstp.ErrBadSignature) {
		t.Errorf("VerifySET empty = %v, want ErrBadSignature", err)
	}
}

// TestVerifySET_NoIssuerGate pins that with ExpectedIssuer empty, iss is
// NOT gated (JWKS routing alone). Consumer path for the community
// business acceptor when its iss set is dynamic.
func TestVerifySET_NoIssuerGate(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signTestSET(t, "https://any-issuer.example/", testAudience, key)
	got, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedAudiences: []string{testAudience},
	})
	if err != nil {
		t.Fatalf("VerifySET no-issuer-gate = %v", err)
	}
	if got.Issuer != "https://any-issuer.example/" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
}

// TestVerifySET_NoAudienceGate pins that with ExpectedAudiences empty, aud
// is NOT gated.
func TestVerifySET_NoAudienceGate(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signTestSET(t, testIssuer, "https://whatever.example/", key)
	if _, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:           jwks,
		ExpectedIssuer: testIssuer,
	}); err != nil {
		t.Errorf("VerifySET no-aud-gate = %v", err)
	}
}
