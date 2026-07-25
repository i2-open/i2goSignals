package goSetSstp_test

import (
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
)

// An out-of-tree vendor URI, deliberately not a RISC/CAEP/SCIM one: this
// fixture means "an event type no built-in validator pack covers", and a
// standardised URI stops meaning that as soon as a pack adds it.
const sstpNoValidatorUri = "https://vendor.example.com/secevent/event-type/no-validator"

// VerifySET's signature is FROZEN by the #247 slice contract: the event
// validation hook is an added VerifyConfig field, never a new parameter. This
// compile-time assertion fails the build if the signature ever moves, which is
// what makes the additive-only promise to the out-of-tree consumers
// (enterprise, admin) a checked fact rather than a review note.
var _ func(string, goSetSstp.VerifyConfig) (goSetSstp.VerifiedSET, error) = goSetSstp.VerifySET

// signSstpValidationSET signs a SET carrying the SSF stream-management envelope
// (top-level opaque sub_id) plus whatever payload the caller adds.
func signSstpValidationSET(t *testing.T, key *rsa.PrivateKey, addPayload func(*goSet.SecurityEventToken)) string {
	t.Helper()
	set := goSet.CreateSet(nil, testIssuer, []string{testAudience})
	set.Kid = "test-kid"
	set.SubjectId = &goSet.SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: goSet.OpaqueIdentifier{Id: "sstp-pair-under-validation"},
	}
	addPayload(&set)
	token, err := set.JWS(jwt.SigningMethodRS256, key)
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	return token
}

// TestVerifySET_NoValidatorsIsUnchanged pins the additive-only contract: with
// Validators unset (every pre-#247 caller, including every out-of-tree one)
// VerifySET behaves exactly as before and reports the ZERO SetResult, which
// must read as "nothing to report" rather than as a rejection.
func TestVerifySET_NoValidatorsIsUnchanged(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	// Deliberately a payload that WOULD be malformed if validated: the stream
	// updated event's status claim is outside the SSF §8.1.2 vocabulary.
	tok := signSstpValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
	})

	got, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
	})
	if err != nil {
		t.Fatalf("VerifySET: %v", err)
	}
	if got.Validation.Disposition != goSetValidate.Valid {
		t.Errorf("Validation.Disposition = %v, want Valid (zero) with no Validators", got.Validation.Disposition)
	}
	if got.Validation.Results != nil {
		t.Errorf("Validation.Results = %v, want nil with no Validators", got.Validation.Results)
	}
}

// TestVerifySET_ReportsMalformedNeverRejects proves the library computes and
// reports but never rejects: a malformed payload comes back on the accepted
// VerifiedSET with a Malformed disposition and a nil error. Turning that into
// an SSTP §2.3 setErr is the server's job (#247 mode policy).
func TestVerifySET_ReportsMalformedNeverRejects(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signSstpValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
	})

	got, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
		Validators:        goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), nil),
	})
	if err != nil {
		t.Fatalf("VerifySET must not reject on a validation disposition: %v", err)
	}
	if got.Token == nil {
		t.Fatal("VerifiedSET.Token must still be populated")
	}
	if got.Validation.Disposition != goSetValidate.Malformed {
		t.Fatalf("Validation.Disposition = %v, want Malformed", got.Validation.Disposition)
	}
	if len(got.Validation.Results) != 1 {
		t.Fatalf("Validation.Results = %v, want exactly one entry", got.Validation.Results)
	}
	r := got.Validation.Results[0]
	if r.EventURI != goSetValidate.SsfStreamUpdatedEventUri {
		t.Errorf("Result.EventURI = %q, want %q", r.EventURI, goSetValidate.SsfStreamUpdatedEventUri)
	}
	if r.Claim == "" {
		t.Error("Result.Claim must name the failing claim so the setErr can quote it")
	}
}

// TestVerifySET_UnsupportedWhenNotEngaged pins the out-of-contract disposition
// the SSTP acceptor's STRICT posture rejects on: a URI no engaged validator
// vouches for reports Unsupported, not Malformed.
func TestVerifySET_UnsupportedWhenNotEngaged(t *testing.T) {
	key, jwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signSstpValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(sstpNoValidatorUri, map[string]any{"anything": "goes"})
	})

	got, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
		Validators:        goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), nil),
	})
	if err != nil {
		t.Fatalf("VerifySET: %v", err)
	}
	if got.Validation.Disposition != goSetValidate.Unsupported {
		t.Errorf("Validation.Disposition = %v, want Unsupported", got.Validation.Disposition)
	}
}

// TestVerifySET_TrustFailureIsNeverAPayloadDefect pins the ordering: validation
// runs only after alg/iss/aud/signature are settled, so a forged SET fails as a
// trust error and never surfaces as a validation disposition.
func TestVerifySET_TrustFailureIsNeverAPayloadDefect(t *testing.T) {
	key, _ := makeTestKeyAndJWKS(t, "test-kid")
	_, otherJwks := makeTestKeyAndJWKS(t, "test-kid")
	tok := signSstpValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
	})

	got, err := goSetSstp.VerifySET(tok, goSetSstp.VerifyConfig{
		JWKS:              otherJwks, // signed by a different key
		ExpectedIssuer:    testIssuer,
		ExpectedAudiences: []string{testAudience},
		RequireSignature:  true,
		Validators:        goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), nil),
	})
	if err == nil {
		t.Fatal("expected a signature failure")
	}
	if got.Validation.Disposition != goSetValidate.Valid || got.Validation.Results != nil {
		t.Errorf("a rejected SET must carry no validation result, got %+v", got.Validation)
	}
}
