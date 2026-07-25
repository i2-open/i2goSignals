package goSetPoll

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	validationTestIssuer = "https://issuer.example.com"
	validationTestStream = "stream-under-validation"
	validationRiscUri    = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
)

var validationTestAud = []string{"https://aud.example.com"}

// signValidationSET signs a SET carrying the SSF stream-management envelope
// (top-level opaque sub_id = stream id) and returns (jti, token).
func signValidationSET(t *testing.T, key *rsa.PrivateKey, addPayload func(*goSet.SecurityEventToken)) (string, string) {
	t.Helper()
	set := goSet.CreateSet(nil, validationTestIssuer, validationTestAud)
	set.SubjectId = &goSet.SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: goSet.OpaqueIdentifier{Id: validationTestStream},
	}
	addPayload(&set)
	tokenString, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return set.ID, tokenString
}

// validationPollServer serves one poll response carrying the supplied SETs.
func validationPollServer(t *testing.T, sets map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PollResponse{Sets: sets})
	}))
}

func validationPollConfig(t *testing.T, url string, key *rsa.PrivateKey, vs *goSetValidate.ValidatorSet) ReceiverConfig {
	t.Helper()
	return ReceiverConfig{
		EndpointURL:       url,
		JWKS:              jwksForKey(t, validationTestIssuer, key),
		ExpectedIssuer:    validationTestIssuer,
		ExpectedAudiences: validationTestAud,
		Validators:        vs,
	}
}

// TestPoll_NoValidatorsIsUnchanged pins the additive-only contract: with
// Validators unset, Validations stays nil (the documented zero) and a payload
// that WOULD be malformed is parsed and delivered exactly as before.
func TestPoll_NoValidatorsIsUnchanged(t *testing.T) {
	key := generateTestKey(t)
	jti, token := signValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
	})

	server := validationPollServer(t, map[string]string{jti: token})
	defer server.Close()

	parsed, status, err := Poll(context.Background(), PollRequest{ReturnImmediately: true},
		validationPollConfig(t, server.URL, key, nil))

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, parsed)
	assert.Nil(t, parsed.Validations, "an unconfigured receiver reports a nil Validations map")
	assert.Contains(t, parsed.ParsedSETs, jti)
	assert.Empty(t, parsed.Errors)
}

// TestPoll_ValidatorsReportNeverNack is the library-side half of the policy
// split: dispositions reach the caller keyed by jti, and NO disposition moves a
// jti into Errors inside this package — the ack/setErrs decision is the caller's.
func TestPoll_ValidatorsReportNeverNack(t *testing.T) {
	key := generateTestKey(t)
	vs := goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), []string{validationRiscUri})

	validJti, validToken := signValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfVerificationEventUri, map[string]any{"state": "abc"})
	})
	unsupportedJti, unsupportedToken := signValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(validationRiscUri, map[string]any{"reason": "test"})
	})
	malformedJti, malformedToken := signValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
	})

	server := validationPollServer(t, map[string]string{
		validJti:       validToken,
		unsupportedJti: unsupportedToken,
		malformedJti:   malformedToken,
	})
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true},
		validationPollConfig(t, server.URL, key, vs))

	require.NoError(t, err)
	require.NotNil(t, parsed)
	assert.Empty(t, parsed.Errors,
		"goSetPoll must never nack on a validation disposition — that is the caller's policy")
	assert.Len(t, parsed.ParsedSETs, 3, "every jti still reaches the caller whatever its disposition")

	require.Len(t, parsed.Validations, 3)
	assert.Equal(t, goSetValidate.Valid, parsed.Validations[validJti].Disposition)
	assert.Equal(t, goSetValidate.Unsupported, parsed.Validations[unsupportedJti].Disposition)

	malformed := parsed.Validations[malformedJti]
	assert.Equal(t, goSetValidate.Malformed, malformed.Disposition)
	require.Len(t, malformed.Results, 1)
	assert.Equal(t, goSetValidate.SsfStreamUpdatedEventUri, malformed.Results[0].EventURI)
	assert.Equal(t, "status", malformed.Results[0].Claim)
	assert.NotEmpty(t, malformed.Results[0].Detail)
}

// TestPoll_ValidationRunsOnlyAfterTrust pins the ordering: a jti that fails
// signature/iss/aud lands in Errors and gets NO Validations entry, so a nack can
// never be misattributed to a payload defect.
func TestPoll_ValidationRunsOnlyAfterTrust(t *testing.T) {
	key := generateTestKey(t)
	otherKey := generateTestKey(t)
	vs := goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), nil)

	badJti, badToken := signValidationSET(t, otherKey, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
	})
	goodJti, goodToken := signValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfVerificationEventUri, map[string]any{"state": "abc"})
	})

	server := validationPollServer(t, map[string]string{badJti: badToken, goodJti: goodToken})
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true},
		validationPollConfig(t, server.URL, key, vs))

	require.NoError(t, err)
	require.NotNil(t, parsed)
	assert.Contains(t, parsed.Errors, badJti)
	assert.NotContains(t, parsed.Validations, badJti,
		"an untrusted SET is never validated, so it carries no disposition")
	assert.Equal(t, goSetValidate.Valid, parsed.Validations[goodJti].Disposition)
}

// TestPoll_WorstDispositionWins pins the whole-SET reduction within one jti: ack
// granularity is the jti, so a multi-URI SET carries exactly one decision.
func TestPoll_WorstDispositionWins(t *testing.T) {
	key := generateTestKey(t)
	vs := goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), nil)

	jti, token := signValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfVerificationEventUri, map[string]any{"state": "abc"})
		s.AddEventPayload(validationRiscUri, map[string]any{"reason": "companion"})
	})

	server := validationPollServer(t, map[string]string{jti: token})
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true},
		validationPollConfig(t, server.URL, key, vs))

	require.NoError(t, err)
	require.NotNil(t, parsed)
	assert.Equal(t, goSetValidate.Unsupported, parsed.Validations[jti].Disposition,
		"max(Valid, Unsupported) == Unsupported")
	assert.Len(t, parsed.Validations[jti].Results, 2, "the caller still sees every per-URI result")
}

// TestReceiverConfigZeroValueCompiles is the source-compatibility guard the seam
// promises: the added fields have nil-safe zero values meaning "no validation".
func TestReceiverConfigZeroValueCompiles(t *testing.T) {
	var config ReceiverConfig
	assert.Nil(t, config.Validators)
	var parsed ParsedPollResponse
	assert.Nil(t, parsed.Validations)
}
