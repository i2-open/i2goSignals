package goSetPush

import (
	"crypto/rsa"
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
	// An out-of-tree vendor URI, deliberately not a RISC/CAEP/SCIM one: this
	// fixture means "an event type no built-in validator pack covers", and a
	// standardised URI stops meaning that as soon as a pack adds it.
	validationNoValidatorUri = "https://vendor.example.com/secevent/event-type/no-validator"
)

var validationTestAud = []string{"https://aud.example.com"}

// signValidationSET signs a SET carrying the SSF stream-management envelope
// (top-level opaque sub_id = stream id) plus whatever payload the caller added.
func signValidationSET(t *testing.T, key *rsa.PrivateKey, addPayload func(*goSet.SecurityEventToken)) string {
	t.Helper()
	set := goSet.CreateSet(nil, validationTestIssuer, validationTestAud)
	set.SubjectId = &goSet.SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: goSet.OpaqueIdentifier{Id: validationTestStream},
	}
	addPayload(&set)
	tokenString, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return tokenString
}

func validationReceiverConfig(t *testing.T, key *rsa.PrivateKey, vs *goSetValidate.ValidatorSet) ReceiverConfig {
	t.Helper()
	return ReceiverConfig{
		JWKS:              jwksForKey(t, validationTestIssuer, key),
		ExpectedIssuer:    validationTestIssuer,
		ExpectedAudiences: validationTestAud,
		Validators:        vs,
	}
}

// TestParseReceivedSET_NoValidatorsIsUnchanged pins the additive-only contract:
// with Validators unset the receiver behaves exactly as before and reports the
// ZERO SetResult, which must read as "nothing to report", not as a rejection.
func TestParseReceivedSET_NoValidatorsIsUnchanged(t *testing.T) {
	key := generateTestKey(t)
	// Deliberately a payload that WOULD be malformed if validated: the stream
	// updated event's status claim is outside the SSF §8.1.2 vocabulary.
	token := signValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
	})

	received, deliveryErr := ParseReceivedSET(
		buildPushRequest(t, token, "application/secevent+jwt"),
		validationReceiverConfig(t, key, nil))

	require.Nil(t, deliveryErr)
	require.NotNil(t, received)
	assert.Equal(t, goSetValidate.SetResult{}, received.Validation,
		"an unconfigured receiver must report the zero SetResult")
	assert.Equal(t, goSetValidate.Valid, received.Validation.Disposition)
}

// TestParseReceivedSET_ValidatorsReportNeverReject is the library-side half of the
// policy split: dispositions must reach the caller on ReceivedSET.Validation, and
// no disposition may become a *DeliveryErr inside this package.
func TestParseReceivedSET_ValidatorsReportNeverReject(t *testing.T) {
	key := generateTestKey(t)
	// Engage only the unvalidated vendor URI; the two SSF stream-management URIs are added
	// unconditionally by NewValidatorSet.
	vs := goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), []string{validationNoValidatorUri})

	cases := []struct {
		name            string
		addPayload      func(*goSet.SecurityEventToken)
		wantDisposition goSetValidate.Disposition
		wantURI         string
		wantClaim       string
	}{
		{
			name: "well-formed verification event is valid",
			addPayload: func(s *goSet.SecurityEventToken) {
				s.AddEventPayload(goSetValidate.SsfVerificationEventUri, map[string]any{"state": "abc"})
			},
			wantDisposition: goSetValidate.Valid,
			wantURI:         goSetValidate.SsfVerificationEventUri,
		},
		{
			name: "engaged URI with no registered validator is unsupported",
			addPayload: func(s *goSet.SecurityEventToken) {
				s.AddEventPayload(validationNoValidatorUri, map[string]any{"reason": "test"})
			},
			wantDisposition: goSetValidate.Unsupported,
			wantURI:         validationNoValidatorUri,
		},
		{
			name: "stream updated event with a bad status is malformed",
			addPayload: func(s *goSet.SecurityEventToken) {
				s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
			},
			wantDisposition: goSetValidate.Malformed,
			wantURI:         goSetValidate.SsfStreamUpdatedEventUri,
			wantClaim:       "status",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := signValidationSET(t, key, tc.addPayload)

			received, deliveryErr := ParseReceivedSET(
				buildPushRequest(t, token, "application/secevent+jwt"),
				validationReceiverConfig(t, key, vs))

			require.Nil(t, deliveryErr,
				"goSetPush must never reject on a validation disposition — that is the caller's policy")
			require.NotNil(t, received)
			assert.Equal(t, tc.wantDisposition, received.Validation.Disposition)
			require.Len(t, received.Validation.Results, 1)
			assert.Equal(t, tc.wantURI, received.Validation.Results[0].EventURI)
			assert.Equal(t, tc.wantClaim, received.Validation.Results[0].Claim)
		})
	}
}

// TestParseReceivedSET_ValidationRunsOnlyAfterTrust pins the ordering: a SET that
// fails signature/iss/aud never reaches validation, so a rejected delivery cannot
// be attributed to a payload defect.
func TestParseReceivedSET_ValidationRunsOnlyAfterTrust(t *testing.T) {
	key := generateTestKey(t)
	otherKey := generateTestKey(t)
	vs := goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), nil)

	token := signValidationSET(t, otherKey, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus"})
	})

	received, deliveryErr := ParseReceivedSET(
		buildPushRequest(t, token, "application/secevent+jwt"),
		validationReceiverConfig(t, key, vs))

	assert.Nil(t, received)
	require.NotNil(t, deliveryErr)
	assert.Equal(t, ErrInvalidRequest, deliveryErr.ErrCode)
	assert.NotContains(t, deliveryErr.Description, "status",
		"a signature failure must not be reported as a payload defect")
}

// TestParseReceivedSET_WorstDispositionWins pins the whole-SET reduction the
// caller depends on: ack granularity is the jti, so a multi-URI SET carries one
// decision.
func TestParseReceivedSET_WorstDispositionWins(t *testing.T) {
	key := generateTestKey(t)
	vs := goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), nil)

	token := signValidationSET(t, key, func(s *goSet.SecurityEventToken) {
		s.AddEventPayload(goSetValidate.SsfVerificationEventUri, map[string]any{"state": "abc"})
		s.AddEventPayload(validationNoValidatorUri, map[string]any{"reason": "companion"})
	})

	received, deliveryErr := ParseReceivedSET(
		buildPushRequest(t, token, "application/secevent+jwt"),
		validationReceiverConfig(t, key, vs))

	require.Nil(t, deliveryErr)
	require.NotNil(t, received)
	assert.Equal(t, goSetValidate.Unsupported, received.Validation.Disposition,
		"max(Valid, Unsupported) == Unsupported")
	assert.Len(t, received.Validation.Results, 2, "the caller still sees every per-URI result")
}

// TestReceiverConfigZeroValueCompiles is the source-compatibility guard the seam
// promises: a ReceiverConfig built positionally-free by an out-of-tree consumer
// still compiles and still means "no validation".
func TestReceiverConfigZeroValueCompiles(t *testing.T) {
	var config ReceiverConfig
	assert.Nil(t, config.Validators)
	var received ReceivedSET
	assert.Equal(t, goSetValidate.SetResult{}, received.Validation)
}
