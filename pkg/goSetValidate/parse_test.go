package goSetValidate

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signSet produces a signed SET wire string plus the JWKS a verifier needs to
// accept it. RS256 matches the production posture used elsewhere in pkg/goSet.
func signSet(t *testing.T, set *goSet.SecurityEventToken) (string, *keyfunc.JWKS) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	set.Kid = "kid-goSetValidate-test"
	signed, err := set.JWS(jwt.SigningMethodRS256, priv)
	require.NoError(t, err)

	pub := priv.PublicKey
	given := keyfunc.NewGivenRSA(&pub, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	return signed, keyfunc.NewGiven(map[string]keyfunc.GivenKey{set.Kid: given})
}

// TestParseAndValidate_NilValidatorSetDegradesToPlainParse is the story-17
// contract: a nil validator set returns exactly what a plain verified parse
// returns, plus a zero SetResult.
func TestParseAndValidate_NilValidatorSetDegradesToPlainParse(t *testing.T) {
	original := events.CreateVerifyEvent(testStreamId, "opaque-state", "https://transmitter.example.com", []string{"receiver.example.com"})
	signed, jwks := signSet(t, original)

	want, wantErr := goSet.Parse(signed, jwks)
	require.NoError(t, wantErr)

	got, result, err := ParseAndValidate(signed, jwks, nil)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, want.Issuer, got.Issuer)
	assert.Equal(t, want.Events, got.Events)
	assert.Equal(t, SetResult{}, result, "a nil validator set must produce a zero SetResult")
}

// TestParseAndValidate_NilJwksMatchesParseError pins identical error behaviour on
// the ADR-0066 §D3 verify-only path.
func TestParseAndValidate_NilJwksMatchesParseError(t *testing.T) {
	original := events.CreateVerifyEvent(testStreamId, "s", "https://transmitter.example.com", []string{"receiver.example.com"})
	signed, _ := signSet(t, original)

	_, wantErr := goSet.Parse(signed, nil)
	require.Error(t, wantErr)

	for name, vs := range map[string]*ValidatorSet{
		"nil validator set":     nil,
		"non-nil validator set": NewValidatorSet(BuiltinRegistry(), nil),
	} {
		t.Run(name, func(t *testing.T) {
			set, result, err := ParseAndValidate(signed, nil, vs)
			require.Error(t, err)
			assert.Equal(t, wantErr.Error(), err.Error())
			assert.Nil(t, set)
			assert.Equal(t, SetResult{}, result, "a failed parse must not report a disposition")
		})
	}
}

// TestParseAndValidate_MalformedTokenMatchesParseError: validation never masks or
// alters a signature/parse failure.
func TestParseAndValidate_MalformedTokenMatchesParseError(t *testing.T) {
	original := events.CreateVerifyEvent(testStreamId, "s", "https://transmitter.example.com", []string{"receiver.example.com"})
	_, jwks := signSet(t, original)

	const garbage = "not.a.jwt"
	_, wantErr := goSet.Parse(garbage, jwks)
	require.Error(t, wantErr)

	set, result, err := ParseAndValidate(garbage, jwks, NewValidatorSet(BuiltinRegistry(), nil))
	require.Error(t, err)
	assert.Equal(t, wantErr.Error(), err.Error())
	assert.Nil(t, set)
	assert.Equal(t, SetResult{}, result)
}

// TestParseAndValidate_ComposesVerifyThenValidate: signature verification first,
// then payload validation — and a validation failure is reported, never returned
// as an error (the libraries compute dispositions and never reject).
func TestParseAndValidate_ComposesVerifyThenValidate(t *testing.T) {
	t.Run("valid payload", func(t *testing.T) {
		original := events.CreateVerifyEvent(testStreamId, "opaque-state", "https://transmitter.example.com", []string{"receiver.example.com"})
		signed, jwks := signSet(t, original)

		set, result, err := ParseAndValidate(signed, jwks, NewValidatorSet(BuiltinRegistry(), []string{SsfVerificationEventUri}))
		require.NoError(t, err)
		require.NotNil(t, set)
		assert.Equal(t, Valid, result.Disposition)
		require.Len(t, result.Results, 1)
		assert.Equal(t, SsfVerificationEventUri, result.Results[0].EventURI)
	})

	t.Run("malformed payload is reported, not errored", func(t *testing.T) {
		bad := setWithStreamSubject(testStreamId)
		bad.AddEventPayload(SsfStreamUpdatedEventUri, map[string]any{"status": "quiesced"})
		signed, jwks := signSet(t, bad)

		set, result, err := ParseAndValidate(signed, jwks, NewValidatorSet(BuiltinRegistry(), nil))
		require.NoError(t, err, "goSetValidate never rejects; the server decides policy")
		require.NotNil(t, set)
		assert.Equal(t, Malformed, result.Disposition)
		require.Len(t, result.Results, 1)
		assert.Equal(t, "status", result.Results[0].Claim)
	})

	t.Run("unsupported payload is reported, not errored", func(t *testing.T) {
		other := setWithStreamSubject(testStreamId)
		other.AddEventPayload(fakeVocabularyUri, map[string]any{"x": 1})
		signed, jwks := signSet(t, other)

		set, result, err := ParseAndValidate(signed, jwks, NewValidatorSet(BuiltinRegistry(), nil))
		require.NoError(t, err)
		require.NotNil(t, set)
		assert.Equal(t, Unsupported, result.Disposition)
	})
}
