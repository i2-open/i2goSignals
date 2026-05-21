package main

import (
    "testing"

    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestParseSubjectArgEmailFlag verifies the parser infers the `email` format
// from the --email field flag and populates the email member. The format is
// derived from which field flag is set — there is no --format flag.
func TestParseSubjectArgEmailFlag(t *testing.T) {
    sub, err := parseSubjectArg("", subjectArgFlags{Email: "bob@example.com"})
    require.NoError(t, err)
    require.NotNil(t, sub)
    assert.Equal(t, "email", sub.Format)
    assert.Equal(t, "bob@example.com", sub.Email)
}

// TestParseSubjectArgFormatInference verifies the parser infers the correct
// format from each single field flag and populates the matching member.
// account, uri, and scim all populate the SubjectIdentifier.Uri member, so
// --account and --uri are distinct flags that each fix their own format.
func TestParseSubjectArgFormatInference(t *testing.T) {
    cases := []struct {
        name       string
        flags      subjectArgFlags
        wantFormat string
        check      func(t *testing.T, sub *goSet.SubjectIdentifier)
    }{
        {"phone", subjectArgFlags{PhoneNumber: "+15551234"}, "phone_number",
            func(t *testing.T, s *goSet.SubjectIdentifier) { assert.Equal(t, "+15551234", s.PhoneNumber) }},
        {"opaque", subjectArgFlags{Id: "opaque-123"}, "opaque",
            func(t *testing.T, s *goSet.SubjectIdentifier) { assert.Equal(t, "opaque-123", s.Id) }},
        {"did", subjectArgFlags{Url: "did:example:abc"}, "did",
            func(t *testing.T, s *goSet.SubjectIdentifier) { assert.Equal(t, "did:example:abc", s.Url) }},
        {"username", subjectArgFlags{Username: "carol"}, "username",
            func(t *testing.T, s *goSet.SubjectIdentifier) { assert.Equal(t, "carol", s.Username) }},
        {"externalId", subjectArgFlags{ExternalId: "ext-9"}, "externalId",
            func(t *testing.T, s *goSet.SubjectIdentifier) { assert.Equal(t, "ext-9", s.ExternalId) }},
        {"account", subjectArgFlags{Account: "acct:dave@example.com"}, "account",
            func(t *testing.T, s *goSet.SubjectIdentifier) { assert.Equal(t, "acct:dave@example.com", s.Uri) }},
        {"uri", subjectArgFlags{Uri: "https://example.com/u/1"}, "uri",
            func(t *testing.T, s *goSet.SubjectIdentifier) { assert.Equal(t, "https://example.com/u/1", s.Uri) }},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            sub, err := parseSubjectArg("", tc.flags)
            require.NoError(t, err)
            require.NotNil(t, sub)
            assert.Equal(t, tc.wantFormat, sub.Format)
            tc.check(t, sub)
        })
    }
}

// TestParseSubjectArgIssSub verifies --iss together with --sub infers the
// iss_sub format and populates both members.
func TestParseSubjectArgIssSub(t *testing.T) {
    sub, err := parseSubjectArg("", subjectArgFlags{Iss: "https://idp.example", Sub: "user-7"})
    require.NoError(t, err)
    require.NotNil(t, sub)
    assert.Equal(t, "iss_sub", sub.Format)
    assert.Equal(t, "https://idp.example", sub.Issuer)
    assert.Equal(t, "user-7", sub.Sub)
}

// TestParseSubjectArgIssWithoutSub verifies the iss_sub format requires both
// halves: --iss without --sub is rejected with a clear error rather than
// producing a half-formed subject.
func TestParseSubjectArgIssWithoutSub(t *testing.T) {
    _, err := parseSubjectArg("", subjectArgFlags{Iss: "https://idp.example"})
    require.Error(t, err, "--iss without --sub must be rejected")
    assert.Contains(t, err.Error(), "--sub")
}

// TestParseSubjectArgSubWithoutIss verifies the symmetric case: --sub without
// --iss is also rejected — iss_sub is a two-member format.
func TestParseSubjectArgSubWithoutIss(t *testing.T) {
    _, err := parseSubjectArg("", subjectArgFlags{Sub: "user-7"})
    require.Error(t, err, "--sub without --iss must be rejected")
    assert.Contains(t, err.Error(), "--iss")
}

// TestParseSubjectArgMultipleFormats verifies the parser rejects field flags
// drawn from more than one format — a subject has exactly one format.
func TestParseSubjectArgMultipleFormats(t *testing.T) {
    _, err := parseSubjectArg("", subjectArgFlags{Email: "a@example.com", Username: "carol"})
    require.Error(t, err, "field flags from two formats must be rejected")
    assert.Contains(t, err.Error(), "one format")
}

// TestParseSubjectArgJSONAndFlags verifies positional JSON combined with field
// flags is rejected — the two input modes are mutually exclusive.
func TestParseSubjectArgJSONAndFlags(t *testing.T) {
    _, err := parseSubjectArg(`{"format":"email","email":"a@example.com"}`,
        subjectArgFlags{Username: "carol"})
    require.Error(t, err, "positional JSON plus a field flag must be rejected")
    assert.Contains(t, err.Error(), "mutually exclusive")
}

// TestParseSubjectArgEmpty verifies no JSON and no field flags yields a nil
// subject with no error — callers (e.g. `get subject-filter status` with no
// subject) treat this as "no point lookup requested".
func TestParseSubjectArgEmpty(t *testing.T) {
    sub, err := parseSubjectArg("", subjectArgFlags{})
    require.NoError(t, err)
    assert.Nil(t, sub, "no input must yield a nil subject, not an empty one")
}

// TestParseSubjectArgJSON verifies the pure subject-argument parser accepts a
// positional JSON literal and unmarshals it into a goSet.SubjectIdentifier.
// Complex subjects, the aliases array, and the scim format are positional-JSON
// only by design (PRD #106) — the JSON path is the general escape hatch.
func TestParseSubjectArgJSON(t *testing.T) {
    sub, err := parseSubjectArg(`{"format":"email","email":"alice@example.com"}`, subjectArgFlags{})
    require.NoError(t, err, "a JSON literal must parse")
    require.NotNil(t, sub)
    assert.Equal(t, "email", sub.Format)
    assert.Equal(t, "alice@example.com", sub.Email)
}
