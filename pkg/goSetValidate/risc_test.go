package goSetValidate

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
)

// riscAccountSet is the well-formed envelope the account-scoped RISC tables
// reuse: a top-level iss_sub sub_id, the subject type RISC names for the account
// events.
func riscAccountSet() *goSet.SecurityEventToken {
	return setWithSubject(&goSet.SubjectIdentifier{
		Format:                  "iss_sub",
		IssuerSubjectIdentifier: goSet.IssuerSubjectIdentifier{Issuer: "https://idp.example.com", Sub: "user-42"},
	})
}

func riscEmailSubject(email string) *goSet.SubjectIdentifier {
	return &goSet.SubjectIdentifier{
		Format:          "email",
		EmailIdentifier: goSet.EmailIdentifier{Email: email},
	}
}

func riscPhoneSubject(phone string) *goSet.SubjectIdentifier {
	return &goSet.SubjectIdentifier{
		Format:                "phone_number",
		PhoneNumberIdentifier: goSet.PhoneNumberIdentifier{PhoneNumber: phone},
	}
}

// runRiscCases runs the shared validator table and additionally asserts the AC
// that a Malformed Detail names the claim that failed — a receiver operator
// reads the Detail, not the Claim field, out of a log line.
func runRiscCases(t *testing.T, eventURI string, validate ValidatorFunc, cases []validatorCase) {
	t.Helper()
	runValidatorCases(t, eventURI, validate, cases)

	for _, tc := range cases {
		if tc.want != Malformed {
			continue
		}
		got := validate.Validate(eventURI, tc.payload, tc.set)
		assert.Contains(t, got.Detail, tc.wantClaim,
			"%s: Detail must name the failing claim %q (%s)", tc.name, tc.wantClaim, tc.citation)
	}
}

// TestBuiltinRegistry_CarriesRiscValidatorPack asserts every RISC event type the
// repo advertises has a validator, and that adding the pack did not displace the
// packs already registered.
func TestBuiltinRegistry_CarriesRiscValidatorPack(t *testing.T) {
	r := BuiltinRegistry()

	for _, uri := range []string{
		riscAccountEnabledEventUri,
		riscAccountDisabledEventUri,
		riscAccountPurgedEventUri,
		riscAccountCredentialChangeRequiredEventUri,
		riscRecoveryActivatedEventUri,
		riscRecoveryInformationChangedEventUri,
		riscSessionsRevokedEventUri,
		riscIdentifierChangedEventUri,
		riscIdentifierRecycledEventUri,
	} {
		v, ok := r.Lookup(uri)
		assert.True(t, ok, "the built-in registry must carry a validator for %s", uri)
		assert.NotNil(t, v)
	}

	_, ok := r.Lookup(SsfVerificationEventUri)
	assert.True(t, ok, "the RISC pack must not displace the SSF verification validator")
	_, ok = r.Lookup(SsfStreamUpdatedEventUri)
	assert.True(t, ok, "the RISC pack must not displace the SSF stream-updated validator")
	_, ok = r.Lookup(caepSessionRevokedEventUri)
	assert.True(t, ok, "the RISC pack must not displace the CAEP pack")
}

// riscSubjectOnlyCases is the shared table for the RISC events that define no
// claims of their own: everything they assert is about the subject. cite is the
// event's own section, quoted so a failure points at the right rule.
func riscSubjectOnlyCases(cite string) []validatorCase {
	return []validatorCase{
		{
			name:        "well-formed with iss_sub sub_id",
			citation:    cite,
			set:         riscAccountSet(),
			payload:     map[string]any{},
			want:        Valid,
			description: "the event defines no payload claims; the subject identifies the account",
		},
		{
			name:        "well-formed with an in-payload RISC subject",
			citation:    cite + ", RFC 8417 §2.2",
			set:         setWithSubject(nil),
			payload:     map[string]any{"subject": map[string]any{"format": "email", "email": "user@example.com"}},
			want:        Valid,
			description: "RISC predates SSF and its own examples carry the subject inside the payload",
		},
		{
			name:        "well-formed with an opaque account subject",
			citation:    cite,
			set:         setWithSubject(opaqueSubject("acct-9f8e7d")),
			payload:     map[string]any{},
			want:        Valid,
			description: "RISC names a typical subject type per event but does not make it normative",
		},
		{
			name:        "unknown extra claims are allowed",
			citation:    cite + " (forward compatibility)",
			set:         riscAccountSet(),
			payload:     map[string]any{"vendor_extension": map[string]any{"risk": 0.9}, "future_claim": "x"},
			want:        Valid,
			description: "a validator must tolerate claims it does not know",
		},
		{
			name:        "missing subject",
			citation:    cite,
			set:         setWithSubject(nil),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the event is defined in terms of its subject, so a SET naming none is unactionable",
		},
		{
			name:        "sub_id with an unrecognised format",
			citation:    cite + ", RFC 9493",
			set:         setWithSubject(&goSet.SubjectIdentifier{Format: "not-a-format"}),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "a subject the router cannot canonicalise could never be matched to a stream filter",
		},
		{
			name:        "in-payload subject of the wrong JSON type",
			citation:    cite + ", RFC 8417 §2.2",
			set:         riscAccountSet(),
			payload:     map[string]any{"subject": "user@example.com"},
			want:        Malformed,
			wantClaim:   "subject",
			description: "a subject identifier is a JSON object, not a bare string",
		},
		{
			name:        "in-payload subject missing its required value",
			citation:    cite + ", RFC 9493",
			set:         setWithSubject(nil),
			payload:     map[string]any{"subject": map[string]any{"format": "email"}},
			want:        Malformed,
			wantClaim:   "subject",
			description: "an email-format subject with no email value is structurally incomplete",
		},
	}
}

// TestValidateRiscAccountEnabled covers RISC §2.4 (Account Enabled), which
// defines no claims of its own.
func TestValidateRiscAccountEnabled(t *testing.T) {
	runRiscCases(t, riscAccountEnabledEventUri, validateRiscAccountEnabled,
		riscSubjectOnlyCases("RISC §2.4"))
}

// TestValidateRiscAccountPurged covers RISC §2.2 (Account Purged), which defines
// no claims of its own.
func TestValidateRiscAccountPurged(t *testing.T) {
	runRiscCases(t, riscAccountPurgedEventUri, validateRiscAccountPurged,
		riscSubjectOnlyCases("RISC §2.2"))
}

// TestValidateRiscAccountCredentialChangeRequired covers RISC §2.1 (Account
// Credential Change Required), which defines no claims of its own.
func TestValidateRiscAccountCredentialChangeRequired(t *testing.T) {
	runRiscCases(t, riscAccountCredentialChangeRequiredEventUri, validateRiscAccountCredentialChangeRequired,
		riscSubjectOnlyCases("RISC §2.1"))
}

// TestValidateRiscRecoveryActivated covers RISC §2.8 (Recovery Activated), which
// defines no claims of its own.
func TestValidateRiscRecoveryActivated(t *testing.T) {
	runRiscCases(t, riscRecoveryActivatedEventUri, validateRiscRecoveryActivated,
		riscSubjectOnlyCases("RISC §2.8"))
}

// TestValidateRiscRecoveryInformationChanged covers RISC §2.9 (Recovery
// Information Changed), which defines no claims of its own.
func TestValidateRiscRecoveryInformationChanged(t *testing.T) {
	runRiscCases(t, riscRecoveryInformationChangedEventUri, validateRiscRecoveryInformationChanged,
		riscSubjectOnlyCases("RISC §2.9"))
}

// TestValidateRiscSessionsRevoked covers RISC §2.10 (Sessions Revoked), which
// defines no claims of its own: the revoked sessions are identified collectively
// by the subject.
func TestValidateRiscSessionsRevoked(t *testing.T) {
	runRiscCases(t, riscSessionsRevokedEventUri, validateRiscSessionsRevoked,
		riscSubjectOnlyCases("RISC §2.10"))
}

// TestValidateRiscAccountDisabled covers RISC §2.3 (Account Disabled) and its one
// OPTIONAL claim, "reason".
func TestValidateRiscAccountDisabled(t *testing.T) {
	cases := append(riscSubjectOnlyCases("RISC §2.3"), []validatorCase{
		{
			name:        "reason hijacking",
			citation:    "RISC §2.3 (reason: OPTIONAL. Possible values: hijacking, bulk-account)",
			set:         riscAccountSet(),
			payload:     map[string]any{"reason": "hijacking"},
			want:        Valid,
			description: "one of the two values the spec lists",
		},
		{
			name:        "reason bulk-account",
			citation:    "RISC §2.3",
			set:         riscAccountSet(),
			payload:     map[string]any{"reason": "bulk-account"},
			want:        Valid,
			description: "the other value the spec lists",
		},
		{
			name:        "reason outside the listed values",
			citation:    "RISC §2.3",
			set:         riscAccountSet(),
			payload:     map[string]any{"reason": "suspicious-activity"},
			want:        Valid,
			description: "the spec lists possible values without closing the vocabulary, so membership is not checked",
		},
		{
			name:        "reason absent",
			citation:    "RISC §2.3 (reason: OPTIONAL)",
			set:         riscAccountSet(),
			payload:     map[string]any{},
			want:        Valid,
			description: "an OPTIONAL claim must never fail a validator when absent",
		},
		{
			name:        "reason of the wrong JSON type",
			citation:    "RISC §2.3",
			set:         riscAccountSet(),
			payload:     map[string]any{"reason": map[string]any{"en": "hijacking"}},
			want:        Malformed,
			wantClaim:   "reason",
			description: "reason is a string, not a language map — that is a CAEP shape, not a RISC one",
		},
		{
			name:        "reason present but empty",
			citation:    "RISC §2.3",
			set:         riscAccountSet(),
			payload:     map[string]any{"reason": "   "},
			want:        Malformed,
			wantClaim:   "reason",
			description: "a present reason exists to carry a value; blank is indistinguishable from a bug",
		},
	}...)

	runRiscCases(t, riscAccountDisabledEventUri, validateRiscAccountDisabled, cases)
}

// riscIdentifierSubjectCases is the shared table for the §2.5/§2.6 rule "The
// subject type MUST be either email or phone" — the constraint that separates the
// two identifier events from the rest of the pack.
func riscIdentifierSubjectCases(cite string) []validatorCase {
	return []validatorCase{
		{
			name:        "email subject",
			citation:    cite + " (subject type MUST be either email or phone)",
			set:         setWithSubject(riscEmailSubject("old@example.com")),
			payload:     map[string]any{},
			want:        Valid,
			description: "email is one of the two allowable subject types",
		},
		{
			name:        "phone_number subject",
			citation:    cite,
			set:         setWithSubject(riscPhoneSubject("+1-604-555-0142")),
			payload:     map[string]any{},
			want:        Valid,
			description: "phone_number is RFC 9493's spelling of the other allowable type",
		},
		{
			name:        "in-payload email subject",
			citation:    cite + ", RFC 8417 §2.2",
			set:         setWithSubject(nil),
			payload:     map[string]any{"subject": map[string]any{"format": "email", "email": "old@example.com"}},
			want:        Valid,
			description: "RISC's own examples carry the subject inside the payload",
		},
		{
			name:        "unknown extra claims are allowed",
			citation:    cite + " (forward compatibility)",
			set:         setWithSubject(riscEmailSubject("old@example.com")),
			payload:     map[string]any{"vendor_extension": "x"},
			want:        Valid,
			description: "a validator must tolerate claims it does not know",
		},
		{
			name:        "missing subject",
			citation:    cite,
			set:         setWithSubject(nil),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the event is about the identifier its subject names",
		},
		{
			name:        "iss_sub subject",
			citation:    cite + " (subject type MUST be either email or phone)",
			set:         riscAccountSet(),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "an account subject cannot say which identifier changed or was recycled",
		},
		{
			name:        "opaque subject",
			citation:    cite,
			set:         setWithSubject(opaqueSubject("acct-9f8e7d")),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "opaque is outside the two allowable subject types",
		},
		{
			name:        "legacy \"phone\" subject type",
			citation:    cite + ", RFC 9493",
			set:         setWithSubject(&goSet.SubjectIdentifier{Format: "phone", PhoneNumberIdentifier: goSet.PhoneNumberIdentifier{PhoneNumber: "+1-604-555-0142"}}),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "RISC 1.0's \"phone\" spelling is not an RFC 9493 format and cannot be canonicalised",
		},
		{
			name:        "subject declaring no type",
			citation:    cite,
			set:         setWithSubject(&goSet.SubjectIdentifier{EmailIdentifier: goSet.EmailIdentifier{Email: "old@example.com"}}),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the subject type is what the MUST is about, so an untyped subject fails it",
		},
		{
			name:        "email subject missing the old value",
			citation:    cite + " (it MUST specify the old value)",
			set:         setWithSubject(riscEmailSubject("")),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "an email subject carrying no address does not specify the old value",
		},
		{
			name:        "phone_number subject missing the old value",
			citation:    cite + " (it MUST specify the old value)",
			set:         setWithSubject(riscPhoneSubject("")),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "a phone subject carrying no number does not specify the old value",
		},
		{
			name:        "in-payload subject of the wrong JSON type",
			citation:    cite + ", RFC 8417 §2.2",
			set:         setWithSubject(riscEmailSubject("old@example.com")),
			payload:     map[string]any{"subject": []any{"old@example.com"}},
			want:        Malformed,
			wantClaim:   "subject",
			description: "a subject identifier is a JSON object, not an array",
		},
	}
}

// TestValidateRiscIdentifierChanged covers RISC §2.5 (Identifier Changed): the
// subject-type MUST, the "MUST specify the old value" rule, and the OPTIONAL
// new-value claim. This is the event the spec's motivating example uses, so
// new-value gets coverage of its own rather than a subject-only check.
func TestValidateRiscIdentifierChanged(t *testing.T) {
	cases := append(riscIdentifierSubjectCases("RISC §2.5"), []validatorCase{
		{
			name:        "the canonical §2.5 shape",
			citation:    "RISC §2.5 (new-value: optional, the new value of the identifier)",
			set:         setWithSubject(riscEmailSubject("old@example.com")),
			payload:     map[string]any{"new-value": "new@example.com"},
			want:        Valid,
			description: "an email identifier changing to another address",
		},
		{
			name:        "phone identifier changing",
			citation:    "RISC §2.5",
			set:         setWithSubject(riscPhoneSubject("+1-604-555-0142")),
			payload:     map[string]any{"new-value": "+1-604-555-0199"},
			want:        Valid,
			description: "a phone identifier changing to another number",
		},
		{
			name:        "new-value absent",
			citation:    "RISC §2.5 (new-value: optional)",
			set:         setWithSubject(riscEmailSubject("old@example.com")),
			payload:     map[string]any{},
			want:        Valid,
			description: "an OPTIONAL claim must never fail a validator when absent",
		},
		{
			name:     "new-value on an in-payload subject",
			citation: "RISC §2.5, RFC 8417 §2.2",
			set:      setWithSubject(nil),
			payload: map[string]any{
				"subject":   map[string]any{"format": "email", "email": "old@example.com"},
				"new-value": "new@example.com",
			},
			want:        Valid,
			description: "the new-value rule keys off the subject type wherever the subject is carried",
		},
		{
			name:        "new-value of the wrong JSON type",
			citation:    "RISC §2.5",
			set:         setWithSubject(riscEmailSubject("old@example.com")),
			payload:     map[string]any{"new-value": map[string]any{"email": "new@example.com"}},
			want:        Malformed,
			wantClaim:   "new-value",
			description: "new-value is the identifier's new value as a string, not a nested object",
		},
		{
			name:        "new-value as a number",
			citation:    "RISC §2.5",
			set:         setWithSubject(riscPhoneSubject("+1-604-555-0142")),
			payload:     map[string]any{"new-value": float64(16045550199)},
			want:        Malformed,
			wantClaim:   "new-value",
			description: "even a phone number is carried as a JSON string",
		},
		{
			name:        "new-value present but empty",
			citation:    "RISC §2.5",
			set:         setWithSubject(riscEmailSubject("old@example.com")),
			payload:     map[string]any{"new-value": ""},
			want:        Malformed,
			wantClaim:   "new-value",
			description: "an empty new-value conveys nothing; omitting the claim is the way to not disclose it",
		},
		{
			name:        "new-value is not an address for an email subject",
			citation:    "RISC §2.5 (new-value is the new value of the identifier)",
			set:         setWithSubject(riscEmailSubject("old@example.com")),
			payload:     map[string]any{"new-value": "not-an-address"},
			want:        Malformed,
			wantClaim:   "new-value",
			description: "the subject type constrains what the new value can be",
		},
		{
			name:        "new-value is not a number for a phone subject",
			citation:    "RISC §2.5",
			set:         setWithSubject(riscPhoneSubject("+1-604-555-0142")),
			payload:     map[string]any{"new-value": "not-a-phone"},
			want:        Malformed,
			wantClaim:   "new-value",
			description: "a phone identifier's new value contains digits",
		},
	}...)

	runRiscCases(t, riscIdentifierChangedEventUri, validateRiscIdentifierChanged, cases)
}

// TestValidateRiscIdentifierRecycled covers RISC §2.6 (Identifier Recycled): the
// same subject-type MUST, and the fact that the event defines no claims of its
// own — recycling reassigns the identifier rather than replacing it, so new-value
// is an unknown extra claim here and must not be required or type-checked.
func TestValidateRiscIdentifierRecycled(t *testing.T) {
	cases := append(riscIdentifierSubjectCases("RISC §2.6"), []validatorCase{
		{
			name:        "the canonical §2.6 shape",
			citation:    "RISC §2.6 (attributes: none)",
			set:         setWithSubject(riscEmailSubject("recycled@example.com")),
			payload:     map[string]any{},
			want:        Valid,
			description: "the recycled identifier is the subject; no payload claim is required",
		},
		{
			name:        "new-value is not a claim of this event",
			citation:    "RISC §2.6",
			set:         setWithSubject(riscEmailSubject("recycled@example.com")),
			payload:     map[string]any{"new-value": "not-an-address"},
			want:        Valid,
			description: "§2.6 defines no attributes, so new-value is an unknown extra claim and passes",
		},
	}...)

	runRiscCases(t, riscIdentifierRecycledEventUri, validateRiscIdentifierRecycled, cases)
}

// TestValidateRiscIdentifierChanged_MalformedDetailNamesTheClaim is the
// motivating example from the spec: an identifier-changed missing what it needs
// must not flow through to a downstream system unremarked. The disposition alone
// is not enough — the report has to say which claim failed.
func TestValidateRiscIdentifierChanged_MalformedDetailNamesTheClaim(t *testing.T) {
	got := validateRiscIdentifierChanged(riscIdentifierChangedEventUri,
		map[string]any{"new-value": "new@example.com"}, setWithSubject(nil))

	assert.Equal(t, Malformed, got.Disposition)
	assert.Equal(t, "sub_id", got.Claim)
	assert.Contains(t, got.Detail, "RISC §2.5", "the Detail must cite the rule that failed")
}
