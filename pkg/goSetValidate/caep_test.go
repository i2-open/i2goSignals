package goSetValidate

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
)

// caepSubjectSet is the well-formed envelope the CAEP tables reuse: a top-level
// opaque sub_id, which is how CAEP 1.0's own examples convey the subject.
func caepSubjectSet() *goSet.SecurityEventToken {
	return setWithSubject(opaqueSubject("5a2b1f4c8e7d4a6f9c3b0d1e2f3a4b5c"))
}

// caepSessionSubjectSet carries the SSF §8.1.3 complex subject a real
// session-revoked event is most likely to use: a session member plus the user it
// belongs to.
func caepSessionSubjectSet() *goSet.SecurityEventToken {
	return setWithSubject(&goSet.SubjectIdentifier{
		ComplexIdentifier: goSet.ComplexIdentifier{
			Session: opaqueSubject("sess-9f8e7d"),
			User: &goSet.SubjectIdentifier{
				Format:                  "iss_sub",
				IssuerSubjectIdentifier: goSet.IssuerSubjectIdentifier{Issuer: "https://idp.example.com", Sub: "user-42"},
			},
		},
	})
}

// runCaepCases runs the shared validator table and additionally asserts the AC
// that a Malformed Detail names the claim that failed — a receiver operator reads
// the Detail, not the Claim field, out of a log line.
func runCaepCases(t *testing.T, eventURI string, validate ValidatorFunc, cases []validatorCase) {
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

// TestBuiltinRegistry_CarriesCaepValidatorPack asserts every CAEP event type the
// repo advertises has a validator, and that adding the pack did not displace the
// SSF stream-management validators already registered.
func TestBuiltinRegistry_CarriesCaepValidatorPack(t *testing.T) {
	r := BuiltinRegistry()

	for _, uri := range []string{
		caepSessionRevokedEventUri,
		caepTokenClaimsChangeEventUri,
		caepCredentialChangeEventUri,
		caepAssuranceLevelChangeEventUri,
		caepDeviceComplianceChangeEventUri,
	} {
		v, ok := r.Lookup(uri)
		assert.True(t, ok, "the built-in registry must carry a validator for %s", uri)
		assert.NotNil(t, v)
	}

	_, ok := r.Lookup(SsfVerificationEventUri)
	assert.True(t, ok, "the CAEP pack must not displace the SSF verification validator")
	_, ok = r.Lookup(SsfStreamUpdatedEventUri)
	assert.True(t, ok, "the CAEP pack must not displace the SSF stream-updated validator")
}

// TestValidateCaepSessionRevoked covers CAEP §3.1 (Session Revoked), which
// defines no claims of its own: the session comes from the subject, and the §2
// common claims are the only payload content.
func TestValidateCaepSessionRevoked(t *testing.T) {
	runCaepCases(t, caepSessionRevokedEventUri, validateCaepSessionRevoked, []validatorCase{
		{
			name:        "well-formed with opaque sub_id",
			citation:    "CAEP §3.1",
			set:         caepSubjectSet(),
			payload:     map[string]any{},
			want:        Valid,
			description: "the event defines no required payload claims; the subject carries the session",
		},
		{
			name:        "well-formed with complex session subject",
			citation:    "CAEP §3.1, SSF §8.1.3",
			set:         caepSessionSubjectSet(),
			payload:     map[string]any{"event_timestamp": float64(1761350400)},
			want:        Valid,
			description: "a complex subject naming the session and its user is a valid subject shape",
		},
		{
			name:     "well-formed with every common claim",
			citation: "CAEP §2",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"event_timestamp":   float64(1761350400),
				"initiating_entity": "policy",
				"reason_admin":      map[string]any{"en": "Policy violation detected"},
				"reason_user":       map[string]any{"en": "Please sign in again"},
			},
			want:        Valid,
			description: "all four §2 claims in their specified shapes",
		},
		{
			name:        "unknown extra claims are allowed",
			citation:    "CAEP §2 forward compatibility",
			set:         caepSubjectSet(),
			payload:     map[string]any{"vendor_extension": map[string]any{"risk": 0.9}, "future_claim": "x"},
			want:        Valid,
			description: "a validator must tolerate claims it does not know",
		},
		{
			name:        "missing subject",
			citation:    "CAEP §3.1",
			set:         setWithSubject(nil),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "without a subject there is no session to revoke",
		},
		{
			name:        "structurally invalid sub_id",
			citation:    "CAEP §3.1, RFC 9493 §3.2.2",
			set:         setWithSubject(&goSet.SubjectIdentifier{Format: "opaque"}),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "an opaque subject with no id cannot be matched against a stream",
		},
		{
			name:        "unrecognized subject format",
			citation:    "CAEP §3.1, RFC 9493 §3",
			set:         setWithSubject(&goSet.SubjectIdentifier{Format: "carrier-pigeon"}),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the subject format must be a registered identifier format",
		},
		{
			name:        "in-payload subject is accepted instead of sub_id",
			citation:    "CAEP §3.1, RFC 8417 §2.2",
			set:         setWithSubject(nil),
			payload:     map[string]any{"subject": map[string]any{"format": "opaque", "id": "sess-1234"}},
			want:        Valid,
			description: "a transmitter still emitting the earlier in-payload subject shape is not malformed",
		},
		{
			name:        "in-payload subject that is not an object",
			citation:    "CAEP §3.1, RFC 9493 §3",
			set:         setWithSubject(nil),
			payload:     map[string]any{"subject": "sess-1234"},
			want:        Malformed,
			wantClaim:   "subject",
			description: "a bare string is not a subject identifier",
		},
		{
			name:        "event_timestamp of the wrong type",
			citation:    "CAEP §2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"event_timestamp": "2026-07-24T00:00:00Z"},
			want:        Malformed,
			wantClaim:   "event_timestamp",
			description: "event_timestamp is a JSON number of seconds, not a formatted string",
		},
		{
			name:        "initiating_entity outside the allowable values",
			citation:    "CAEP §2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"initiating_entity": "robot"},
			want:        Malformed,
			wantClaim:   "initiating_entity",
			description: "the vocabulary is admin, user, policy, system",
		},
		{
			name:        "initiating_entity of the wrong type",
			citation:    "CAEP §2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"initiating_entity": float64(1)},
			want:        Malformed,
			wantClaim:   "initiating_entity",
			description: "initiating_entity is a JSON string",
		},
		{
			name:        "reason_admin that is not an object",
			citation:    "CAEP §2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"reason_admin": "Policy violation"},
			want:        Malformed,
			wantClaim:   "reason_admin",
			description: "reason_admin is keyed by BCP47 language tag",
		},
		{
			name:        "reason_user message that is not a string",
			citation:    "CAEP §2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"reason_user": map[string]any{"en": float64(42)}},
			want:        Malformed,
			wantClaim:   "reason_user",
			description: "each localised value is a message string",
		},
	})
}

// TestValidateCaepTokenClaimsChange covers CAEP §3.2 (Token Claims Change),
// whose one event-specific claim is the REQUIRED "claims" object.
func TestValidateCaepTokenClaimsChange(t *testing.T) {
	runCaepCases(t, caepTokenClaimsChangeEventUri, validateCaepTokenClaimsChange, []validatorCase{
		{
			name:        "well-formed single changed claim",
			citation:    "CAEP §3.2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"claims": map[string]any{"role": "ro-admin"}},
			want:        Valid,
			description: "claims maps a claim name to its new value",
		},
		{
			name:     "changed claim values may be any JSON type",
			citation: "CAEP §3.2",
			set:      caepSubjectSet(),
			payload: map[string]any{"claims": map[string]any{
				"role":         "ro-admin",
				"trusted":      false,
				"entitlements": []any{"read", "write"},
				"level":        float64(3),
			}},
			want:        Valid,
			description: "the new values are the token's own claim values, so their types are unconstrained",
		},
		{
			name:     "unknown extra claims are allowed",
			citation: "CAEP §3.2",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"claims":           map[string]any{"role": "ro-admin"},
				"vendor_extension": "ignored",
			},
			want:        Valid,
			description: "a validator must tolerate claims it does not know",
		},
		{
			name:        "missing claims",
			citation:    "CAEP §3.2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"event_timestamp": float64(1761350400)},
			want:        Malformed,
			wantClaim:   "claims",
			description: "claims is REQUIRED — without it the event says nothing changed",
		},
		{
			name:        "claims of the wrong type",
			citation:    "CAEP §3.2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"claims": "role=ro-admin"},
			want:        Malformed,
			wantClaim:   "claims",
			description: "claims is a JSON object, not a serialised string",
		},
		{
			name:        "empty claims object",
			citation:    "CAEP §3.2",
			set:         caepSubjectSet(),
			payload:     map[string]any{"claims": map[string]any{}},
			want:        Malformed,
			wantClaim:   "claims",
			description: "claims carries one or more changed claims",
		},
		{
			name:        "missing subject",
			citation:    "CAEP §3.2",
			set:         setWithSubject(nil),
			payload:     map[string]any{"claims": map[string]any{"role": "ro-admin"}},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the subject identifies the token whose claims changed",
		},
	})
}

// TestValidateCaepCredentialChange covers CAEP §3.3 (Credential Change): the two
// REQUIRED claims, the closed change_type vocabulary, the OPEN credential_type
// vocabulary, and the four OPTIONAL descriptive claims.
func TestValidateCaepCredentialChange(t *testing.T) {
	runCaepCases(t, caepCredentialChangeEventUri, validateCaepCredentialChange, []validatorCase{
		{
			name:     "well-formed password creation",
			citation: "CAEP §3.3",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"credential_type": "password",
				"change_type":     "create",
			},
			want:        Valid,
			description: "credential_type and change_type are the only required claims",
		},
		{
			name:     "well-formed x509 revocation with every optional claim",
			citation: "CAEP §3.3",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"credential_type": "x509",
				"change_type":     "revoke",
				"friendly_name":   "Work laptop certificate",
				"x509_issuer":     "CN=Example Issuing CA,O=Example,C=US",
				"x509_serial":     "1F2E3D4C5B6A",
				"fido2_aaguid":    "6028b017-b1d4-4c02-b4b3-afcdafc96bb2",
			},
			want:        Valid,
			description: "all optional claims in their specified shapes",
		},
		{
			name:     "credential_type outside the listed vocabulary is allowed",
			citation: "CAEP §3.3",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"credential_type": "vendor-smartcard",
				"change_type":     "update",
			},
			want:        Valid,
			description: "CAEP permits any other mutually supported credential type, so the vocabulary is open",
		},
		{
			name:        "missing credential_type",
			citation:    "CAEP §3.3",
			set:         caepSubjectSet(),
			payload:     map[string]any{"change_type": "create"},
			want:        Malformed,
			wantClaim:   "credential_type",
			description: "credential_type is REQUIRED",
		},
		{
			name:        "credential_type of the wrong type",
			citation:    "CAEP §3.3",
			set:         caepSubjectSet(),
			payload:     map[string]any{"credential_type": float64(7), "change_type": "create"},
			want:        Malformed,
			wantClaim:   "credential_type",
			description: "credential_type is a JSON string",
		},
		{
			name:        "missing change_type",
			citation:    "CAEP §3.3",
			set:         caepSubjectSet(),
			payload:     map[string]any{"credential_type": "password"},
			want:        Malformed,
			wantClaim:   "change_type",
			description: "change_type is REQUIRED",
		},
		{
			name:        "change_type of the wrong type",
			citation:    "CAEP §3.3",
			set:         caepSubjectSet(),
			payload:     map[string]any{"credential_type": "password", "change_type": true},
			want:        Malformed,
			wantClaim:   "change_type",
			description: "change_type is a JSON string",
		},
		{
			name:        "change_type outside the allowable values",
			citation:    "CAEP §3.3",
			set:         caepSubjectSet(),
			payload:     map[string]any{"credential_type": "password", "change_type": "rotate"},
			want:        Malformed,
			wantClaim:   "change_type",
			description: "the vocabulary is create, revoke, update, delete",
		},
		{
			name:     "friendly_name of the wrong type",
			citation: "CAEP §3.3",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"credential_type": "password",
				"change_type":     "create",
				"friendly_name":   float64(1),
			},
			want:        Malformed,
			wantClaim:   "friendly_name",
			description: "an OPTIONAL claim still has to be the right type when present",
		},
		{
			name:        "missing subject",
			citation:    "CAEP §3.3",
			set:         setWithSubject(nil),
			payload:     map[string]any{"credential_type": "password", "change_type": "create"},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the subject identifies whose credential changed",
		},
	})
}

// TestValidateCaepAssuranceLevelChange covers CAEP §3.4 (Assurance Level
// Change): REQUIRED namespace and current_level, OPTIONAL previous_level and
// change_direction.
func TestValidateCaepAssuranceLevelChange(t *testing.T) {
	runCaepCases(t, caepAssuranceLevelChangeEventUri, validateCaepAssuranceLevelChange, []validatorCase{
		{
			name:     "well-formed increase with previous level",
			citation: "CAEP §3.4",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"namespace":        "NIST-AAL",
				"current_level":    "aal2",
				"previous_level":   "aal1",
				"change_direction": "increase",
			},
			want:        Valid,
			description: "all four claims in their specified shapes",
		},
		{
			name:     "well-formed with both optional claims absent",
			citation: "CAEP §3.4",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"namespace":     "RFC8176",
				"current_level": "mfa",
			},
			want:        Valid,
			description: "an omitted previous_level means the prior level is simply unknown",
		},
		{
			name:     "namespace outside the listed vocabulary is allowed",
			citation: "CAEP §3.4",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"namespace":     "urn:example:assurance",
				"current_level": "gold",
			},
			want:        Valid,
			description: "CAEP permits any other agreed namespace, so the vocabulary is open",
		},
		{
			name:        "missing namespace",
			citation:    "CAEP §3.4",
			set:         caepSubjectSet(),
			payload:     map[string]any{"current_level": "aal2"},
			want:        Malformed,
			wantClaim:   "namespace",
			description: "namespace is REQUIRED — a level is meaningless without it",
		},
		{
			name:        "missing current_level",
			citation:    "CAEP §3.4",
			set:         caepSubjectSet(),
			payload:     map[string]any{"namespace": "NIST-AAL"},
			want:        Malformed,
			wantClaim:   "current_level",
			description: "current_level is REQUIRED",
		},
		{
			name:        "current_level of the wrong type",
			citation:    "CAEP §3.4",
			set:         caepSubjectSet(),
			payload:     map[string]any{"namespace": "NIST-AAL", "current_level": float64(2)},
			want:        Malformed,
			wantClaim:   "current_level",
			description: "current_level is a JSON string defined by the namespace",
		},
		{
			name:     "previous_level of the wrong type",
			citation: "CAEP §3.4",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"namespace":      "NIST-AAL",
				"current_level":  "aal2",
				"previous_level": float64(1),
			},
			want:        Malformed,
			wantClaim:   "previous_level",
			description: "an OPTIONAL claim still has to be the right type when present",
		},
		{
			name:     "change_direction of the wrong type",
			citation: "CAEP §3.4",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"namespace":        "NIST-AAL",
				"current_level":    "aal2",
				"change_direction": float64(1),
			},
			want:        Malformed,
			wantClaim:   "change_direction",
			description: "change_direction is a JSON string",
		},
		{
			name:     "change_direction outside the allowable values",
			citation: "CAEP §3.4",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"namespace":        "NIST-AAL",
				"current_level":    "aal2",
				"change_direction": "sideways",
			},
			want:        Malformed,
			wantClaim:   "change_direction",
			description: "the vocabulary is increase, decrease",
		},
		{
			name:        "missing subject",
			citation:    "CAEP §3.4",
			set:         setWithSubject(nil),
			payload:     map[string]any{"namespace": "NIST-AAL", "current_level": "aal2"},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the subject identifies whose assurance level changed",
		},
	})
}

// TestValidateCaepDeviceComplianceChange covers CAEP §3.5 (Device Compliance
// Change): both status claims are REQUIRED and both share a closed vocabulary.
func TestValidateCaepDeviceComplianceChange(t *testing.T) {
	runCaepCases(t, caepDeviceComplianceChangeEventUri, validateCaepDeviceComplianceChange, []validatorCase{
		{
			name:     "well-formed fall out of compliance",
			citation: "CAEP §3.5",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"previous_status": "compliant",
				"current_status":  "not-compliant",
			},
			want:        Valid,
			description: "both statuses drawn from the allowable values",
		},
		{
			name:     "well-formed return to compliance with common claims",
			citation: "CAEP §3.5, §2",
			set:      caepSubjectSet(),
			payload: map[string]any{
				"previous_status":   "not-compliant",
				"current_status":    "compliant",
				"initiating_entity": "system",
				"event_timestamp":   float64(1761350400),
			},
			want:        Valid,
			description: "the §2 common claims apply to this event like any other",
		},
		{
			name:        "missing previous_status",
			citation:    "CAEP §3.5",
			set:         caepSubjectSet(),
			payload:     map[string]any{"current_status": "compliant"},
			want:        Malformed,
			wantClaim:   "previous_status",
			description: "previous_status is REQUIRED",
		},
		{
			name:        "missing current_status",
			citation:    "CAEP §3.5",
			set:         caepSubjectSet(),
			payload:     map[string]any{"previous_status": "compliant"},
			want:        Malformed,
			wantClaim:   "current_status",
			description: "current_status is REQUIRED",
		},
		{
			name:        "current_status of the wrong type",
			citation:    "CAEP §3.5",
			set:         caepSubjectSet(),
			payload:     map[string]any{"previous_status": "compliant", "current_status": true},
			want:        Malformed,
			wantClaim:   "current_status",
			description: "current_status is a JSON string",
		},
		{
			name:        "current_status outside the allowable values",
			citation:    "CAEP §3.5",
			set:         caepSubjectSet(),
			payload:     map[string]any{"previous_status": "compliant", "current_status": "unknown"},
			want:        Malformed,
			wantClaim:   "current_status",
			description: "the vocabulary is compliant, not-compliant",
		},
		{
			name:        "missing subject",
			citation:    "CAEP §3.5",
			set:         setWithSubject(nil),
			payload:     map[string]any{"previous_status": "compliant", "current_status": "not-compliant"},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the subject identifies the device whose compliance changed",
		},
	})
}

// TestCaepValidators_OptionalClaimsAbsentAndExtrasPresent is the cross-cutting
// tolerance rule, checked once per event type: the minimum well-formed payload
// validates with every OPTIONAL and RECOMMENDED claim absent, and still validates
// when unknown claims are added to it.
func TestCaepValidators_OptionalClaimsAbsentAndExtrasPresent(t *testing.T) {
	minimal := map[string]map[string]any{
		caepSessionRevokedEventUri:    {},
		caepTokenClaimsChangeEventUri: {"claims": map[string]any{"role": "ro-admin"}},
		caepCredentialChangeEventUri:  {"credential_type": "password", "change_type": "update"},
		caepAssuranceLevelChangeEventUri: {
			"namespace":     "NIST-AAL",
			"current_level": "aal2",
		},
		caepDeviceComplianceChangeEventUri: {
			"previous_status": "compliant",
			"current_status":  "not-compliant",
		},
	}

	registry := BuiltinRegistry()

	for uri, payload := range minimal {
		t.Run(uri, func(t *testing.T) {
			validator, ok := registry.Lookup(uri)
			if !assert.True(t, ok, "no validator registered for %s", uri) {
				return
			}

			got := validator.Validate(uri, payload, caepSubjectSet())
			assert.Equal(t, Valid, got.Disposition,
				"every OPTIONAL/RECOMMENDED claim absent must still validate: %s", got.Detail)

			extended := map[string]any{
				"unknown_vendor_claim": map[string]any{"nested": []any{"a", "b"}},
				"another_new_claim":    float64(1),
			}
			for k, v := range payload {
				extended[k] = v
			}

			got = validator.Validate(uri, extended, caepSubjectSet())
			assert.Equal(t, Valid, got.Disposition,
				"unknown extra claims must not fail validation: %s", got.Detail)
		})
	}
}

// TestValidatorSet_CaepPackIsReachableThroughEngagement checks the pack from the
// caller's side: a stream that engaged a CAEP URI gets the pack's disposition,
// and one that did not still reports Unsupported.
func TestValidatorSet_CaepPackIsReachableThroughEngagement(t *testing.T) {
	set := caepSubjectSet()
	set.AddEventPayload(caepDeviceComplianceChangeEventUri, map[string]any{
		"previous_status": "compliant",
		"current_status":  "bogus",
	})

	engaged := NewValidatorSet(BuiltinRegistry(), []string{caepDeviceComplianceChangeEventUri})
	result := engaged.Validate(set)
	assert.Equal(t, Malformed, result.Disposition)
	assert.Len(t, result.Results, 1)
	assert.Equal(t, "current_status", result.Results[0].Claim)

	notEngaged := NewValidatorSet(BuiltinRegistry(), []string{caepSessionRevokedEventUri})
	result = notEngaged.Validate(set)
	assert.Equal(t, Unsupported, result.Disposition,
		"a registered validator must not run for a URI the stream never engaged")
}
