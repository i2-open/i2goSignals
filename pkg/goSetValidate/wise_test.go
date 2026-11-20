package goSetValidate

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wiseWorkloadId is the WIMSE Workload Identifier the tables reuse — the exact
// shape the draft's non-normative examples use
// (WISE draft § Subject Identifiers for Workload Events / URI Format).
const wiseWorkloadId = "wimse://trust.example.com/workload/payment-service"

// wiseTrustDomainId is the Workload Identifier Origin trust-anchor-changed uses
// as its subject (WISE draft § Trust Domain Subject).
const wiseTrustDomainId = "wimse://trust.example.com"

func wiseUriSubject(uri string) *goSet.SubjectIdentifier {
	return &goSet.SubjectIdentifier{
		Format:                    "uri",
		UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: uri},
	}
}

// wiseWorkloadSet is the well-formed envelope the workload-scoped tables reuse:
// a top-level sub_id in the "uri" format, which is how this router's
// transmitters carry a subject.
func wiseWorkloadSet() *goSet.SecurityEventToken {
	return setWithSubject(wiseUriSubject(wiseWorkloadId))
}

func wiseTrustDomainSet() *goSet.SecurityEventToken {
	return setWithSubject(wiseUriSubject(wiseTrustDomainId))
}

// wiseSubjectlessSet is a SET carrying no sub_id at all.
func wiseSubjectlessSet() *goSet.SecurityEventToken {
	return setWithSubject(nil)
}

// runWiseCases runs the shared validator table and additionally asserts the AC
// that a Malformed Detail names the claim that failed — an operator reads the
// Detail out of a log line, not the structured Claim field.
func runWiseCases(t *testing.T, eventURI string, validate ValidatorFunc, cases []validatorCase) {
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

// wiseSubjectCases is the subject table every WISE event in this pack shares
// (WISE draft § Subject Identifiers for Workload Events / URI Format). base is a
// payload carrying that event's REQUIRED claims and nothing else, so the only
// variable across the cases is the subject.
func wiseSubjectCases(subjectUri string, base map[string]any) []validatorCase {
	const cite = "WISE draft § URI Format (uri is the primary subject identifier format)"

	withBase := func(extra map[string]any) map[string]any {
		merged := map[string]any{}
		for k, v := range base {
			merged[k] = v
		}
		for k, v := range extra {
			merged[k] = v
		}
		return merged
	}

	return []validatorCase{
		{
			name:        "subject carried by the SET's top-level sub_id",
			citation:    cite,
			set:         setWithSubject(wiseUriSubject(subjectUri)),
			payload:     withBase(nil),
			want:        Valid,
			description: "SSF puts the subject in sub_id; that satisfies the rule",
		},
		{
			name:     "subject carried in the payload, as the draft's examples do",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: withBase(map[string]any{
				"subject": map[string]any{"format": "uri", "uri": subjectUri},
			}),
			want:        Valid,
			description: "the draft's examples put subject inside the event payload (RFC 8417 §2.2)",
		},
		{
			name:        "no subject anywhere",
			citation:    cite,
			set:         wiseSubjectlessSet(),
			payload:     withBase(nil),
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the event describes a specific workload; without one it carries no signal",
		},
		{
			name:     "subject in a format other than uri",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: withBase(map[string]any{
				"subject": map[string]any{"format": "email", "email": "ops@example.com"},
			}),
			want:        Malformed,
			wantClaim:   "subject",
			description: "uri is the primary WISE subject format; a workload is not an email address",
		},
		{
			name:     "subject declares no format",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: withBase(map[string]any{
				"subject": map[string]any{"uri": subjectUri},
			}),
			want:        Malformed,
			wantClaim:   "subject",
			description: "an RFC 9493 subject identifier must declare its format",
		},
		{
			name:     "subject uri is empty",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: withBase(map[string]any{
				"subject": map[string]any{"format": "uri", "uri": ""},
			}),
			want:        Malformed,
			wantClaim:   "subject",
			description: "pkg/subjectid cannot canonicalise a uri subject with no value",
		},
		{
			name:     "subject uri is a bare path, not an absolute URI",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: withBase(map[string]any{
				"subject": map[string]any{"format": "uri", "uri": "/workload/payment-service"},
			}),
			want:        Malformed,
			wantClaim:   "subject",
			description: "a Workload Identifier carries its trust domain in the authority component",
		},
		{
			name:     "subject is not an object",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: withBase(map[string]any{
				"subject": wiseWorkloadId,
			}),
			want:        Malformed,
			wantClaim:   "subject",
			description: "a subject identifier is a JSON object, not a bare string",
		},
	}
}

// TestWiseSubjectFormats covers the schemes the draft's examples use: a WIMSE
// Workload Identifier, a SPIFFE ID, and an OAuth client-ID metadata URL. All
// three are the same RFC 9493 "uri" format, so the pack must not privilege one
// scheme (WISE draft § URI Format).
func TestWiseSubjectFormats(t *testing.T) {
	for _, subjectUri := range []string{
		wiseWorkloadId,
		"spiffe://trust.example.com/ns/production/sa/payment-service",
		"https://client.example.com/.well-known/oauth-client",
	} {
		t.Run(subjectUri, func(t *testing.T) {
			got := validateWiseWorkloadCompromised(
				wiseWorkloadCompromisedEventUri,
				map[string]any{},
				setWithSubject(wiseUriSubject(subjectUri)),
			)
			assert.Equal(t, Valid, got.Disposition,
				"the draft names wimse, spiffe and https URLs as workload subjects")
		})
	}
}

// TestValidateWiseWorkloadCompromised covers WISE draft § workload-compromised.
// Its only own claim is the OPTIONAL detection_method; the high-severity
// "SHOULD trigger immediate isolation or credential revocation" sentence is
// receiver policy and is deliberately NOT encoded (that is what PR #245 carried
// and this re-homing drops).
func TestValidateWiseWorkloadCompromised(t *testing.T) {
	const cite = "WISE draft § workload-compromised"

	cases := []validatorCase{
		{
			name:        "no claims at all",
			citation:    cite,
			set:         wiseWorkloadSet(),
			payload:     map[string]any{},
			want:        Valid,
			description: "every claim on this event is OPTIONAL",
		},
		{
			name:        "detection_method present",
			citation:    cite + " (detection_method: OPTIONAL)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"detection_method": "runtime-monitor"},
			want:        Valid,
			description: "free text; the draft closes no vocabulary",
		},
		{
			name:        "detection_method is not a string",
			citation:    cite + " (detection_method: OPTIONAL)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"detection_method": 42.0},
			want:        Malformed,
			wantClaim:   "detection_method",
			description: "a present optional claim must still have the right type",
		},
		{
			name:     "unknown extra claims are tolerated",
			citation: cite,
			set:      wiseWorkloadSet(),
			payload: map[string]any{
				"detection_method":  "ebpf",
				"vendor_confidence": 0.97,
				"vendor_case_url":   "https://soc.example.com/case/17",
			},
			want:        Valid,
			description: "forward compatibility: an unadopted profile will grow claims",
		},
		{
			name:     "common optional claims in their CAEP shapes",
			citation: "WISE draft § Common Optional Claims (defers to CAEP §2)",
			set:      wiseWorkloadSet(),
			payload: map[string]any{
				"event_timestamp":   1700000000.0,
				"initiating_entity": "system",
				"reason_admin":      map[string]any{"en": "Private key material detected in public repository"},
			},
			want:        Valid,
			description: "WISE inherits the CAEP §2 common optional claims wholesale",
		},
		{
			name:        "reason_admin as a plain string",
			citation:    "WISE draft § Common Optional Claims (MUST use the localizable object structure)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"reason_admin": "compromised"},
			want:        Malformed,
			wantClaim:   "reason_admin",
			description: "the draft explicitly forbids the plain-string spelling",
		},
	}
	cases = append(cases, wiseSubjectCases(wiseWorkloadId, map[string]any{})...)

	runWiseCases(t, wiseWorkloadCompromisedEventUri, validateWiseWorkloadCompromised, cases)
}

// TestValidateWiseCredentialCompromise covers WISE draft § credential-compromise:
// credential_type is REQUIRED, credential_id is OPTIONAL.
func TestValidateWiseCredentialCompromise(t *testing.T) {
	const cite = "WISE draft § credential-compromise"

	cases := []validatorCase{
		{
			name:        "required credential_type only",
			citation:    cite + " (credential_type: REQUIRED)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": "wit"},
			want:        Valid,
			description: "the minimum conformant payload",
		},
		{
			name:     "the draft's full non-normative example",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: map[string]any{
				"subject":         map[string]any{"format": "uri", "uri": wiseWorkloadId},
				"credential_type": "wit",
				"credential_id":   "jti:wit-signing-key-2024-q4",
				"reason_admin":    map[string]any{"en": "Private key material detected in public repository"},
			},
			want:        Valid,
			description: "the example in the draft must validate as written",
		},
		{
			name:        "credential_type absent",
			citation:    cite + " (credential_type: REQUIRED)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_id": "jti:wit-signing-key-2024-q4"},
			want:        Malformed,
			wantClaim:   "credential_type",
			description: "missing REQUIRED claim: recognized but malformed",
		},
		{
			name:        "credential_type is not a string",
			citation:    cite + " (credential_type: REQUIRED)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": map[string]any{"kind": "wit"}},
			want:        Malformed,
			wantClaim:   "credential_type",
			description: "wrong claim type: recognized but malformed",
		},
		{
			name:        "credential_type present but empty",
			citation:    cite + " (credential_type: REQUIRED)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": ""},
			want:        Malformed,
			wantClaim:   "credential_type",
			description: "an empty required string names no credential type",
		},
		{
			name:        "credential_id is not a string",
			citation:    cite + " (credential_id: OPTIONAL)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": "wit", "credential_id": 17.0},
			want:        Malformed,
			wantClaim:   "credential_id",
			description: "a present optional claim must still have the right type",
		},
		{
			name:        "credential_id absent",
			citation:    cite + " (credential_id: OPTIONAL)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": "wic"},
			want:        Valid,
			description: "an absent OPTIONAL claim never fails validation",
		},
	}
	cases = append(cases, wiseSubjectCases(wiseWorkloadId, map[string]any{"credential_type": "wit"})...)

	runWiseCases(t, wiseCredentialCompromiseEventUri, validateWiseCredentialCompromise, cases)
}

// TestValidateWiseCredentialRevoked covers WISE draft § credential-revoked:
// credential_type REQUIRED; credential_id, reason and event_timestamp OPTIONAL.
//
// The reason vocabulary is deliberately NOT closed — see the validator's doc
// comment. PR #245 read reason only to choose a recommended action, which is the
// policy this re-homing drops.
func TestValidateWiseCredentialRevoked(t *testing.T) {
	const cite = "WISE draft § credential-revoked"

	cases := []validatorCase{
		{
			name:     "the draft's full non-normative example",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: map[string]any{
				"subject":         map[string]any{"format": "uri", "uri": wiseWorkloadId},
				"credential_type": "wic",
				"credential_id":   "serial:ABC123DEF456",
				"reason":          "compromise",
			},
			want:        Valid,
			description: "the example in the draft must validate as written",
		},
		{
			name:        "listed reason key_compromise",
			citation:    cite + " (reason: OPTIONAL)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": "wic", "reason": "key_compromise"},
			want:        Valid,
			description: "a bound key is signalled by revoking its credential",
		},
		{
			name:        "reason outside the draft's listed values",
			citation:    cite + " (reason: OPTIONAL, \"possible values\" — an open list)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": "wic", "reason": "operator_request"},
			want:        Valid,
			description: "an advisory optional claim is not a closed vocabulary this pack may police",
		},
		{
			name:        "reason is not a string",
			citation:    cite + " (reason: OPTIONAL)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": "wic", "reason": []any{"compromise"}},
			want:        Malformed,
			wantClaim:   "reason",
			description: "wrong claim type: recognized but malformed",
		},
		{
			name:        "credential_type absent",
			citation:    cite + " (credential_type: REQUIRED)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"reason": "superseded"},
			want:        Malformed,
			wantClaim:   "credential_type",
			description: "missing REQUIRED claim: recognized but malformed",
		},
		{
			name:        "event_timestamp as a NumericDate",
			citation:    cite + " (event_timestamp: OPTIONAL)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": "wic", "event_timestamp": 1700000000.0},
			want:        Valid,
			description: "the time at which revocation occurred",
		},
		{
			name:        "event_timestamp as a string",
			citation:    cite + " (event_timestamp: OPTIONAL, NumericDate)",
			set:         wiseWorkloadSet(),
			payload:     map[string]any{"credential_type": "wic", "event_timestamp": "1700000000"},
			want:        Malformed,
			wantClaim:   "event_timestamp",
			description: "a timestamp spelled as a string cannot be compared to anything",
		},
	}
	cases = append(cases, wiseSubjectCases(wiseWorkloadId, map[string]any{"credential_type": "wic"})...)

	runWiseCases(t, wiseCredentialRevokedEventUri, validateWiseCredentialRevoked, cases)
}

// TestValidateWiseTrustAnchorChanged covers WISE draft § trust-anchor-changed:
// anchor_type, change_type and trust_domain are REQUIRED, the first two against
// closed vocabularies; the rest of the claims are OPTIONAL.
func TestValidateWiseTrustAnchorChanged(t *testing.T) {
	const cite = "WISE draft § trust-anchor-changed"

	base := map[string]any{
		"anchor_type":  "jwks",
		"change_type":  "key_rotated",
		"trust_domain": "trust.example.com",
	}
	with := func(extra map[string]any) map[string]any {
		merged := map[string]any{}
		for k, v := range base {
			merged[k] = v
		}
		for k, v := range extra {
			merged[k] = v
		}
		return merged
	}

	cases := []validatorCase{
		{
			name:     "the draft's JWKS-rotation example",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: map[string]any{
				"subject":             map[string]any{"format": "uri", "uri": wiseTrustDomainId},
				"anchor_type":         "jwks",
				"change_type":         "key_rotated",
				"trust_domain":        "trust.example.com",
				"effective_at":        1700000000.0,
				"old_material_expiry": 1700604800.0,
				"jwks_uri":            "https://authority.example.com/.well-known/jwks.json",
				"key_id":              "kid:signing-2024-q4",
				"reason":              "scheduled_rotation",
			},
			want:        Valid,
			description: "the example in the draft must validate as written",
		},
		{
			name:     "the draft's CA-compromise example",
			citation: cite,
			set:      wiseSubjectlessSet(),
			payload: map[string]any{
				"subject":      map[string]any{"format": "uri", "uri": wiseTrustDomainId},
				"anchor_type":  "x509_ca",
				"change_type":  "key_revoked",
				"trust_domain": "trust.example.com",
				"key_id":       "serial:CA-ROOT-2023-001",
				"reason":       "compromise",
			},
			want:        Valid,
			description: "key_revoked is a change_type, not a recommended action",
		},
		{
			name:        "anchor_type absent",
			citation:    cite + " (anchor_type: REQUIRED)",
			set:         wiseTrustDomainSet(),
			payload:     map[string]any{"change_type": "key_rotated", "trust_domain": "trust.example.com"},
			want:        Malformed,
			wantClaim:   "anchor_type",
			description: "missing REQUIRED claim: recognized but malformed",
		},
		{
			name:        "anchor_type outside its closed vocabulary",
			citation:    cite + " (anchor_type: REQUIRED — x509_ca or jwks)",
			set:         wiseTrustDomainSet(),
			payload:     with(map[string]any{"anchor_type": "pgp"}),
			want:        Malformed,
			wantClaim:   "anchor_type",
			description: "the whole meaning of the event is the value; an unknown one is uninterpretable",
		},
		{
			name:        "anchor_type is not a string",
			citation:    cite + " (anchor_type: REQUIRED)",
			set:         wiseTrustDomainSet(),
			payload:     with(map[string]any{"anchor_type": 1.0}),
			want:        Malformed,
			wantClaim:   "anchor_type",
			description: "wrong claim type: recognized but malformed",
		},
		{
			name:        "change_type absent",
			citation:    cite + " (change_type: REQUIRED)",
			set:         wiseTrustDomainSet(),
			payload:     map[string]any{"anchor_type": "jwks", "trust_domain": "trust.example.com"},
			want:        Malformed,
			wantClaim:   "change_type",
			description: "missing REQUIRED claim: recognized but malformed",
		},
		{
			name:        "change_type outside its closed vocabulary",
			citation:    cite + " (change_type: REQUIRED — five listed values)",
			set:         wiseTrustDomainSet(),
			payload:     with(map[string]any{"change_type": "key_unrevoked"}),
			want:        Malformed,
			wantClaim:   "change_type",
			description: "an unlisted change is an instruction the receiver cannot follow",
		},
		{
			name:        "trust_domain absent",
			citation:    cite + " (trust_domain: REQUIRED)",
			set:         wiseTrustDomainSet(),
			payload:     map[string]any{"anchor_type": "jwks", "change_type": "key_added"},
			want:        Malformed,
			wantClaim:   "trust_domain",
			description: "missing REQUIRED claim: recognized but malformed",
		},
		{
			name:        "effective_at as a string",
			citation:    cite + " (effective_at: OPTIONAL, NumericDate)",
			set:         wiseTrustDomainSet(),
			payload:     with(map[string]any{"effective_at": "1700000000"}),
			want:        Malformed,
			wantClaim:   "effective_at",
			description: "wrong claim type on an optional NumericDate",
		},
		{
			name:        "old_material_expiry as a string",
			citation:    cite + " (old_material_expiry: OPTIONAL, NumericDate)",
			set:         wiseTrustDomainSet(),
			payload:     with(map[string]any{"old_material_expiry": "later"}),
			want:        Malformed,
			wantClaim:   "old_material_expiry",
			description: "wrong claim type on an optional NumericDate",
		},
		{
			name:        "x509_bundle_uri is not a string",
			citation:    cite + " (x509_bundle_uri: OPTIONAL)",
			set:         wiseTrustDomainSet(),
			payload:     with(map[string]any{"anchor_type": "x509_ca", "x509_bundle_uri": 7.0}),
			want:        Malformed,
			wantClaim:   "x509_bundle_uri",
			description: "wrong claim type: recognized but malformed",
		},
		{
			name:        "every optional claim absent",
			citation:    cite,
			set:         wiseTrustDomainSet(),
			payload:     with(nil),
			want:        Valid,
			description: "the three REQUIRED claims are the whole obligation",
		},
		{
			name:        "unknown extra claims are tolerated",
			citation:    cite,
			set:         wiseTrustDomainSet(),
			payload:     with(map[string]any{"bundle_generation": 12.0, "operator_ticket": "CHG-8891"}),
			want:        Valid,
			description: "forward compatibility: an unadopted profile will grow claims",
		},
	}
	cases = append(cases, wiseSubjectCases(wiseTrustDomainId, base)...)

	runWiseCases(t, wiseTrustAnchorChangedEventUri, validateWiseTrustAnchorChanged, cases)
}

// TestBuiltinRegistry_CarriesWiseValidatorPack asserts the four WISE event types
// this pack ships are registered, and that adding an experimental pack did not
// displace any adopted pack already there.
func TestBuiltinRegistry_CarriesWiseValidatorPack(t *testing.T) {
	r := BuiltinRegistry()

	for _, uri := range []string{
		wiseCredentialRevokedEventUri,
		wiseCredentialCompromiseEventUri,
		wiseTrustAnchorChangedEventUri,
		wiseWorkloadCompromisedEventUri,
	} {
		v, ok := r.Lookup(uri)
		assert.True(t, ok, "the built-in registry must carry a validator for %s", uri)
		assert.NotNil(t, v)
	}

	for _, uri := range []string{
		SsfVerificationEventUri,
		SsfStreamUpdatedEventUri,
		caepSessionRevokedEventUri,
		riscAccountDisabledEventUri,
		scimCreateFullEventUri,
	} {
		_, ok := r.Lookup(uri)
		assert.True(t, ok, "the WISE pack must not displace the adopted validator for %s", uri)
	}
}

// TestWiseUnregisteredEventDegradesToUnsupported is the degrade path the slice
// promises. WISE is unadopted, so its URIs may move; anything outside the four
// this pack registers — a WISE event nobody wrote a validator for, or a
// hypothetical successor URI — must resolve as Unsupported rather than Valid or
// Malformed.
//
// Unsupported is what the SERVER's mode policy then acts on: forwarded under
// NONE / WARN / ENFORCE, rejected only under STRICT. That mapping lives in the
// server wiring, never here — this package only has to report the disposition
// that makes the mapping possible.
func TestWiseUnregisteredEventDegradesToUnsupported(t *testing.T) {
	for _, uri := range []string{
		wiseEventPrefix + "anomalous-behavior-detected",                               // a real WISE event this pack does not validate
		wiseEventPrefix + "credential-issued",                                         // ditto
		"https://schemas.openid.net/secevent/wise-v2/event-type/workload-compromised", // a hypothetical successor URI
	} {
		t.Run(uri, func(t *testing.T) {
			_, ok := BuiltinRegistry().Lookup(uri)
			require.False(t, ok, "this URI is deliberately not registered")

			set := wiseWorkloadSet()
			set.Events = map[string]interface{}{
				uri: map[string]any{
					"subject": map[string]any{"format": "uri", "uri": wiseWorkloadId},
				},
			}

			// Engaged by the stream, so engagement is not what makes this
			// Unsupported — the absent validator is.
			vs := NewValidatorSet(BuiltinRegistry(), []string{uri})
			got := vs.Validate(set)

			assert.Equal(t, Unsupported, got.Disposition)
			require.Len(t, got.Results, 1)
			assert.Equal(t, uri, got.Results[0].EventURI)
			assert.Equal(t, Unsupported, got.Results[0].Disposition)
			assert.Empty(t, got.Results[0].Claim, "Unsupported blames no claim")
		})
	}
}

// TestWiseEventReachesItsValidatorThroughAValidatorSet is the companion to the
// degrade test: a registered WISE URI that the stream engaged is validated, and
// a malformed payload surfaces as Malformed on the whole-SET reduction.
func TestWiseEventReachesItsValidatorThroughAValidatorSet(t *testing.T) {
	vs := NewValidatorSet(BuiltinRegistry(), []string{wiseCredentialRevokedEventUri})

	good := wiseWorkloadSet()
	good.Events = map[string]interface{}{
		wiseCredentialRevokedEventUri: map[string]any{"credential_type": "wic"},
	}
	assert.Equal(t, Valid, vs.Validate(good).Disposition)

	bad := wiseWorkloadSet()
	bad.Events = map[string]interface{}{
		wiseCredentialRevokedEventUri: map[string]any{"reason": "cessation"},
	}
	got := vs.Validate(bad)
	assert.Equal(t, Malformed, got.Disposition)
	require.Len(t, got.Results, 1)
	assert.Equal(t, "credential_type", got.Results[0].Claim)
}

// TestWiseEventUris pins the four URIs to the draft's spellings so a typo cannot
// silently register a validator nothing will ever match.
func TestWiseEventUris(t *testing.T) {
	assert.Equal(t, "https://schemas.openid.net/secevent/wise/event-type/credential-revoked", wiseCredentialRevokedEventUri)
	assert.Equal(t, "https://schemas.openid.net/secevent/wise/event-type/credential-compromise", wiseCredentialCompromiseEventUri)
	assert.Equal(t, "https://schemas.openid.net/secevent/wise/event-type/trust-anchor-changed", wiseTrustAnchorChangedEventUri)
	assert.Equal(t, "https://schemas.openid.net/secevent/wise/event-type/workload-compromised", wiseWorkloadCompromisedEventUri)
}

// TestWiseCarriesNoRecommendedActionPolicy guards the boundary this slice
// exists to enforce. PR #245 returned a WISERecommendedAction — isolate the
// workload, revoke the credential, refresh trust material — computed from
// reason and change_type. Nothing here may reconstruct that: a Result carries a
// disposition, a claim name and a reason, and never an instruction. If a future
// change adds one, this test is where it should fail first.
func TestWiseCarriesNoRecommendedActionPolicy(t *testing.T) {
	compromised := validateWiseCredentialRevoked(
		wiseCredentialRevokedEventUri,
		map[string]any{"credential_type": "wic", "reason": "key_compromise"},
		wiseWorkloadSet(),
	)
	superseded := validateWiseCredentialRevoked(
		wiseCredentialRevokedEventUri,
		map[string]any{"credential_type": "wic", "reason": "superseded"},
		wiseWorkloadSet(),
	)

	assert.Equal(t, superseded, compromised,
		"reason must not change the reported Result — which response a finding warrants is the "+
			"receiving deployment's call, not this library's")

	revoked := validateWiseTrustAnchorChanged(
		wiseTrustAnchorChangedEventUri,
		map[string]any{"anchor_type": "jwks", "change_type": "key_revoked", "trust_domain": "trust.example.com"},
		wiseTrustDomainSet(),
	)
	rotated := validateWiseTrustAnchorChanged(
		wiseTrustAnchorChangedEventUri,
		map[string]any{"anchor_type": "jwks", "change_type": "key_rotated", "trust_domain": "trust.example.com"},
		wiseTrustDomainSet(),
	)
	assert.Equal(t, rotated, revoked,
		"change_type must not change the reported Result either")
}
