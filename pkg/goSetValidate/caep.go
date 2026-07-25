package goSetValidate

import (
	"encoding/json"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/subjectid"
)

// The CAEP 1.0 event-type URIs this pack validates — the same five the repo's
// supported-events catalog enumerates.
//
// Deliberately re-declared here rather than imported: the catalog lives in
// pkg/ssfModels, which is outside this package's import allowlist (#247 Slice
// Contract). The values are spec constants, so the duplication cannot drift
// without the spec changing, and a drift guard in pkg/ssfModels asserts the two
// lists agree.
const (
	caepSessionRevokedEventUri         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	caepTokenClaimsChangeEventUri      = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	caepCredentialChangeEventUri       = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	caepAssuranceLevelChangeEventUri   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	caepDeviceComplianceChangeEventUri = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
)

// caepInitiatingEntities is the allowable "initiating_entity" vocabulary
// (CAEP §2). Absent is always fine — the claim is OPTIONAL.
var caepInitiatingEntities = map[string]struct{}{
	"admin":  {},
	"user":   {},
	"policy": {},
	"system": {},
}

// caepCredentialChangeTypes is the allowable "change_type" vocabulary
// (CAEP §3.3). Unlike credential_type, this list is closed.
var caepCredentialChangeTypes = map[string]struct{}{
	"create": {},
	"revoke": {},
	"update": {},
	"delete": {},
}

// caepAssuranceChangeDirections is the allowable "change_direction" vocabulary
// (CAEP §3.4).
var caepAssuranceChangeDirections = map[string]struct{}{
	"increase": {},
	"decrease": {},
}

// caepComplianceStatuses is the allowable device-compliance vocabulary shared by
// "previous_status" and "current_status" (CAEP §3.5).
var caepComplianceStatuses = map[string]struct{}{
	"compliant":     {},
	"not-compliant": {},
}

// registerCaepValidators adds the CAEP 1.0 pack to r and returns r so
// BuiltinRegistry keeps chaining.
func registerCaepValidators(r *Registry) *Registry {
	return r.
		Register(caepSessionRevokedEventUri, ValidatorFunc(validateCaepSessionRevoked)).
		Register(caepTokenClaimsChangeEventUri, ValidatorFunc(validateCaepTokenClaimsChange)).
		Register(caepCredentialChangeEventUri, ValidatorFunc(validateCaepCredentialChange)).
		Register(caepAssuranceLevelChangeEventUri, ValidatorFunc(validateCaepAssuranceLevelChange)).
		Register(caepDeviceComplianceChangeEventUri, ValidatorFunc(validateCaepDeviceComplianceChange))
}

// requireCaepSubject enforces the subject requirement every CAEP event carries:
// each of the five events describes something that happened to a specific
// session, token, credential holder, or device, so a SET that names no subject
// cannot be acted on.
//
// The subject is normally the SET's top-level sub_id claim, which is how CAEP
// 1.0's own examples convey it and how SSF frames it. An in-payload "subject"
// claim (the shape earlier CAEP drafts used, and what RFC 8417 §2.2 permits an
// event to carry) is accepted instead when present, so a transmitter that still
// emits it is not reported malformed.
//
// Structure is checked with pkg/subjectid — the same canonicalisation the
// router's subject matching uses — so "structurally valid" here means exactly
// "this subject could be matched against a stream's filters".
//
// Returns nil when the SET satisfies the rule.
func requireCaepSubject(eventURI, cite string, payload map[string]any, set *goSet.SecurityEventToken) *Result {
	if rawSubject, present := payload["subject"]; present {
		sid, err := decodeSubjectIdentifier(rawSubject)
		if err != nil {
			r := malformed(eventURI, "subject",
				"subject MUST be a JSON object carrying a subject identifier ("+cite+"): "+err.Error())
			return &r
		}
		if _, err := subjectid.CanonicalKey(sid); err != nil {
			r := malformed(eventURI, "subject",
				"subject is not a well-formed RFC 9493 subject identifier ("+cite+"): "+err.Error())
			return &r
		}
		return nil
	}

	if set == nil || set.SubjectId == nil {
		r := malformed(eventURI, "sub_id",
			"a subject is REQUIRED — the event describes a change to a specific subject, "+
				"normally carried by the SET's top-level sub_id claim ("+cite+")")
		return &r
	}
	if _, err := subjectid.CanonicalKey(set.SubjectId); err != nil {
		r := malformed(eventURI, "sub_id",
			"sub_id is not a well-formed RFC 9493 subject identifier ("+cite+"): "+err.Error())
		return &r
	}
	return nil
}

// decodeSubjectIdentifier round-trips a wire-shaped subject claim through JSON
// into the typed subject identifier pkg/subjectid understands.
func decodeSubjectIdentifier(raw any) (*goSet.SubjectIdentifier, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var sid goSet.SubjectIdentifier
	if err := json.Unmarshal(encoded, &sid); err != nil {
		return nil, err
	}
	return &sid, nil
}

// validateCaepCommonClaims checks the OPTIONAL claims CAEP §2 shares across every
// event type. Every one of them is OPTIONAL, so absence is never a failure; only
// a present-but-wrong-shape claim is reported.
//
// Returns nil when the payload satisfies the rule.
func validateCaepCommonClaims(eventURI string, payload map[string]any) *Result {
	if raw, present := payload["event_timestamp"]; present {
		if !isJsonNumber(raw) {
			r := malformed(eventURI, "event_timestamp",
				"event_timestamp MUST be a JSON number of seconds since 1970-01-01T0:0:0Z UTC (CAEP §2)")
			return &r
		}
	}

	if raw, present := payload["initiating_entity"]; present {
		entity, ok := raw.(string)
		if !ok {
			r := malformed(eventURI, "initiating_entity",
				"initiating_entity MUST be a JSON string (CAEP §2)")
			return &r
		}
		if _, allowable := caepInitiatingEntities[entity]; !allowable {
			r := malformed(eventURI, "initiating_entity",
				"initiating_entity \""+entity+"\" is outside the allowable values "+
					"\"admin\", \"user\", \"policy\", \"system\" (CAEP §2)")
			return &r
		}
	}

	for _, claim := range []string{"reason_admin", "reason_user"} {
		if bad := requireLanguageMap(eventURI, claim, payload); bad != nil {
			return bad
		}
	}

	return nil
}

// requireLanguageMap checks a CAEP §2 reason claim: a JSON object keyed by BCP47
// language tag whose values are strings. The claim is OPTIONAL, so an absent one
// passes.
func requireLanguageMap(eventURI, claim string, payload map[string]any) *Result {
	raw, present := payload[claim]
	if !present {
		return nil
	}
	messages, ok := raw.(map[string]any)
	if !ok {
		r := malformed(eventURI, claim,
			claim+" MUST be a JSON object keyed by BCP47 language tag (CAEP §2)")
		return &r
	}
	for tag, message := range messages {
		if tag == "" {
			r := malformed(eventURI, claim,
				claim+" has an empty language tag; keys MUST be BCP47 language tags (CAEP §2)")
			return &r
		}
		if _, ok := message.(string); !ok {
			r := malformed(eventURI, claim,
				claim+"[\""+tag+"\"] MUST be a string message (CAEP §2)")
			return &r
		}
	}
	return nil
}

// isJsonNumber reports whether raw came off the wire as a JSON number. A map
// decoded by encoding/json yields float64; a payload attached in-process as a
// typed struct is round-tripped through JSON by the ValidatorSet before it gets
// here, so float64 is the shape in practice — the integer cases are accepted for
// a caller that hand-built the claim map.
func isJsonNumber(raw any) bool {
	switch raw.(type) {
	case float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, json.Number:
		return true
	default:
		return false
	}
}

// requireCaepString extracts a REQUIRED string claim, reporting a Result that
// names the claim when it is absent, not a string, or empty.
func requireCaepString(eventURI, claim, cite string, payload map[string]any) (string, *Result) {
	raw, present := payload[claim]
	if !present {
		r := malformed(eventURI, claim, claim+" is REQUIRED ("+cite+")")
		return "", &r
	}
	value, ok := raw.(string)
	if !ok {
		r := malformed(eventURI, claim, claim+" MUST be a JSON string ("+cite+")")
		return "", &r
	}
	if value == "" {
		r := malformed(eventURI, claim, claim+" is present but empty ("+cite+")")
		return "", &r
	}
	return value, nil
}

// optionalCaepString type-checks an OPTIONAL string claim. An absent claim
// passes; a present non-string one does not.
func optionalCaepString(eventURI, claim, cite string, payload map[string]any) *Result {
	raw, present := payload[claim]
	if !present {
		return nil
	}
	if _, ok := raw.(string); !ok {
		r := malformed(eventURI, claim, claim+" MUST be a JSON string when present ("+cite+")")
		return &r
	}
	return nil
}

// requireCaepEnum checks a claim's value against a closed vocabulary.
func requireCaepEnum(eventURI, claim, cite, value string, allowable map[string]struct{}, rendered string) *Result {
	if _, ok := allowable[value]; ok {
		return nil
	}
	r := malformed(eventURI, claim,
		claim+" \""+value+"\" is outside the allowable values "+rendered+" ("+cite+")")
	return &r
}

// validateCaepSessionRevoked validates the CAEP Session Revoked event
// (CAEP §3.1). The event defines no claims of its own beyond the §2 common set:
// the session is identified by the subject, and event_timestamp — when present —
// is the time the revocation occurred.
func validateCaepSessionRevoked(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireCaepSubject(eventURI, "CAEP §3.1", payload, set); bad != nil {
		return *bad
	}
	if bad := validateCaepCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateCaepTokenClaimsChange validates the CAEP Token Claims Change event
// (CAEP §3.2). Claims:
//
//	claims  REQUIRED — a JSON object of one or more claim names and their new
//	        values. The values themselves are opaque to this validator: their
//	        types are whatever the changed token's claims are.
//
// The token whose claims changed is identified by the subject.
func validateCaepTokenClaimsChange(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireCaepSubject(eventURI, "CAEP §3.2", payload, set); bad != nil {
		return *bad
	}

	raw, present := payload["claims"]
	if !present {
		return malformed(eventURI, "claims",
			"claims is REQUIRED — it carries the claims whose values changed (CAEP §3.2)")
	}
	claims, ok := raw.(map[string]any)
	if !ok {
		return malformed(eventURI, "claims",
			"claims MUST be a JSON object of claim names to their new values (CAEP §3.2)")
	}
	if len(claims) == 0 {
		return malformed(eventURI, "claims",
			"claims MUST carry one or more claims with their new values (CAEP §3.2)")
	}

	if bad := validateCaepCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateCaepCredentialChange validates the CAEP Credential Change event
// (CAEP §3.3). Claims:
//
//	credential_type  REQUIRED — the type of credential that changed. CAEP lists a
//	                 vocabulary but explicitly allows any other mutually supported
//	                 type, so this is an OPEN vocabulary: only the string shape is
//	                 checked, never membership.
//	change_type      REQUIRED — one of "create", "revoke", "update", "delete".
//	friendly_name    OPTIONAL — a human-readable name for the credential.
//	x509_issuer      OPTIONAL — the X.509 issuer, when credential_type is x509.
//	x509_serial      OPTIONAL — the X.509 serial number, when credential_type is x509.
//	fido2_aaguid     OPTIONAL — the FIDO2 authenticator AAGUID.
func validateCaepCredentialChange(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "CAEP §3.3"

	if bad := requireCaepSubject(eventURI, cite, payload, set); bad != nil {
		return *bad
	}

	if _, bad := requireCaepString(eventURI, "credential_type", cite, payload); bad != nil {
		return *bad
	}

	changeType, bad := requireCaepString(eventURI, "change_type", cite, payload)
	if bad != nil {
		return *bad
	}
	if bad := requireCaepEnum(eventURI, "change_type", cite, changeType, caepCredentialChangeTypes,
		"\"create\", \"revoke\", \"update\", \"delete\""); bad != nil {
		return *bad
	}

	for _, claim := range []string{"friendly_name", "x509_issuer", "x509_serial", "fido2_aaguid"} {
		if bad := optionalCaepString(eventURI, claim, cite, payload); bad != nil {
			return *bad
		}
	}

	if bad := validateCaepCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateCaepAssuranceLevelChange validates the CAEP Assurance Level Change
// event (CAEP §3.4). Claims:
//
//	namespace         REQUIRED — the namespace the levels are defined in. CAEP
//	                  lists well-known namespaces but allows any other agreed one,
//	                  so this is an OPEN vocabulary: string shape only.
//	current_level     REQUIRED — the new assurance level, as defined by namespace.
//	previous_level    OPTIONAL — the prior level; when absent it is simply unknown.
//	change_direction  OPTIONAL — "increase" or "decrease".
func validateCaepAssuranceLevelChange(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "CAEP §3.4"

	if bad := requireCaepSubject(eventURI, cite, payload, set); bad != nil {
		return *bad
	}

	if _, bad := requireCaepString(eventURI, "namespace", cite, payload); bad != nil {
		return *bad
	}
	if _, bad := requireCaepString(eventURI, "current_level", cite, payload); bad != nil {
		return *bad
	}
	if bad := optionalCaepString(eventURI, "previous_level", cite, payload); bad != nil {
		return *bad
	}

	if raw, present := payload["change_direction"]; present {
		direction, ok := raw.(string)
		if !ok {
			return malformed(eventURI, "change_direction",
				"change_direction MUST be a JSON string when present ("+cite+")")
		}
		if bad := requireCaepEnum(eventURI, "change_direction", cite, direction,
			caepAssuranceChangeDirections, "\"increase\", \"decrease\""); bad != nil {
			return *bad
		}
	}

	if bad := validateCaepCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateCaepDeviceComplianceChange validates the CAEP Device Compliance Change
// event (CAEP §3.5). Claims:
//
//	previous_status  REQUIRED — "compliant" or "not-compliant".
//	current_status   REQUIRED — "compliant" or "not-compliant".
//
// The device whose compliance changed is identified by the subject.
func validateCaepDeviceComplianceChange(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "CAEP §3.5"

	if bad := requireCaepSubject(eventURI, cite, payload, set); bad != nil {
		return *bad
	}

	for _, claim := range []string{"previous_status", "current_status"} {
		status, bad := requireCaepString(eventURI, claim, cite, payload)
		if bad != nil {
			return *bad
		}
		if bad := requireCaepEnum(eventURI, claim, cite, status, caepComplianceStatuses,
			"\"compliant\", \"not-compliant\""); bad != nil {
			return *bad
		}
	}

	if bad := validateCaepCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}
