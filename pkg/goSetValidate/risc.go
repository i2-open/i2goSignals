package goSetValidate

import (
	"strings"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/subjectid"
)

// The RISC 1.0 event-type URIs this pack validates — the same nine the repo's
// supported-events catalog enumerates. RISC also defines credential-compromise
// and the opt-in / opt-out family; those are not in the catalog, so a validator
// for them would never be engaged and is deliberately absent.
//
// Deliberately re-declared here rather than imported: the catalog lives in
// pkg/ssfModels, which is outside this package's import allowlist (#247 Slice
// Contract). The values are spec constants, so the duplication cannot drift
// without the spec changing, and a drift guard in pkg/ssfModels asserts the two
// lists agree.
const (
	riscAccountEnabledEventUri                  = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	riscAccountDisabledEventUri                 = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	riscAccountPurgedEventUri                   = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	riscAccountCredentialChangeRequiredEventUri = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
	riscRecoveryActivatedEventUri               = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
	riscRecoveryInformationChangedEventUri      = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"
	riscSessionsRevokedEventUri                 = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
	riscIdentifierChangedEventUri               = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
	riscIdentifierRecycledEventUri              = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
)

// riscIdentifierSubjectFormats is the closed subject-type vocabulary RISC §2.5
// and §2.6 impose on the identifier events: "The subject type MUST be either
// email or phone."
//
// RISC 1.0 predates RFC 9493 and spells the second one "phone"; the RFC 9493
// format name this repo canonicalises is "phone_number". Only the RFC 9493
// spellings are accepted — a "phone" subject cannot be canonicalised by
// pkg/subjectid, so it could not be matched against a stream's filters either —
// but the failure Detail names the modern spelling so the report is actionable.
var riscIdentifierSubjectFormats = map[string]struct{}{
	"email":        {},
	"phone_number": {},
}

// registerRiscValidators adds the RISC 1.0 pack to r and returns r so
// BuiltinRegistry keeps chaining.
func registerRiscValidators(r *Registry) *Registry {
	return r.
		Register(riscAccountEnabledEventUri, ValidatorFunc(validateRiscAccountEnabled)).
		Register(riscAccountDisabledEventUri, ValidatorFunc(validateRiscAccountDisabled)).
		Register(riscAccountPurgedEventUri, ValidatorFunc(validateRiscAccountPurged)).
		Register(riscAccountCredentialChangeRequiredEventUri, ValidatorFunc(validateRiscAccountCredentialChangeRequired)).
		Register(riscRecoveryActivatedEventUri, ValidatorFunc(validateRiscRecoveryActivated)).
		Register(riscRecoveryInformationChangedEventUri, ValidatorFunc(validateRiscRecoveryInformationChanged)).
		Register(riscSessionsRevokedEventUri, ValidatorFunc(validateRiscSessionsRevoked)).
		Register(riscIdentifierChangedEventUri, ValidatorFunc(validateRiscIdentifierChanged)).
		Register(riscIdentifierRecycledEventUri, ValidatorFunc(validateRiscIdentifierRecycled))
}

// riscSubjectClaim names the claim a RISC subject failure should be attributed
// to. RISC 1.0 predates SSF and its own examples put a "subject" claim inside the
// event payload (the shape RFC 8417 §2.2 permits); SSF moved the subject to the
// SET's top-level sub_id claim, which is what this router's transmitters emit.
// Either carrier satisfies the subject rule, with the in-payload form taking
// precedence when both are present, so an older RISC transmitter is not reported
// malformed.
func riscSubjectClaim(payload map[string]any) string {
	if _, present := payload["subject"]; present {
		return "subject"
	}
	return "sub_id"
}

// riscSubjectPresence resolves the subject from whichever carrier holds it,
// without applying any structural rule — the identifier events order their own
// checks so that a subject-type violation is reported against the RISC rule it
// actually breaks.
func riscSubjectPresence(eventURI, cite, claim string, payload map[string]any, set *goSet.SecurityEventToken) (*goSet.SubjectIdentifier, *Result) {
	var sid *goSet.SubjectIdentifier

	if rawSubject, present := payload["subject"]; present {
		decoded, err := decodeSubjectIdentifier(rawSubject)
		if err != nil {
			r := malformed(eventURI, claim,
				"subject MUST be a JSON object carrying a subject identifier ("+cite+"): "+err.Error())
			return nil, &r
		}
		sid = decoded
	} else if set != nil {
		sid = set.SubjectId
	}

	if sid == nil {
		r := malformed(eventURI, claim,
			"a subject is REQUIRED — the event describes a change to a specific subject, "+
				"normally carried by the SET's top-level sub_id claim ("+cite+")")
		return nil, &r
	}
	return sid, nil
}

// requireRiscSubject enforces the subject rule the seven non-identifier RISC
// events share: each is defined in terms of its subject — "the account
// identified by the subject" — so a SET naming no subject carries no signal a
// receiver can act on.
//
// Structure is checked with pkg/subjectid — the same canonicalisation the
// router's subject matching uses — so "structurally valid" here means exactly
// "this subject could be matched against a stream's filters". A pre-RFC 9493
// subject spelling its type as "subject_type" rather than "format" therefore
// does NOT pass: it is unroutable on this router, and reporting it as well-formed
// would hide that. No subject FORMAT is required: RISC names a typical type per
// event without making it normative, and a transmitter that identifies an
// account by opaque id or email is not malformed.
//
// Returns nil when the SET satisfies the rule.
func requireRiscSubject(eventURI, cite string, payload map[string]any, set *goSet.SecurityEventToken) *Result {
	claim := riscSubjectClaim(payload)

	sid, bad := riscSubjectPresence(eventURI, cite, claim, payload, set)
	if bad != nil {
		return bad
	}

	if _, err := subjectid.CanonicalKey(sid); err != nil {
		r := malformed(eventURI, claim,
			claim+" is not a well-formed RFC 9493 subject identifier ("+cite+"): "+err.Error())
		return &r
	}
	return nil
}

// riscIdentifierSubject enforces the extra constraint the two identifier events
// carry: "The subject type MUST be either email or phone" (RISC §2.5, §2.6).
//
// The subject-type check runs BEFORE canonicalisation so a legacy "phone"
// subject is reported against the RISC rule that it actually violates rather
// than as an unrecognised RFC 9493 format. Canonicalisation then enforces §2.5's
// "it MUST specify the old value": pkg/subjectid rejects an email or
// phone_number subject whose value is empty.
//
// A complex or aliases subject is a different subject type and so fails the
// same rule — its Format is not one of the two.
//
// Returns the subject's format on success.
func riscIdentifierSubject(eventURI, cite string, payload map[string]any, set *goSet.SecurityEventToken) (string, *Result) {
	claim := riscSubjectClaim(payload)

	sid, bad := riscSubjectPresence(eventURI, cite, claim, payload, set)
	if bad != nil {
		return "", bad
	}

	if _, allowable := riscIdentifierSubjectFormats[sid.Format]; !allowable {
		detail := claim + " type \"" + sid.Format + "\" is outside the allowable subject types: " +
			"the subject type MUST be either email or phone (" + cite + ")"
		if sid.Format == "phone" {
			detail += " — RFC 9493 spells that format \"phone_number\""
		}
		if sid.Format == "" {
			detail = claim + " declares no subject type: the subject type MUST be either email or " +
				"phone, carried in the RFC 9493 \"format\" member (" + cite + ")"
		}
		r := malformed(eventURI, claim, detail)
		return "", &r
	}

	if _, err := subjectid.CanonicalKey(sid); err != nil {
		r := malformed(eventURI, claim,
			claim+" MUST specify the old value of the identifier ("+cite+"): "+err.Error())
		return "", &r
	}

	return sid.Format, nil
}

// optionalRiscString type-checks an OPTIONAL RISC string claim. An absent claim
// passes — a validator must never fail on an absent OPTIONAL or RECOMMENDED
// claim — but a present one must be a non-empty string, since every optional
// RISC string claim exists to carry a value.
func optionalRiscString(eventURI, claim, cite string, payload map[string]any) (string, *Result) {
	raw, present := payload[claim]
	if !present {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok {
		r := malformed(eventURI, claim, claim+" MUST be a JSON string when present ("+cite+")")
		return "", &r
	}
	if strings.TrimSpace(value) == "" {
		r := malformed(eventURI, claim, claim+" is present but empty ("+cite+")")
		return "", &r
	}
	return value, nil
}

// validateRiscAccountEnabled validates the RISC Account Enabled event
// (RISC §2.4): "the account identified by the subject has been enabled". The
// event defines no claims of its own.
func validateRiscAccountEnabled(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireRiscSubject(eventURI, "RISC §2.4", payload, set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateRiscAccountDisabled validates the RISC Account Disabled event
// (RISC §2.3). Claims:
//
//	reason  OPTIONAL — why the account was disabled. RISC lists "hijacking" and
//	        "bulk-account" as possible values without closing the vocabulary, so
//	        membership is NOT checked: an unlisted reason is a value this
//	        validator has no standing to reject.
func validateRiscAccountDisabled(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "RISC §2.3"

	if bad := requireRiscSubject(eventURI, cite, payload, set); bad != nil {
		return *bad
	}
	if _, bad := optionalRiscString(eventURI, "reason", cite, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateRiscAccountPurged validates the RISC Account Purged event
// (RISC §2.2): the account identified by the subject has been purged. The event
// defines no claims of its own.
func validateRiscAccountPurged(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireRiscSubject(eventURI, "RISC §2.2", payload, set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateRiscAccountCredentialChangeRequired validates the RISC Account
// Credential Change Required event (RISC §2.1): the subject is required to
// change a credential. The event defines no claims of its own.
func validateRiscAccountCredentialChangeRequired(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireRiscSubject(eventURI, "RISC §2.1", payload, set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateRiscRecoveryActivated validates the RISC Recovery Activated event
// (RISC §2.8): an account-recovery flow was activated for the subject. The event
// defines no claims of its own.
func validateRiscRecoveryActivated(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireRiscSubject(eventURI, "RISC §2.8", payload, set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateRiscRecoveryInformationChanged validates the RISC Recovery Information
// Changed event (RISC §2.9): the subject's recovery information changed. The
// event defines no claims of its own.
func validateRiscRecoveryInformationChanged(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireRiscSubject(eventURI, "RISC §2.9", payload, set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateRiscSessionsRevoked validates the RISC Sessions Revoked event
// (RISC §2.10): all of the subject's sessions were revoked. The event defines no
// claims of its own — the sessions are identified collectively by the subject,
// which is what distinguishes it from CAEP Session Revoked.
func validateRiscSessionsRevoked(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireRiscSubject(eventURI, "RISC §2.10", payload, set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateRiscIdentifierChanged validates the RISC Identifier Changed event
// (RISC §2.5): "the identifier specified in the subject has changed". Rules:
//
//	subject    REQUIRED — "The subject type MUST be either email or phone and it
//	           MUST specify the old value."
//	new-value  OPTIONAL — the new value of the identifier. Absent means the
//	           transmitter is not disclosing it, which §2.5 permits; present means
//	           it must actually be a value of the subject's identifier type.
//
// The new-value type cross-check is derived: §2.5 defines the claim as the new
// value of an identifier whose type it has already constrained to email or
// phone, so an object, an empty string, or an email-typed change whose new value
// is not an address cannot be what the claim means. The checks are deliberately
// the weakest ones that catch that — an "@" for email, a digit for a phone
// number — because a validator that guessed at address or number syntax would
// reject values the spec allows. This is the event the spec's motivating example
// uses, so it gets real coverage rather than a subject-only check.
func validateRiscIdentifierChanged(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "RISC §2.5"

	format, bad := riscIdentifierSubject(eventURI, cite, payload, set)
	if bad != nil {
		return *bad
	}

	newValue, bad := optionalRiscString(eventURI, "new-value", cite, payload)
	if bad != nil {
		return *bad
	}
	if newValue == "" {
		return valid(eventURI)
	}

	switch format {
	case "email":
		if !strings.Contains(newValue, "@") {
			return malformed(eventURI, "new-value",
				"new-value MUST be the new value of the identifier, and the subject is an email "+
					"identifier, so it MUST be an email address ("+cite+")")
		}
	case "phone_number":
		if !strings.ContainsFunc(newValue, isAsciiDigit) {
			return malformed(eventURI, "new-value",
				"new-value MUST be the new value of the identifier, and the subject is a phone_number "+
					"identifier, so it MUST be a phone number ("+cite+")")
		}
	}

	return valid(eventURI)
}

// validateRiscIdentifierRecycled validates the RISC Identifier Recycled event
// (RISC §2.6): "the identifier specified in the subject was recycled and now it
// belongs to a new user". Rules:
//
//	subject  REQUIRED — "The subject type MUST be either email or phone."
//
// The event defines no claims of its own. In particular new-value is NOT one of
// its claims: recycling reassigns the identifier rather than replacing it, so a
// payload carrying new-value is treated as an unknown extra claim and allowed
// through, never required and never type-checked.
func validateRiscIdentifierRecycled(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if _, bad := riscIdentifierSubject(eventURI, "RISC §2.6", payload, set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// isAsciiDigit reports whether r is one of "0".."9".
func isAsciiDigit(r rune) bool {
	return r >= '0' && r <= '9'
}
