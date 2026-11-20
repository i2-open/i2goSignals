package goSetValidate

import (
	"net/url"
	"strings"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/subjectid"
)

// EXPERIMENTAL — Workload Identity Security Events (WISE).
//
// WISE is an UNADOPTED proposal (https://github.com/identitymonk/openid-wise),
// not an OpenID specification. This pack makes NO conformance claim, stated or
// implied, and carries no stability promise: the URIs, the claim names, and the
// closed vocabularies below are all drawn from a draft that may change or be
// abandoned. Nothing outside this file depends on it.
//
// The degrade path is deliberately gentle. If the adopted profile ends up using
// different URIs, the URIs registered here simply stop matching anything on the
// wire and the new ones resolve as Unsupported — forwarded under NONE / WARN /
// ENFORCE, rejected only under STRICT, which is the mode an operator picks
// precisely to say "reject what nothing vouched for". No SET is mis-reported as
// Malformed by a stale URI, because a validator only ever runs for a URI it is
// registered under.
//
// This pack is the surviving half of closed PR #245. That contribution wired a
// WISE parser straight into the poll receiver and returned a
// WISERecommendedAction (isolate the workload, revoke the credential, refresh
// trust material). The payload checks are preserved here; the recommended-action
// and incident-response policy is NOT, and is not reconstructible from this
// package. Which findings warrant which response is the receiving deployment's
// call, bound to its own authorization, audit and retention controls — a
// transmitter's event is a report, never a command, and this library reports
// dispositions and nothing else.
//
// wiseEventPrefix is the event-type base URI the proposal uses
// (WISE draft § Event Types).
const wiseEventPrefix = "https://schemas.openid.net/secevent/wise/event-type/"

// The four WISE event types this pack validates — the same high-priority subset
// PR #245 selected. The draft defines many more (credential-issued,
// credential-rotated, the workload-lifecycle, policy, supply-chain and
// anomalous-behavior families); each of those is deliberately absent rather than
// half-checked, so it resolves as Unsupported instead of being vouched for by a
// validator nobody wrote.
const (
	wiseCredentialRevokedEventUri    = wiseEventPrefix + "credential-revoked"    // WISE draft § credential-revoked
	wiseCredentialCompromiseEventUri = wiseEventPrefix + "credential-compromise" // WISE draft § credential-compromise
	wiseTrustAnchorChangedEventUri   = wiseEventPrefix + "trust-anchor-changed"  // WISE draft § trust-anchor-changed
	wiseWorkloadCompromisedEventUri  = wiseEventPrefix + "workload-compromised"  // WISE draft § workload-compromised
)

// wiseSubjectFormat is the subject identifier format WISE names as primary for
// workload events: "The `uri` format is the primary subject identifier format
// for WISE events" (WISE draft § Subject Identifiers for Workload Events / URI
// Format). It carries a WIMSE Workload Identifier, a SPIFFE ID, or a client-ID
// metadata URL — different schemes, one RFC 9493 format.
const wiseSubjectFormat = "uri"

// wiseAnchorTypes is the closed vocabulary trust-anchor-changed puts on
// anchor_type (WISE draft § trust-anchor-changed).
var wiseAnchorTypes = map[string]struct{}{
	"jwks":    {},
	"x509_ca": {},
}

// wiseChangeTypes is the closed vocabulary trust-anchor-changed puts on
// change_type (WISE draft § trust-anchor-changed).
var wiseChangeTypes = map[string]struct{}{
	"key_added":        {},
	"key_rotated":      {},
	"key_revoked":      {},
	"key_expired":      {},
	"full_replacement": {},
}

// registerWiseValidators adds the experimental WISE pack to r and returns r so
// BuiltinRegistry keeps chaining. Registration is unconditional — an event URI
// nobody sends costs a map entry — but see the EXPERIMENTAL notice above for
// what a receiver is and is not being promised.
func registerWiseValidators(r *Registry) *Registry {
	return r.
		Register(wiseCredentialRevokedEventUri, ValidatorFunc(validateWiseCredentialRevoked)).
		Register(wiseCredentialCompromiseEventUri, ValidatorFunc(validateWiseCredentialCompromise)).
		Register(wiseTrustAnchorChangedEventUri, ValidatorFunc(validateWiseTrustAnchorChanged)).
		Register(wiseWorkloadCompromisedEventUri, ValidatorFunc(validateWiseWorkloadCompromised))
}

// requireWiseSubject enforces the subject rule every WISE event in this pack
// shares: each is defined in terms of the workload (or, for
// trust-anchor-changed, the trust domain) the signal is about, so a SET naming
// no subject carries nothing a receiver can act on.
//
// Two carriers are accepted. The draft's own examples put a "subject" claim
// inside the event payload, which is the shape PR #245 read and which RFC 8417
// §2.2 permits; SSF puts the subject in the SET's top-level sub_id, which is
// what this router's transmitters emit. The in-payload form wins when both are
// present, so a transmitter following the draft literally is not reported
// malformed.
//
// Beyond presence, three things are checked:
//
//   - the subject canonicalises under pkg/subjectid — the same canonicalisation
//     the router's subject matching uses, so "structurally valid" here means
//     exactly "this subject could be matched against a stream's filters";
//   - its format is "uri" — the format the draft names as primary. This is the
//     strictest rule in the pack and the one most likely to change: if the
//     adopted profile blesses a second format, this check is what loosens;
//   - its uri is ABSOLUTE. A Workload Identifier is a URI with a trust domain in
//     the authority component, so a bare path identifies nothing. pkg/subjectid
//     only requires the value be non-empty, so the scheme check lives here.
//
// Returns nil when the SET satisfies the rule.
func requireWiseSubject(eventURI, cite string, payload map[string]any, set *goSet.SecurityEventToken) *Result {
	claim := "sub_id"
	var sid *goSet.SubjectIdentifier

	if rawSubject, present := payload["subject"]; present {
		claim = "subject"
		decoded, err := decodeSubjectIdentifier(rawSubject)
		if err != nil {
			r := malformed(eventURI, claim,
				"subject MUST be a JSON object carrying a subject identifier ("+cite+"): "+err.Error())
			return &r
		}
		sid = decoded
	} else if set != nil {
		sid = set.SubjectId
	}

	if sid == nil {
		r := malformed(eventURI, claim,
			"a subject is REQUIRED — the event describes a specific workload, normally carried by "+
				"the SET's top-level sub_id claim ("+cite+")")
		return &r
	}

	if sid.Format != wiseSubjectFormat {
		detail := claim + " format \"" + sid.Format + "\" is not the primary WISE subject format: " +
			"a workload subject is identified by its Workload Identifier in the RFC 9493 \"uri\" " +
			"format (" + cite + ")"
		if sid.Format == "" {
			detail = claim + " declares no subject format: a workload subject is identified by its " +
				"Workload Identifier in the RFC 9493 \"uri\" format (" + cite + ")"
		}
		r := malformed(eventURI, claim, detail)
		return &r
	}

	if _, err := subjectid.CanonicalKey(sid); err != nil {
		r := malformed(eventURI, claim,
			claim+" is not a well-formed RFC 9493 subject identifier ("+cite+"): "+err.Error())
		return &r
	}

	if !isAbsoluteUri(sid.Uri) {
		r := malformed(eventURI, claim,
			claim+" uri MUST be an absolute URI — a Workload Identifier carries its trust domain in "+
				"the authority component ("+cite+")")
		return &r
	}

	return nil
}

// isAbsoluteUri reports whether value parses as a URI carrying a scheme. It is
// deliberately scheme-agnostic: the draft's examples use wimse, spiffe and
// https, and a deployment on some other scheme is not malformed.
func isAbsoluteUri(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	parsed, err := url.ParseRequestURI(trimmed)
	return err == nil && parsed.Scheme != ""
}

// optionalWiseNumber type-checks an OPTIONAL NumericDate claim. An absent claim
// passes — a validator must never fail on an absent OPTIONAL claim — but a
// present one must be a JSON number, since a timestamp spelled as a string
// cannot be compared to anything.
func optionalWiseNumber(eventURI, claim, cite string, payload map[string]any) *Result {
	raw, present := payload[claim]
	if !present {
		return nil
	}
	if !isJsonNumber(raw) {
		r := malformed(eventURI, claim,
			claim+" MUST be a JSON number (NumericDate) when present ("+cite+")")
		return &r
	}
	return nil
}

// validateWiseCommonClaims checks the claims WISE inherits wholesale: "any WISE
// event MAY include the common optional claims defined in Section 2 of [CAEP]"
// — reason_admin and reason_user as BCP 47 language maps rather than plain
// strings (the draft says MUST for that shape), initiating_entity from CAEP's
// closed vocabulary, and event_timestamp as a NumericDate
// (WISE draft § Common Optional Claims).
//
// The CAEP pack's helper is exactly that rule, so it is reused rather than
// re-implemented; failure details cite CAEP §2, which is where WISE points.
func validateWiseCommonClaims(eventURI string, payload map[string]any) *Result {
	return validateCaepCommonClaims(eventURI, payload)
}

// validateWiseCredentialRevoked validates the WISE Credential Revoked event
// (WISE draft § credential-revoked): "a workload's credential was explicitly
// revoked before its natural expiry". Claims:
//
//	credential_type  REQUIRED — the type of credential revoked.
//	credential_id    OPTIONAL — identifier of the revoked credential.
//	reason           OPTIONAL — why it was revoked. The draft lists compromise,
//	                 key_compromise, superseded, cessation and policy_violation
//	                 as "possible values" without closing the set, so membership
//	                 is NOT checked: an unlisted reason on an advisory optional
//	                 claim is a value this validator has no standing to reject,
//	                 and PR #245 read it only to pick a recommended action, which
//	                 is policy this package does not do.
func validateWiseCredentialRevoked(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "WISE draft § credential-revoked"

	if bad := requireWiseSubject(eventURI, cite, payload, set); bad != nil {
		return *bad
	}
	if _, bad := requireCaepString(eventURI, "credential_type", cite, payload); bad != nil {
		return *bad
	}
	for _, claim := range []string{"credential_id", "reason"} {
		if bad := optionalCaepString(eventURI, claim, cite, payload); bad != nil {
			return *bad
		}
	}
	if bad := validateWiseCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateWiseCredentialCompromise validates the WISE Credential Compromise
// event (WISE draft § credential-compromise): "a workload credential is believed
// to have been compromised". Claims:
//
//	credential_type  REQUIRED — the type of credential compromised.
//	credential_id    OPTIONAL — identifier of the compromised credential.
//
// reason_admin is called out by the draft on this event specifically, but it is
// the common optional claim and is checked as such.
func validateWiseCredentialCompromise(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "WISE draft § credential-compromise"

	if bad := requireWiseSubject(eventURI, cite, payload, set); bad != nil {
		return *bad
	}
	if _, bad := requireCaepString(eventURI, "credential_type", cite, payload); bad != nil {
		return *bad
	}
	if bad := optionalCaepString(eventURI, "credential_id", cite, payload); bad != nil {
		return *bad
	}
	if bad := validateWiseCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateWiseTrustAnchorChanged validates the WISE Trust Anchor Changed event
// (WISE draft § trust-anchor-changed): "the trust anchors for a trust domain
// have changed". Its subject is the trust domain itself, expressed as a Workload
// Identifier Origin — still the "uri" format, so the shared subject rule applies
// unchanged. Claims:
//
//	anchor_type          REQUIRED — jwks or x509_ca.
//	change_type          REQUIRED — key_added, key_rotated, key_revoked,
//	                     key_expired or full_replacement.
//	trust_domain         REQUIRED — FQDN of the trust domain whose material
//	                     changed. NOT pattern-matched: the draft makes no
//	                     hostname syntax normative.
//	effective_at         OPTIONAL — NumericDate.
//	old_material_expiry  OPTIONAL — NumericDate.
//	jwks_uri             OPTIONAL — where to fetch the updated JWK Set.
//	x509_bundle_uri      OPTIONAL — where to fetch the updated CA bundle.
//	key_id               OPTIONAL — the specific key affected.
//	reason               OPTIONAL — open vocabulary, same reasoning as
//	                     credential-revoked's reason.
//
// anchor_type and change_type ARE checked against their vocabularies, unlike the
// optional reasons: they are REQUIRED and the whole meaning of the event is the
// value, so a receiver that does not recognise it cannot act on the event at
// all. That is the one place where reporting Malformed is more useful than
// forwarding a signal nobody can interpret. The two URI claims are type-checked
// but not fetched or resolved — retrieving trust material is the receiver's
// decision, on the receiver's schedule.
func validateWiseTrustAnchorChanged(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "WISE draft § trust-anchor-changed"

	if bad := requireWiseSubject(eventURI, cite, payload, set); bad != nil {
		return *bad
	}

	anchorType, bad := requireCaepString(eventURI, "anchor_type", cite, payload)
	if bad != nil {
		return *bad
	}
	if bad := requireCaepEnum(eventURI, "anchor_type", cite, anchorType, wiseAnchorTypes,
		"\"jwks\", \"x509_ca\""); bad != nil {
		return *bad
	}

	changeType, bad := requireCaepString(eventURI, "change_type", cite, payload)
	if bad != nil {
		return *bad
	}
	if bad := requireCaepEnum(eventURI, "change_type", cite, changeType, wiseChangeTypes,
		"\"key_added\", \"key_rotated\", \"key_revoked\", \"key_expired\", \"full_replacement\""); bad != nil {
		return *bad
	}

	if _, bad := requireCaepString(eventURI, "trust_domain", cite, payload); bad != nil {
		return *bad
	}

	for _, claim := range []string{"jwks_uri", "x509_bundle_uri", "key_id", "reason"} {
		if bad := optionalCaepString(eventURI, claim, cite, payload); bad != nil {
			return *bad
		}
	}
	for _, claim := range []string{"effective_at", "old_material_expiry"} {
		if bad := optionalWiseNumber(eventURI, claim, cite, payload); bad != nil {
			return *bad
		}
	}

	if bad := validateWiseCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateWiseWorkloadCompromised validates the WISE Workload Compromised event
// (WISE draft § workload-compromised): "a workload is believed to be compromised
// based on runtime detection". Claims:
//
//	detection_method  OPTIONAL — how the compromise was detected. Free text; the
//	                  draft closes no vocabulary.
//
// The draft calls this "a high-severity signal that SHOULD trigger immediate
// isolation or credential revocation". That sentence is about the receiver's
// response, not the payload's shape, so it is deliberately not encoded here:
// PR #245 turned it into a WISERecommendedAction, and dropping that is the
// point of re-homing this pack. The event's severity is carried by its URI,
// which the receiver already sees.
func validateWiseWorkloadCompromised(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "WISE draft § workload-compromised"

	if bad := requireWiseSubject(eventURI, cite, payload, set); bad != nil {
		return *bad
	}
	if bad := optionalCaepString(eventURI, "detection_method", cite, payload); bad != nil {
		return *bad
	}
	if bad := validateWiseCommonClaims(eventURI, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}
