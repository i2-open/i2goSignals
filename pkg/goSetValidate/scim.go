package goSetValidate

import (
	"strconv"
	"strings"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/subjectid"
)

// The SCIM event-type URNs this pack validates — the same twelve the repo's
// supported-events catalog enumerates, verified verbatim against published
// RFC 9967 ("SCIM Profile for Security Event Tokens"). Each constant carries the
// RFC section that defines it; scim_test.go pins the literals so a silent
// re-spelling cannot happen.
//
// Verification result (RFC 9967 vs the draft-ietf-scim-events-16 spellings the
// catalog was written from): NO URN CHANGED. Every URN below is byte-identical
// to the one already in pkg/ssfModels, including the all-lowercase "scim"
// namespace-specific string and the all-lowercase "asyncresp" (the catalog was
// already corrected from "asyncResp" in v0.12.0-alpha.4). RFC 9967 defines no
// SCIM event type outside this list, so nothing was added either.
//
// Deliberately re-declared here rather than imported: the catalog lives in
// pkg/ssfModels, which is outside this package's import allowlist (#247 Slice
// Contract). The values are spec constants, so the duplication cannot drift
// without the spec changing, and a drift guard in pkg/ssfModels asserts the two
// lists agree.
const (
	scimFeedAddEventUri       = "urn:ietf:params:scim:event:feed:add"           // RFC 9967 §2.3.1
	scimFeedRemoveEventUri    = "urn:ietf:params:scim:event:feed:remove"        // RFC 9967 §2.3.2
	scimCreateFullEventUri    = "urn:ietf:params:scim:event:prov:create:full"   // RFC 9967 §2.4.1
	scimCreateNoticeEventUri  = "urn:ietf:params:scim:event:prov:create:notice" // RFC 9967 §2.4.1
	scimPatchFullEventUri     = "urn:ietf:params:scim:event:prov:patch:full"    // RFC 9967 §2.4.2
	scimPatchNoticeEventUri   = "urn:ietf:params:scim:event:prov:patch:notice"  // RFC 9967 §2.4.2
	scimPutFullEventUri       = "urn:ietf:params:scim:event:prov:put:full"      // RFC 9967 §2.4.3
	scimPutNoticeEventUri     = "urn:ietf:params:scim:event:prov:put:notice"    // RFC 9967 §2.4.3
	scimDeleteEventUri        = "urn:ietf:params:scim:event:prov:delete"        // RFC 9967 §2.4.4
	scimActivateEventUri      = "urn:ietf:params:scim:event:prov:activate"      // RFC 9967 §2.4.5
	scimDeactivateEventUri    = "urn:ietf:params:scim:event:prov:deactivate"    // RFC 9967 §2.4.6
	scimAsyncResponseEventUri = "urn:ietf:params:scim:event:misc:asyncresp"     // RFC 9967 §2.5
)

// scimSubjectFormat is the only subject format RFC 9967 §2.1 permits: "SCIM
// Events MUST use the 'sub_id' claim [RFC 9493] to identify the subject", with
// "format" set to "scim" and the resource's relative path in "uri".
const scimSubjectFormat = "scim"

// registerScimValidators adds the RFC 9967 pack to r and returns r so
// BuiltinRegistry keeps chaining.
func registerScimValidators(r *Registry) *Registry {
	return r.
		Register(scimFeedAddEventUri, ValidatorFunc(validateScimFeedAdd)).
		Register(scimFeedRemoveEventUri, ValidatorFunc(validateScimFeedRemove)).
		Register(scimCreateFullEventUri, ValidatorFunc(validateScimCreateFull)).
		Register(scimCreateNoticeEventUri, ValidatorFunc(validateScimCreateNotice)).
		Register(scimPatchFullEventUri, ValidatorFunc(validateScimPatchFull)).
		Register(scimPatchNoticeEventUri, ValidatorFunc(validateScimPatchNotice)).
		Register(scimPutFullEventUri, ValidatorFunc(validateScimPutFull)).
		Register(scimPutNoticeEventUri, ValidatorFunc(validateScimPutNotice)).
		Register(scimDeleteEventUri, ValidatorFunc(validateScimDelete)).
		Register(scimActivateEventUri, ValidatorFunc(validateScimActivate)).
		Register(scimDeactivateEventUri, ValidatorFunc(validateScimDeactivate)).
		Register(scimAsyncResponseEventUri, ValidatorFunc(validateScimAsyncResponse))
}

// requireScimSubject enforces the subject rule every SCIM event shares
// (RFC 9967 §2.1): the SET MUST carry a top-level sub_id whose format is "scim"
// and whose uri names the SCIM resource the event is about. Unlike RISC, an
// in-payload "subject" claim does NOT satisfy the rule — §2.1 names sub_id
// specifically and says the JWT "sub" claim is not to be used — so a payload
// carrying its own subject is treated as an unknown extra claim and the sub_id
// rule still applies.
//
// Structure is checked with pkg/subjectid, but through Kind rather than
// CanonicalKey: "scim" is not one of the formats the RFC 9493 registry defines,
// so CanonicalKey has no canonical form for it and rejects it by construction.
// The structural facts pkg/subjectid can honestly assert about a SCIM subject
// are that it is a SIMPLE subject (a complex or aliases subject identifies a
// principal, not a SCIM resource) and that it is not empty; the format and uri
// members are then checked against §2.1 directly. Using CanonicalKey as the gate
// would report every conformant SCIM event malformed.
//
// The uri is required to be a non-empty string but is NOT pattern-matched: §2.1
// gives "/Users/2b2f880af6674ac284bae9381673d462" as an example of a relative
// path without making any syntax normative, and a validator that guessed at SCIM
// endpoint naming would reject paths the RFC allows.
//
// Returns nil when the SET satisfies the rule.
func requireScimSubject(eventURI, cite string, set *goSet.SecurityEventToken) *Result {
	var sid *goSet.SubjectIdentifier
	if set != nil {
		sid = set.SubjectId
	}

	if sid == nil {
		r := malformed(eventURI, "sub_id",
			"SCIM events MUST use the top-level sub_id claim to identify the subject of the event ("+cite+")")
		return &r
	}

	if kind := subjectid.Kind(sid); kind != subjectid.KindSimple {
		r := malformed(eventURI, "sub_id",
			"sub_id MUST be a simple \"scim\" subject identifier naming one SCIM resource, "+
				"not a complex or aliases subject ("+cite+")")
		return &r
	}

	if sid.Format != scimSubjectFormat {
		detail := "sub_id format \"" + sid.Format + "\" is not \"scim\": the sub_id of a SCIM event MUST " +
			"set format to \"scim\" to indicate its members are SCIM attributes (" + cite + ")"
		if sid.Format == "" {
			detail = "sub_id declares no format: the sub_id of a SCIM event MUST set format to \"scim\" (" + cite + ")"
		}
		r := malformed(eventURI, "sub_id", detail)
		return &r
	}

	if strings.TrimSpace(sid.Uri) == "" {
		r := malformed(eventURI, "sub_id",
			"sub_id carries no uri: a \"scim\" subject identifier MUST give the SCIM relative path of "+
				"the resource, for example \"/Users/2b2f880af6674ac284bae9381673d462\" ("+cite+")")
		return &r
	}

	return nil
}

// requiredScimObject checks a REQUIRED payload claim that must be a JSON object.
func requiredScimObject(eventURI, claim, cite string, payload map[string]any) *Result {
	raw, present := payload[claim]
	if !present {
		r := malformed(eventURI, claim, claim+" is REQUIRED but absent ("+cite+")")
		return &r
	}
	if _, ok := raw.(map[string]any); !ok {
		r := malformed(eventURI, claim, claim+" MUST be a JSON object ("+cite+")")
		return &r
	}
	return nil
}

// requiredScimString checks a REQUIRED payload claim that must be a non-empty
// JSON string.
func requiredScimString(eventURI, claim, cite string, payload map[string]any) *Result {
	raw, present := payload[claim]
	if !present {
		r := malformed(eventURI, claim, claim+" is REQUIRED but absent ("+cite+")")
		return &r
	}
	value, ok := raw.(string)
	if !ok {
		r := malformed(eventURI, claim, claim+" MUST be a JSON string ("+cite+")")
		return &r
	}
	if strings.TrimSpace(value) == "" {
		r := malformed(eventURI, claim, claim+" is present but empty ("+cite+")")
		return &r
	}
	return nil
}

// optionalScimString type-checks an OPTIONAL payload string claim. An absent
// claim passes — a validator must never fail on an absent OPTIONAL or
// RECOMMENDED claim — but a present one must be a non-empty string, since every
// optional SCIM string claim exists to carry a value.
func optionalScimString(eventURI, claim, cite string, payload map[string]any) *Result {
	raw, present := payload[claim]
	if !present {
		return nil
	}
	value, ok := raw.(string)
	if !ok {
		r := malformed(eventURI, claim, claim+" MUST be a JSON string when present ("+cite+")")
		return &r
	}
	if strings.TrimSpace(value) == "" {
		r := malformed(eventURI, claim, claim+" is present but empty ("+cite+")")
		return &r
	}
	return nil
}

// optionalScimObject type-checks an OPTIONAL payload claim that must be a JSON
// object when present.
func optionalScimObject(eventURI, claim, cite string, payload map[string]any) *Result {
	raw, present := payload[claim]
	if !present {
		return nil
	}
	if _, ok := raw.(map[string]any); !ok {
		r := malformed(eventURI, claim, claim+" MUST be a JSON object when present ("+cite+")")
		return &r
	}
	return nil
}

// requiredScimAttributes checks the "attributes" claim the notice-mode
// provisioning events carry: the list of attribute names created or modified by
// the request. It must be a JSON array of non-empty strings; an empty array is
// accepted, because "nothing the receiver is entitled to see changed" is a
// meaning the notice form can legitimately carry.
func requiredScimAttributes(eventURI, cite string, payload map[string]any) *Result {
	raw, present := payload["attributes"]
	if !present {
		r := malformed(eventURI, "attributes",
			"attributes is REQUIRED in notice mode: exactly one of the payload attributes \"data\" or "+
				"\"attributes\" MUST be present ("+cite+")")
		return &r
	}
	values, ok := raw.([]any)
	if !ok {
		r := malformed(eventURI, "attributes",
			"attributes MUST be a JSON array of SCIM attribute names ("+cite+")")
		return &r
	}
	for i, item := range values {
		name, isString := item.(string)
		if !isString || strings.TrimSpace(name) == "" {
			r := malformed(eventURI, "attributes",
				"attributes member "+strconv.Itoa(i)+" is not a SCIM attribute name: every member MUST be a "+
					"non-empty JSON string ("+cite+")")
			return &r
		}
	}
	return nil
}

// exactlyOneProvisioningBody enforces RFC 9967 §2.4's shared rule for the
// create/patch/put families: "Exactly one of the payload attributes, 'data' or
// 'attributes', MUST be present." The ":full" variants carry data, the ":notice"
// variants carry attributes; a payload carrying both is ambiguous about which
// form the receiver should apply, so it is malformed either way.
//
// absent names the claim this variant must NOT carry — the other half of the
// pair, already required by the caller.
func exactlyOneProvisioningBody(eventURI, absent, cite string, payload map[string]any) *Result {
	if _, found := payload[absent]; found {
		r := malformed(eventURI, absent,
			"exactly one of the payload attributes \"data\" or \"attributes\" MUST be present, and this "+
				"event type carries the other one ("+cite+")")
		return &r
	}
	return nil
}

// validateScimProvisioningFull is the shared body of the three ":full"
// provisioning events (RFC 9967 §2.4.1–§2.4.3). Claims:
//
//	data     REQUIRED — the full JSON representation of the resource. Its members
//	         are SCIM schema attributes, which this package has no SCIM schema to
//	         check against and deliberately does not: RFC 9967 defines the SET
//	         envelope, not the resource, and unknown members must pass.
//	version  OPTIONAL — the resource's ETag version. §2.4 lists it without
//	         normative force, so an absent version never rejects.
func validateScimProvisioningFull(eventURI, cite string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireScimSubject(eventURI, "RFC 9967 §2.1", set); bad != nil {
		return *bad
	}
	if bad := requiredScimObject(eventURI, "data", cite, payload); bad != nil {
		return *bad
	}
	if bad := exactlyOneProvisioningBody(eventURI, "attributes", cite, payload); bad != nil {
		return *bad
	}
	if bad := optionalScimString(eventURI, "version", cite, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateScimProvisioningNotice is the shared body of the three ":notice"
// provisioning events (RFC 9967 §2.4.1–§2.4.3). Claims:
//
//	attributes  REQUIRED — the names of the attributes created or modified. The
//	            notice form exists so a receiver that is not entitled to the data
//	            still learns what changed.
//	version     OPTIONAL — the resource's ETag version.
func validateScimProvisioningNotice(eventURI, cite string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireScimSubject(eventURI, "RFC 9967 §2.1", set); bad != nil {
		return *bad
	}
	if bad := requiredScimAttributes(eventURI, cite, payload); bad != nil {
		return *bad
	}
	if bad := exactlyOneProvisioningBody(eventURI, "data", cite, payload); bad != nil {
		return *bad
	}
	if bad := optionalScimString(eventURI, "version", cite, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateScimFeedAdd validates the SCIM Feed Add event (RFC 9967 §2.3.1): "the
// specified resource has been added to the event feed". The event defines no
// payload attributes of its own — the resource is named by sub_id and the feed
// by the SET's aud claim — so the subject rule is the whole of the check.
func validateScimFeedAdd(eventURI string, _ map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireScimSubject(eventURI, "RFC 9967 §2.1", set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateScimFeedRemove validates the SCIM Feed Remove event
// (RFC 9967 §2.3.2): "the specified resource has been removed from the feed".
// Removal does not indicate deletion or deactivation — those are separate prov
// events — and the event defines no payload attributes of its own.
func validateScimFeedRemove(eventURI string, _ map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireScimSubject(eventURI, "RFC 9967 §2.1", set); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateScimCreateFull validates the SCIM Create (full) event
// (RFC 9967 §2.4.1) — a new resource was created and its representation is
// carried in "data".
func validateScimCreateFull(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimProvisioningFull(eventURI, "RFC 9967 §2.4.1", payload, set)
}

// validateScimCreateNotice validates the SCIM Create (notice) event
// (RFC 9967 §2.4.1) — a new resource was created and only the names of its
// populated attributes are disclosed.
func validateScimCreateNotice(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimProvisioningNotice(eventURI, "RFC 9967 §2.4.1", payload, set)
}

// validateScimPatchFull validates the SCIM Patch (full) event
// (RFC 9967 §2.4.2) — a resource was modified by a SCIM PATCH and the resulting
// representation is carried in "data".
func validateScimPatchFull(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimProvisioningFull(eventURI, "RFC 9967 §2.4.2", payload, set)
}

// validateScimPatchNotice validates the SCIM Patch (notice) event
// (RFC 9967 §2.4.2) — a resource was modified by a SCIM PATCH and only the names
// of the modified attributes are disclosed.
func validateScimPatchNotice(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimProvisioningNotice(eventURI, "RFC 9967 §2.4.2", payload, set)
}

// validateScimPutFull validates the SCIM Put (full) event (RFC 9967 §2.4.3) — a
// resource was replaced by a SCIM PUT and the resulting representation is carried
// in "data".
func validateScimPutFull(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimProvisioningFull(eventURI, "RFC 9967 §2.4.3", payload, set)
}

// validateScimPutNotice validates the SCIM Put (notice) event
// (RFC 9967 §2.4.3) — a resource was replaced by a SCIM PUT and only the names of
// the modified attributes are disclosed.
func validateScimPutNotice(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimProvisioningNotice(eventURI, "RFC 9967 §2.4.3", payload, set)
}

// validateScimDelete validates the SCIM Delete event (RFC 9967 §2.4.4): the
// resource named by sub_id was deleted. The event carries no body — there is no
// resource left to represent — so only the subject rule and the OPTIONAL version
// apply.
func validateScimDelete(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimSubjectOnly(eventURI, "RFC 9967 §2.4.4", payload, set)
}

// validateScimActivate validates the SCIM Activate event (RFC 9967 §2.4.5): the
// resource named by sub_id was activated. It carries no body.
func validateScimActivate(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimSubjectOnly(eventURI, "RFC 9967 §2.4.5", payload, set)
}

// validateScimDeactivate validates the SCIM Deactivate event
// (RFC 9967 §2.4.6): the resource named by sub_id was deactivated. It carries no
// body.
func validateScimDeactivate(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return validateScimSubjectOnly(eventURI, "RFC 9967 §2.4.6", payload, set)
}

// validateScimSubjectOnly is the shared body of the three bodyless provisioning
// events. They define no required payload attribute: the state change is fully
// described by the event type plus the subject. "version" is still type-checked
// when present, since §2.4 defines it for the family as a whole.
func validateScimSubjectOnly(eventURI, cite string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireScimSubject(eventURI, "RFC 9967 §2.1", set); bad != nil {
		return *bad
	}
	if bad := optionalScimString(eventURI, "version", cite, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}

// validateScimAsyncResponse validates the SCIM Asynchronous Response event
// (RFC 9967 §2.5): the outcome of a SCIM request the service provider accepted
// for asynchronous processing. Claims:
//
//	method    REQUIRED — the HTTP method of the original request. The value
//	          vocabulary is NOT closed here: §2.5 defines the claim as the method
//	          of the request, and a method this validator has not heard of is a
//	          value it has no standing to reject.
//	status    REQUIRED — the HTTP status of the completed request, as a JSON
//	          string ("200", "201", "400"), matching how RFC 7644 §3.12 carries
//	          status in a SCIM error response. A JSON number is the common
//	          mistake and is reported as a type failure.
//	response  OPTIONAL — the SCIM error response body, present when the request
//	          failed.
//	version   OPTIONAL — the ETag version of the resulting resource.
//	bulkId    OPTIONAL — the temporary client identifier from a bulk request.
//
// The top-level "txn" claim, which correlates the response with the request, is
// not checked here: §2.2 makes it REQUIRED only to support the asynchronous, CP,
// and replication use cases rather than for every SET, and it is a typed string
// field on the envelope that cannot carry a wrong type.
func validateScimAsyncResponse(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	const cite = "RFC 9967 §2.5"

	if bad := requireScimSubject(eventURI, "RFC 9967 §2.1", set); bad != nil {
		return *bad
	}
	if bad := requiredScimString(eventURI, "method", cite, payload); bad != nil {
		return *bad
	}
	if bad := requiredScimString(eventURI, "status", cite, payload); bad != nil {
		return *bad
	}
	if bad := optionalScimObject(eventURI, "response", cite, payload); bad != nil {
		return *bad
	}
	if bad := optionalScimString(eventURI, "version", cite, payload); bad != nil {
		return *bad
	}
	if bad := optionalScimString(eventURI, "bulkId", cite, payload); bad != nil {
		return *bad
	}
	return valid(eventURI)
}
