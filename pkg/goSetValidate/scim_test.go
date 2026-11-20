package goSetValidate

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scimSubject builds the subject shape RFC 9967 §2.1 mandates: format "scim"
// plus the resource's SCIM relative path in uri.
func scimSubject(uri string) *goSet.SubjectIdentifier {
	return &goSet.SubjectIdentifier{
		Format:                    "scim",
		UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: uri},
	}
}

// scimSet is the well-formed envelope every SCIM table reuses — the §2.1 sub_id
// carried at the top level of the SET, exactly as the RFC's examples show it.
func scimSet() *goSet.SecurityEventToken {
	return setWithSubject(scimSubject("/Users/2b2f880af6674ac284bae9381673d462"))
}

// scimSetWithExternalId adds the OPTIONAL externalId member §2.1 allows
// alongside uri, to prove an optional subject member does not disturb the check.
func scimSetWithExternalId() *goSet.SecurityEventToken {
	sid := scimSubject("/Users/2b2f880af6674ac284bae9381673d462")
	sid.ExternalId = "jdoe"
	return setWithSubject(sid)
}

// runScimCases runs the shared validator table and additionally asserts the AC
// that a Malformed Detail names the claim that failed — a receiver operator
// reads the Detail, not the Claim field, out of a log line.
func runScimCases(t *testing.T, eventURI string, validate ValidatorFunc, cases []validatorCase) {
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

// TestScimEventUris_MatchRfc9967 is the URN verification the slice's first
// acceptance criterion asks for, expressed as a check rather than an assertion
// in prose: every SCIM event URN this pack registers is pinned here to the
// literal published RFC 9967 spells, with the section that defines it.
//
// Verification result: NO URN CHANGED between draft-ietf-scim-events-16 (which
// the repo's supported-events catalog was written from) and published RFC 9967.
// The catalog's twelve URNs are byte-identical to the RFC's, so no in-repo
// reference had to move. RFC 9967 defines no additional SCIM event type, so
// nothing was added to the catalog either.
func TestScimEventUris_MatchRfc9967(t *testing.T) {
	for _, tc := range []struct {
		section string
		uri     string
		got     string
	}{
		{"RFC 9967 §2.3.1", "urn:ietf:params:scim:event:feed:add", scimFeedAddEventUri},
		{"RFC 9967 §2.3.2", "urn:ietf:params:scim:event:feed:remove", scimFeedRemoveEventUri},
		{"RFC 9967 §2.4.1", "urn:ietf:params:scim:event:prov:create:full", scimCreateFullEventUri},
		{"RFC 9967 §2.4.1", "urn:ietf:params:scim:event:prov:create:notice", scimCreateNoticeEventUri},
		{"RFC 9967 §2.4.2", "urn:ietf:params:scim:event:prov:patch:full", scimPatchFullEventUri},
		{"RFC 9967 §2.4.2", "urn:ietf:params:scim:event:prov:patch:notice", scimPatchNoticeEventUri},
		{"RFC 9967 §2.4.3", "urn:ietf:params:scim:event:prov:put:full", scimPutFullEventUri},
		{"RFC 9967 §2.4.3", "urn:ietf:params:scim:event:prov:put:notice", scimPutNoticeEventUri},
		{"RFC 9967 §2.4.4", "urn:ietf:params:scim:event:prov:delete", scimDeleteEventUri},
		{"RFC 9967 §2.4.5", "urn:ietf:params:scim:event:prov:activate", scimActivateEventUri},
		{"RFC 9967 §2.4.6", "urn:ietf:params:scim:event:prov:deactivate", scimDeactivateEventUri},
		{"RFC 9967 §2.5", "urn:ietf:params:scim:event:misc:asyncresp", scimAsyncResponseEventUri},
	} {
		assert.Equal(t, tc.uri, tc.got, "URN must match published %s verbatim, including case", tc.section)
	}
}

// TestBuiltinRegistry_CarriesScimValidatorPack asserts every SCIM event type the
// repo advertises has a validator, and that adding the pack did not displace the
// packs already registered.
func TestBuiltinRegistry_CarriesScimValidatorPack(t *testing.T) {
	r := BuiltinRegistry()

	for _, uri := range scimEventUrisForTest() {
		_, ok := r.Lookup(uri)
		assert.True(t, ok, "no built-in validator registered for SCIM event %q", uri)
	}

	// The earlier packs must survive the chain.
	for _, uri := range []string{
		SsfVerificationEventUri,
		SsfStreamUpdatedEventUri,
		caepSessionRevokedEventUri,
		riscAccountDisabledEventUri,
	} {
		_, ok := r.Lookup(uri)
		assert.True(t, ok, "registering the SCIM pack displaced %q", uri)
	}
}

// scimEventUrisForTest is the twelve URIs the pack registers.
func scimEventUrisForTest() []string {
	return []string{
		scimFeedAddEventUri,
		scimFeedRemoveEventUri,
		scimCreateFullEventUri,
		scimCreateNoticeEventUri,
		scimPatchFullEventUri,
		scimPatchNoticeEventUri,
		scimPutFullEventUri,
		scimPutNoticeEventUri,
		scimDeleteEventUri,
		scimActivateEventUri,
		scimDeactivateEventUri,
		scimAsyncResponseEventUri,
	}
}

// scimWellFormedPayload is the minimum payload each event type needs to be
// well-formed, so the shared subject table can exercise the subject rule on all
// twelve without a per-event payload of its own.
func scimWellFormedPayload(eventURI string) map[string]any {
	switch eventURI {
	case scimCreateFullEventUri, scimPatchFullEventUri, scimPutFullEventUri:
		return map[string]any{"data": map[string]any{"userName": "jdoe"}}
	case scimCreateNoticeEventUri, scimPatchNoticeEventUri, scimPutNoticeEventUri:
		return map[string]any{"attributes": []any{"userName"}}
	case scimAsyncResponseEventUri:
		return map[string]any{"method": "PUT", "status": "200"}
	default:
		return map[string]any{}
	}
}

// TestScimSubjectRule_AppliesToEveryEventType encodes RFC 9967 §2.1 — "SCIM
// Events MUST use the 'sub_id' claim to identify the subject of events", with
// format "scim" and the resource's relative path in uri — against all twelve
// event types at once, since the rule is shared and a per-event copy would only
// hide a validator that forgot it.
func TestScimSubjectRule_AppliesToEveryEventType(t *testing.T) {
	registry := BuiltinRegistry()

	for _, uri := range scimEventUrisForTest() {
		validator, ok := registry.Lookup(uri)
		require.True(t, ok, "%s must be registered", uri)

		payload := scimWellFormedPayload(uri)

		t.Run(uri, func(t *testing.T) {
			// Positive: the RFC's own subject shape.
			assert.Equal(t, Valid, validator.Validate(uri, payload, scimSet()).Disposition,
				"a well-formed SCIM subject is valid (RFC 9967 §2.1)")

			// Positive: the OPTIONAL externalId member is allowed alongside uri.
			assert.Equal(t, Valid, validator.Validate(uri, payload, scimSetWithExternalId()).Disposition,
				"the OPTIONAL externalId member must not reject (RFC 9967 §2.1)")

			// Missing REQUIRED claim: no sub_id at all.
			missing := validator.Validate(uri, payload, setWithSubject(nil))
			assert.Equal(t, Malformed, missing.Disposition, "sub_id is REQUIRED (RFC 9967 §2.1)")
			assert.Equal(t, "sub_id", missing.Claim)
			assert.Contains(t, missing.Detail, "sub_id")

			// Wrong claim format: an RFC 9493 email subject is not a SCIM subject.
			wrongFormat := validator.Validate(uri, payload, setWithSubject(&goSet.SubjectIdentifier{
				Format:          "email",
				EmailIdentifier: goSet.EmailIdentifier{Email: "jdoe@example.com"},
			}))
			assert.Equal(t, Malformed, wrongFormat.Disposition,
				"sub_id format MUST be \"scim\" (RFC 9967 §2.1)")
			assert.Equal(t, "sub_id", wrongFormat.Claim)
			assert.Contains(t, wrongFormat.Detail, "scim")

			// The uri member is what names the resource; an empty one names nothing.
			emptyUri := validator.Validate(uri, payload, setWithSubject(scimSubject("   ")))
			assert.Equal(t, Malformed, emptyUri.Disposition,
				"a \"scim\" sub_id MUST carry the resource's relative path (RFC 9967 §2.1)")
			assert.Equal(t, "sub_id", emptyUri.Claim)

			// A complex subject identifies a principal, not a SCIM resource.
			complexSubject := validator.Validate(uri, payload, setWithSubject(&goSet.SubjectIdentifier{
				ComplexIdentifier: goSet.ComplexIdentifier{User: scimSubject("/Users/1234")},
			}))
			assert.Equal(t, Malformed, complexSubject.Disposition,
				"sub_id MUST be a simple \"scim\" subject (RFC 9967 §2.1)")
			assert.Equal(t, "sub_id", complexSubject.Claim)

			// A nil SET must report rather than panic.
			assert.Equal(t, Malformed, validator.Validate(uri, payload, nil).Disposition)
		})
	}
}

// TestValidateScimFeedEvents covers the two feed events (RFC 9967 §2.3). Neither
// defines a payload attribute — the resource is named by sub_id and the feed by
// the SET's aud claim — so an empty event object is the well-formed case.
func TestValidateScimFeedEvents(t *testing.T) {
	for _, ev := range []struct {
		uri      string
		validate ValidatorFunc
		citation string
	}{
		{scimFeedAddEventUri, validateScimFeedAdd, "RFC 9967 §2.3.1"},
		{scimFeedRemoveEventUri, validateScimFeedRemove, "RFC 9967 §2.3.2"},
	} {
		runScimCases(t, ev.uri, ev.validate, []validatorCase{
			{
				name:        "empty payload is well-formed",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{},
				want:        Valid,
				description: "the feed events carry an empty event object",
			},
			{
				name:        "unknown extra claim is allowed",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"feedName": "employees", "futureClaim": 42},
				want:        Valid,
				description: "forward compatibility: unknown claims never reject",
			},
			{
				name:        "missing required sub_id",
				citation:    "RFC 9967 §2.1",
				set:         setWithSubject(nil),
				payload:     map[string]any{},
				want:        Malformed,
				wantClaim:   "sub_id",
				description: "SCIM events MUST use sub_id to identify the subject",
			},
			{
				name:        "sub_id of the wrong format",
				citation:    "RFC 9967 §2.1",
				set:         setWithSubject(opaqueSubject("resource-1")),
				payload:     map[string]any{},
				want:        Malformed,
				wantClaim:   "sub_id",
				description: "format MUST be \"scim\"",
			},
		})
	}
}

// TestValidateScimProvisioningFullEvents covers the three ":full" provisioning
// events (RFC 9967 §2.4.1–§2.4.3): "data" is the required body and "version" is
// the optional ETag.
func TestValidateScimProvisioningFullEvents(t *testing.T) {
	for _, ev := range []struct {
		uri      string
		validate ValidatorFunc
		citation string
	}{
		{scimCreateFullEventUri, validateScimCreateFull, "RFC 9967 §2.4.1"},
		{scimPatchFullEventUri, validateScimPatchFull, "RFC 9967 §2.4.2"},
		{scimPutFullEventUri, validateScimPutFull, "RFC 9967 §2.4.3"},
	} {
		runScimCases(t, ev.uri, ev.validate, []validatorCase{
			{
				name:     "data carries the resource representation",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{"data": map[string]any{
					"schemas":  []any{"urn:ietf:params:scim:schemas:core:2.0:User"},
					"userName": "jdoe",
				}},
				want:        Valid,
				description: "the full form carries the resource in data",
			},
			{
				name:     "optional version is accepted",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{
					"data":    map[string]any{"userName": "jdoe"},
					"version": "W/\"huJj29dMNgu3WXPD\"",
				},
				want:        Valid,
				description: "version is the resource's ETag",
			},
			{
				name:        "absent optional version does not reject",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"data": map[string]any{"userName": "jdoe"}},
				want:        Valid,
				description: "an absent OPTIONAL/RECOMMENDED claim never rejects",
			},
			{
				name:     "unknown extra claim is allowed",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{
					"data":         map[string]any{"userName": "jdoe"},
					"futureClaim":  map[string]any{"anything": true},
					"anotherClaim": "ignored",
				},
				want:        Valid,
				description: "forward compatibility: unknown claims never reject",
			},
			{
				name:        "missing required data",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"version": "W/\"1\""},
				want:        Malformed,
				wantClaim:   "data",
				description: "exactly one of data or attributes MUST be present",
			},
			{
				name:        "data of the wrong type",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"data": "urn:ietf:params:scim:schemas:core:2.0:User"},
				want:        Malformed,
				wantClaim:   "data",
				description: "data MUST be a JSON object",
			},
			{
				name:     "data and attributes together",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{
					"data":       map[string]any{"userName": "jdoe"},
					"attributes": []any{"userName"},
				},
				want:        Malformed,
				wantClaim:   "attributes",
				description: "exactly one of data or attributes MUST be present, not both",
			},
			{
				name:     "version of the wrong type",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{
					"data":    map[string]any{"userName": "jdoe"},
					"version": 1,
				},
				want:        Malformed,
				wantClaim:   "version",
				description: "version is a string ETag",
			},
			{
				name:        "missing required sub_id",
				citation:    "RFC 9967 §2.1",
				set:         setWithSubject(nil),
				payload:     map[string]any{"data": map[string]any{"userName": "jdoe"}},
				want:        Malformed,
				wantClaim:   "sub_id",
				description: "SCIM events MUST use sub_id to identify the subject",
			},
		})
	}
}

// TestValidateScimProvisioningNoticeEvents covers the three ":notice"
// provisioning events (RFC 9967 §2.4.1–§2.4.3): "attributes" lists what changed
// for a receiver not entitled to the data itself.
func TestValidateScimProvisioningNoticeEvents(t *testing.T) {
	for _, ev := range []struct {
		uri      string
		validate ValidatorFunc
		citation string
	}{
		{scimCreateNoticeEventUri, validateScimCreateNotice, "RFC 9967 §2.4.1"},
		{scimPatchNoticeEventUri, validateScimPatchNotice, "RFC 9967 §2.4.2"},
		{scimPutNoticeEventUri, validateScimPutNotice, "RFC 9967 §2.4.3"},
	} {
		runScimCases(t, ev.uri, ev.validate, []validatorCase{
			{
				name:        "attributes lists the changed attribute names",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"attributes": []any{"userName", "name.familyName"}},
				want:        Valid,
				description: "the notice form discloses names only",
			},
			{
				name:     "optional version is accepted",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{
					"attributes": []any{"userName"},
					"version":    "W/\"huJj29dMNgu3WXPD\"",
				},
				want:        Valid,
				description: "version is the resource's ETag",
			},
			{
				name:        "empty attributes array is accepted",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"attributes": []any{}},
				want:        Valid,
				description: "\"nothing this receiver may see changed\" is a meaning the notice form carries",
			},
			{
				name:     "unknown extra claim is allowed",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{
					"attributes":  []any{"userName"},
					"futureClaim": true,
				},
				want:        Valid,
				description: "forward compatibility: unknown claims never reject",
			},
			{
				name:        "missing required attributes",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"version": "W/\"1\""},
				want:        Malformed,
				wantClaim:   "attributes",
				description: "exactly one of data or attributes MUST be present",
			},
			{
				name:        "attributes of the wrong type",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"attributes": "userName"},
				want:        Malformed,
				wantClaim:   "attributes",
				description: "attributes MUST be a JSON array of attribute names",
			},
			{
				name:        "attributes member of the wrong type",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"attributes": []any{"userName", 7}},
				want:        Malformed,
				wantClaim:   "attributes",
				description: "every member MUST be a non-empty attribute name",
			},
			{
				name:     "attributes and data together",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{
					"attributes": []any{"userName"},
					"data":       map[string]any{"userName": "jdoe"},
				},
				want:        Malformed,
				wantClaim:   "data",
				description: "exactly one of data or attributes MUST be present, not both",
			},
			{
				name:     "version of the wrong type",
				citation: ev.citation,
				set:      scimSet(),
				payload: map[string]any{
					"attributes": []any{"userName"},
					"version":    false,
				},
				want:        Malformed,
				wantClaim:   "version",
				description: "version is a string ETag",
			},
			{
				name:        "missing required sub_id",
				citation:    "RFC 9967 §2.1",
				set:         setWithSubject(nil),
				payload:     map[string]any{"attributes": []any{"userName"}},
				want:        Malformed,
				wantClaim:   "sub_id",
				description: "SCIM events MUST use sub_id to identify the subject",
			},
		})
	}
}

// TestValidateScimBodylessProvisioningEvents covers delete, activate and
// deactivate (RFC 9967 §2.4.4–§2.4.6). None carries a body: the state change is
// fully described by the event type plus the subject.
func TestValidateScimBodylessProvisioningEvents(t *testing.T) {
	for _, ev := range []struct {
		uri      string
		validate ValidatorFunc
		citation string
	}{
		{scimDeleteEventUri, validateScimDelete, "RFC 9967 §2.4.4"},
		{scimActivateEventUri, validateScimActivate, "RFC 9967 §2.4.5"},
		{scimDeactivateEventUri, validateScimDeactivate, "RFC 9967 §2.4.6"},
	} {
		runScimCases(t, ev.uri, ev.validate, []validatorCase{
			{
				name:        "empty payload is well-formed",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{},
				want:        Valid,
				description: "the event defines no required payload attribute",
			},
			{
				name:        "optional version is accepted",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"version": "W/\"huJj29dMNgu3WXPD\""},
				want:        Valid,
				description: "version is the resource's ETag",
			},
			{
				name:        "unknown extra claim is allowed",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"reason": "offboarding", "futureClaim": 1},
				want:        Valid,
				description: "forward compatibility: unknown claims never reject",
			},
			{
				name:        "missing required sub_id",
				citation:    "RFC 9967 §2.1",
				set:         setWithSubject(nil),
				payload:     map[string]any{},
				want:        Malformed,
				wantClaim:   "sub_id",
				description: "SCIM events MUST use sub_id to identify the subject",
			},
			{
				name:        "sub_id of the wrong format",
				citation:    "RFC 9967 §2.1",
				set:         setWithSubject(opaqueSubject("resource-1")),
				payload:     map[string]any{},
				want:        Malformed,
				wantClaim:   "sub_id",
				description: "format MUST be \"scim\"",
			},
			{
				name:        "version of the wrong type",
				citation:    ev.citation,
				set:         scimSet(),
				payload:     map[string]any{"version": []any{"W/\"1\""}},
				want:        Malformed,
				wantClaim:   "version",
				description: "version is a string ETag",
			},
		})
	}
}

// TestValidateScimAsyncResponse covers the asynchronous-response event
// (RFC 9967 §2.5): REQUIRED method and status, OPTIONAL response, version and
// bulkId.
func TestValidateScimAsyncResponse(t *testing.T) {
	const cite = "RFC 9967 §2.5"

	runScimCases(t, scimAsyncResponseEventUri, validateScimAsyncResponse, []validatorCase{
		{
			name:     "successful async response",
			citation: cite,
			set:      scimSet(),
			payload: map[string]any{
				"method":  "PUT",
				"status":  "200",
				"version": "W/\"huJj29dMNgu3WXPD\"",
			},
			want:        Valid,
			description: "the RFC's success example",
		},
		{
			name:     "error async response carries the SCIM error body",
			citation: cite,
			set:      scimSet(),
			payload: map[string]any{
				"method": "PUT",
				"status": "400",
				"response": map[string]any{
					"schemas":  []any{"urn:ietf:params:scim:api:messages:2.0:Error"},
					"scimType": "invalidSyntax",
					"detail":   "Request is unparsable",
					"status":   "400",
				},
			},
			want:        Valid,
			description: "the RFC's error example",
		},
		{
			name:        "optional bulkId is accepted",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"method": "POST", "status": "201", "bulkId": "qwerty"},
			want:        Valid,
			description: "bulkId correlates a bulk-request entry",
		},
		{
			name:        "absent optional claims do not reject",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"method": "DELETE", "status": "204"},
			want:        Valid,
			description: "an absent OPTIONAL/RECOMMENDED claim never rejects",
		},
		{
			name:     "unknown extra claim is allowed",
			citation: cite,
			set:      scimSet(),
			payload: map[string]any{
				"method":      "PATCH",
				"status":      "200",
				"futureClaim": []any{"anything"},
			},
			want:        Valid,
			description: "forward compatibility: unknown claims never reject",
		},
		{
			name:        "missing required method",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"status": "200"},
			want:        Malformed,
			wantClaim:   "method",
			description: "method names the HTTP method of the original request",
		},
		{
			name:        "missing required status",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"method": "PUT"},
			want:        Malformed,
			wantClaim:   "status",
			description: "status carries the outcome of the completed request",
		},
		{
			name:        "status of the wrong type",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"method": "PUT", "status": 200},
			want:        Malformed,
			wantClaim:   "status",
			description: "status is a JSON string, as in RFC 7644 §3.12",
		},
		{
			name:        "method of the wrong type",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"method": []any{"PUT"}, "status": "200"},
			want:        Malformed,
			wantClaim:   "method",
			description: "method is a JSON string",
		},
		{
			name:        "empty method",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"method": "  ", "status": "200"},
			want:        Malformed,
			wantClaim:   "method",
			description: "a present method must carry a value",
		},
		{
			name:        "response of the wrong type",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"method": "PUT", "status": "400", "response": "Request is unparsable"},
			want:        Malformed,
			wantClaim:   "response",
			description: "response is the SCIM error object of RFC 7644 §3.12",
		},
		{
			name:        "bulkId of the wrong type",
			citation:    cite,
			set:         scimSet(),
			payload:     map[string]any{"method": "POST", "status": "201", "bulkId": 7},
			want:        Malformed,
			wantClaim:   "bulkId",
			description: "bulkId is the client's temporary string identifier",
		},
		{
			name:        "missing required sub_id",
			citation:    "RFC 9967 §2.1",
			set:         setWithSubject(nil),
			payload:     map[string]any{"method": "PUT", "status": "200"},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "SCIM events MUST use sub_id to identify the subject",
		},
	})
}

// TestScimPack_ThroughValidatorSet proves the pack is reachable the way the
// server reaches it — engaged by URI through a ValidatorSet built on the
// built-in registry — rather than only by direct function call.
func TestScimPack_ThroughValidatorSet(t *testing.T) {
	set := scimSet()
	set.AddEventPayload(scimCreateFullEventUri, map[string]any{
		"data": map[string]any{"userName": "jdoe"},
	})

	engaged := NewValidatorSet(BuiltinRegistry(), []string{scimCreateFullEventUri})
	result := engaged.Validate(set)
	assert.Equal(t, Valid, result.Disposition)
	require.Len(t, result.Results, 1)
	assert.Equal(t, scimCreateFullEventUri, result.Results[0].EventURI)

	// A stream that never negotiated the URI reports Unsupported, not Malformed:
	// engagement is the caller's decision, not the validator's.
	notEngaged := NewValidatorSet(BuiltinRegistry(), []string{scimDeleteEventUri})
	assert.Equal(t, Unsupported, notEngaged.Validate(set).Disposition)

	// A malformed payload surfaces through the same path.
	bad := scimSet()
	bad.AddEventPayload(scimCreateFullEventUri, map[string]any{"attributes": []any{"userName"}})
	badResult := engaged.Validate(bad)
	assert.Equal(t, Malformed, badResult.Disposition)
	require.Len(t, badResult.Results, 1)
	assert.Equal(t, "data", badResult.Results[0].Claim)
}
