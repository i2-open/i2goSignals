package model

import (
	"strings"
	"testing"
)

// The SCIM async-response event URN must be the canonical all-lowercase form
// defined by draft-ietf-scim-events §2.5.1.3:
//
//	urn:ietf:params:scim:event:misc:asyncresp
//
// A camelCase "asyncResp" was advertised in events_supported and caused the
// OpenID conformance suite's OIDSSFCheckSupportedEventsForStream check to flag
// it as an unknown event type (OIDSSF-8.1.4.1, OIDCAEP-3).
func TestEventScimAsyncResp_IsCanonicalLowercase(t *testing.T) {
	const want = "urn:ietf:params:scim:event:misc:asyncresp"
	if EventScimAsyncResp != want {
		t.Errorf("EventScimAsyncResp = %q, want canonical %q", EventScimAsyncResp, want)
	}
}

// Every advertised supported event type URI must be published in canonical
// lowercase. goSignals matches event types case-insensitively internally
// (pkg/services/event_service.go uses strings.EqualFold), but the value we
// ADVERTISE in events_supported has to be the canonical lowercase form so
// conformant receivers — and the OpenID conformance suite — recognize it.
// This guards against reintroducing a camelCase URN like the asyncResp typo.
func TestGetSupportedEvents_AllCanonicalLowercase(t *testing.T) {
	// builtinEventTypes, not GetSupportedEvents: the canonical-lowercase rule binds
	// the URNs this build ships, not a catalog extension whose spelling the operator
	// chose (EnvEventTypesExtra, ADR 0032).
	for _, e := range builtinEventTypes() {
		if lower := strings.ToLower(e); e != lower {
			t.Errorf("supported event %q is not canonical lowercase (want %q)", e, lower)
		}
	}
}
