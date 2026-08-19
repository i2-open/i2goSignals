package model

import (
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
)

// scimEventUrnPrefix is the namespace every SCIM event type published in
// RFC 9967 shares.
const scimEventUrnPrefix = "urn:ietf:params:scim:event:"

// TestScimEvents_AllHaveBuiltinValidators is the drift guard between the
// supported-events catalog and the pkg/goSetValidate SCIM pack.
//
// The pack re-declares the SCIM URNs because pkg/goSetValidate may not import
// this package (its import allowlist keeps it standalone-consumable), so nothing
// but this test stops the two lists from diverging when a SCIM event type is
// added to the catalog. The dependency direction is deliberate: only this test
// file imports goSetValidate, never production code in this package.
//
// It also closes the loop on the RFC 9967 URN verification: the pack pins each
// of its URNs to the literal published RFC 9967 spells (see
// TestScimEventUris_MatchRfc9967), so a catalog URN that resolves to a validator
// is a catalog URN the RFC agrees with.
func TestScimEvents_AllHaveBuiltinValidators(t *testing.T) {
	registry := goSetValidate.BuiltinRegistry()

	found := 0
	// builtinEventTypes, not GetSupportedEvents: this guard asserts the compiled-in
	// SCIM pack has a validator for every URN it advertises. A catalog extension
	// (EnvEventTypesExtra, ADR 0032) deliberately has no builtin validator, so a
	// SCIM-prefixed extension set in the test runner's environment must not fail it.
	for _, uri := range builtinEventTypes() {
		if !strings.HasPrefix(uri, scimEventUrnPrefix) {
			continue
		}
		found++
		if _, ok := registry.Lookup(uri); !ok {
			t.Errorf("SCIM event %q is advertised in the supported-events catalog but has no built-in validator", uri)
		}
	}

	if found != 12 {
		t.Errorf("expected the catalog to advertise the 12 SCIM event types published in RFC 9967, found %d", found)
	}
}
