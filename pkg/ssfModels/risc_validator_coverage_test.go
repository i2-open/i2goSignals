package model

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
)

// TestRiscEvents_AllHaveBuiltinValidators is the drift guard between the
// supported-events catalog and the pkg/goSetValidate RISC pack.
//
// The pack re-declares the RISC URIs because pkg/goSetValidate may not import
// this package (its import allowlist keeps it standalone-consumable), so nothing
// but this test stops the two lists from diverging when a RISC event type is
// added to the catalog. The dependency direction is deliberate: only this test
// file imports goSetValidate, never production code in this package.
func TestRiscEvents_AllHaveBuiltinValidators(t *testing.T) {
	registry := goSetValidate.BuiltinRegistry()

	for _, uri := range RiscEvents {
		if _, ok := registry.Lookup(uri); !ok {
			t.Errorf("RISC event %q is advertised in the supported-events catalog but has no built-in validator", uri)
		}
	}
}
