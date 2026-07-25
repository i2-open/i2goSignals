package model

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
)

// TestCaepEvents_AllHaveBuiltinValidators is the drift guard between the
// supported-events catalog and the pkg/goSetValidate CAEP pack.
//
// The pack re-declares the CAEP URIs because pkg/goSetValidate may not import
// this package (its import allowlist keeps it standalone-consumable), so nothing
// but this test stops the two lists from diverging when a CAEP event type is
// added to the catalog. The dependency direction is deliberate: only this test
// file imports goSetValidate, never production code in this package.
func TestCaepEvents_AllHaveBuiltinValidators(t *testing.T) {
	registry := goSetValidate.BuiltinRegistry()

	for _, uri := range CaepEvents {
		if _, ok := registry.Lookup(uri); !ok {
			t.Errorf("CAEP event %q is advertised in the supported-events catalog but has no built-in validator", uri)
		}
	}
}
