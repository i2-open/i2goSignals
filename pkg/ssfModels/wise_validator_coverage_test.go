package model

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
)

// TestWiseEvents_AllHaveBuiltinValidators is the drift guard between the
// supported-events catalog and the pkg/goSetValidate WISE pack.
//
// The pack re-declares the WISE URIs because pkg/goSetValidate may not import
// this package (its import allowlist keeps it standalone-consumable), so nothing
// but this test stops the two lists from diverging when a WISE event type is
// added to the catalog. The dependency direction is deliberate: only this test
// file imports goSetValidate, never production code in this package.
//
// This guard is load-bearing beyond bookkeeping: engagement is computed by
// intersecting a stream's events_delivered with this catalog, so a WISE URI that
// is advertised without a validator resolves as Unsupported — forwarded
// unvalidated under ENFORCE, and rejected under STRICT.
func TestWiseEvents_AllHaveBuiltinValidators(t *testing.T) {
	registry := goSetValidate.BuiltinRegistry()

	for _, uri := range WiseEvents {
		if _, ok := registry.Lookup(uri); !ok {
			t.Errorf("WISE event %q is advertised in the supported-events catalog but has no built-in validator", uri)
		}
	}
}
