package goSetValidate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDisposition_SeverityOrdering pins the invariant the whole-SET reduction
// depends on: the constants are declared in ascending severity, so
// "worst-disposition-wins" is a max over the per-URI results.
func TestDisposition_SeverityOrdering(t *testing.T) {
	assert.Less(t, int(Valid), int(Unsupported), "Valid must be less severe than Unsupported")
	assert.Less(t, int(Unsupported), int(Malformed), "Unsupported must be less severe than Malformed")
	assert.Equal(t, 0, int(Valid), "Valid must be the zero value so a zero SetResult reads as Valid")
}

func TestDisposition_String(t *testing.T) {
	tests := []struct {
		name string
		d    Disposition
		want string
	}{
		{"valid", Valid, "valid"},
		{"unsupported", Unsupported, "unsupported"},
		{"malformed", Malformed, "malformed"},
		{"out of range", Disposition(42), "Disposition(42)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.d.String())
		})
	}
}

// TestSetResult_ZeroValueIsValid pins the ParseAndValidate degrade contract: a
// zero SetResult must read as "nothing to say", not as a rejection.
func TestSetResult_ZeroValueIsValid(t *testing.T) {
	var r SetResult
	assert.Equal(t, Valid, r.Disposition)
	assert.Nil(t, r.Results)
}
