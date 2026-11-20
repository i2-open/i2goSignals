package services

import "testing"

// TestStrictSsfEnabled is the table-driven contract for the I2SIG_STRICT_SSF
// toggle. It mirrors the truthy parsing of TxTLSSkipVerifyDefault: only
// true/1/enabled/yes (case-insensitive, trimmed) enable strict mode; unset or
// any other value is off.
func TestStrictSsfEnabled(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"true", true},
		{"TRUE", true},
		{" True ", true},
		{"1", true},
		{"enabled", true},
		{"ENABLED", true},
		{"yes", true},
		{"", false},
		{"false", false},
		{"0", false},
		{"disabled", false},
		{"off", false},
		{"no", false},
		{"strict", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv(strictSsfEnvVar, tc.raw)
			if got := StrictSsfEnabled(); got != tc.want {
				t.Fatalf("StrictSsfEnabled() with %q = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
