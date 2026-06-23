package wellKnownSupport

import (
	"strings"
	"testing"
)

// TestEvaluateIssuerBinding pins the SSF §7.2.4 issuer↔discovery-location
// decision table that both the CLI `add server` and the server-side receiver
// create-stream path key off. The binding compares the metadata `issuer` to the
// location the discovery document was retrieved from; jwks_uri is FREE-FORM and
// is deliberately not an input here. On a mismatch the behavior is keyed off the
// peer's operator-declared strict posture: strict → error, flexible → warning.
func TestEvaluateIssuerBinding(t *testing.T) {
	const loc = "https://tr.example.com/issuer1"

	tests := []struct {
		name     string
		issuer   string
		location string
		strict   bool
		wantWarn bool // expect a non-empty warning string
		wantErr  bool
	}{
		// --- consistent bindings: no warn, no err, regardless of strict ---
		{"identical/flexible", loc, loc, false, false, false},
		{"identical/strict", loc, loc, true, false, false},
		{"trailing-slash-on-issuer", "https://tr.example.com/issuer1/", loc, true, false, false},
		{"trailing-slash-on-location", loc, "https://tr.example.com/issuer1/", true, false, false},
		{"host-case-insensitive", "https://TR.Example.COM/issuer1", loc, true, false, false},
		{"scheme-case-insensitive", "HTTPS://tr.example.com/issuer1", loc, true, false, false},
		{"host-only-issuer", "https://tr.example.com", "https://tr.example.com", true, false, false},

		// --- mismatches: warn when flexible, fail when strict ---
		{"different-host/flexible", "https://evil.example.com/issuer1", loc, false, true, false},
		{"different-host/strict", "https://evil.example.com/issuer1", loc, true, false, true},
		{"different-path/flexible", "https://tr.example.com/issuer2", loc, false, true, false},
		{"different-path/strict", "https://tr.example.com/issuer2", loc, true, false, true},
		{"empty-issuer/flexible", "", loc, false, true, false},
		{"empty-issuer/strict", "", loc, true, false, true},

		// --- path case IS significant (RFC 3986): a path-case difference is a mismatch ---
		{"path-case-differs/strict", "https://tr.example.com/Issuer1", loc, true, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			warn, err := EvaluateIssuerBinding(tc.issuer, tc.location, tc.strict)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for strict mismatch, got nil (warn=%q)", warn)
				}
				if warn != "" {
					t.Fatalf("strict mismatch must not return a warning string, got %q", warn)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantWarn && warn == "" {
				t.Fatalf("expected a non-empty warning for flexible mismatch, got empty")
			}
			if !tc.wantWarn && warn != "" {
				t.Fatalf("expected no warning for a consistent binding, got %q", warn)
			}
		})
	}
}

// TestIssuerMatchesLocation pins the policy-free primitive the visibility-only
// admin discover probe (i2goSignalsAdmin#241) consumes directly: it reports the
// bare §7.2.4 fact with no warn/fail decision attached. Same normalization
// contract as EvaluateIssuerBinding, but a pure bool — no strict argument, so a
// consumer with no committed StrictSsf posture never has to pass a meaningless
// strict=false to dodge an error branch.
func TestIssuerMatchesLocation(t *testing.T) {
	const loc = "https://tr.example.com/issuer1"

	tests := []struct {
		name     string
		issuer   string
		location string
		want     bool
	}{
		{"identical", loc, loc, true},
		{"trailing-slash-on-issuer", "https://tr.example.com/issuer1/", loc, true},
		{"trailing-slash-on-location", loc, "https://tr.example.com/issuer1/", true},
		{"host-case-insensitive", "https://TR.Example.COM/issuer1", loc, true},
		{"scheme-case-insensitive", "HTTPS://tr.example.com/issuer1", loc, true},
		{"host-only", "https://tr.example.com", "https://tr.example.com", true},
		{"different-host", "https://evil.example.com/issuer1", loc, false},
		{"different-path", "https://tr.example.com/issuer2", loc, false},
		{"path-case-differs", "https://tr.example.com/Issuer1", loc, false},
		{"empty-issuer", "", loc, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IssuerMatchesLocation(tc.issuer, tc.location); got != tc.want {
				t.Fatalf("IssuerMatchesLocation(%q,%q) = %v, want %v", tc.issuer, tc.location, got, tc.want)
			}
		})
	}
}

// TestIssuerBindingDetail verifies the policy-free message helper: it returns ""
// exactly on a consistent binding and a non-empty description on a mismatch,
// without ever deciding warn-vs-fail. EvaluateIssuerBinding is built on top of
// it, so this also guards the message the enforcement callers surface.
func TestIssuerBindingDetail(t *testing.T) {
	const loc = "https://tr.example.com/issuer1"

	if d := IssuerBindingDetail(loc, loc); d != "" {
		t.Fatalf("consistent binding must yield empty detail, got %q", d)
	}
	// A mismatch describes both sides and stays policy-free (no warn/fail verb).
	d := IssuerBindingDetail("https://evil.example.com/issuer1", loc)
	if d == "" {
		t.Fatal("mismatch must yield a non-empty detail string")
	}
	for _, want := range []string{"evil.example.com", "tr.example.com", "jwks_uri is free-form"} {
		if !strings.Contains(d, want) {
			t.Fatalf("detail %q missing expected substring %q", d, want)
		}
	}
	// An empty advertised issuer is itself a §7.2.4 violation; detail must say so.
	if d := IssuerBindingDetail("", loc); !strings.Contains(d, "(none advertised)") {
		t.Fatalf("empty-issuer detail must note none advertised, got %q", d)
	}
}

// TestEvaluateIssuerBinding_JwksUriIsFreeForm locks in the regression guard: the
// binding is purely iss↔issuer↔location. EvaluateIssuerBinding structurally
// cannot couple jwks_uri (it takes no jwks_uri argument), so a transmitter whose
// jwks_uri lives on an entirely different host/path than its issuer still passes
// cleanly as long as issuer == location. Nobody can "fix" this into an
// iss==jwks_uri requirement without changing this signature and failing here.
func TestEvaluateIssuerBinding_JwksUriIsFreeForm(t *testing.T) {
	// issuer == discovery location; jwks_uri (not an argument here) could be
	// anything — the binding must be clean.
	warn, err := EvaluateIssuerBinding(
		"https://tr.example.com/issuer1",
		"https://tr.example.com/issuer1",
		true,
	)
	if err != nil || warn != "" {
		t.Fatalf("a transmitter with issuer==location must bind cleanly regardless of jwks_uri; warn=%q err=%v", warn, err)
	}
}
