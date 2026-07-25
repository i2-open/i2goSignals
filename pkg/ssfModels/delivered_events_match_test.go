package model

import (
	"reflect"
	"strings"
	"testing"
)

// supported is a representative events_supported set spanning the three URI
// shapes goSignals actually advertises (CAEP, RISC, SCIM).
var supportedFixture = []string{
	"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
	"https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
	"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
	"urn:ietf:params:scim:event:prov:create:full",
	"urn:ietf:params:scim:event:prov:delete",
}

func TestMatchDeliveredEvents(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		supported []string
		want      []string
	}{
		{
			name:      "empty requested set returns empty",
			requested: []string{},
			supported: supportedFixture,
			want:      []string{},
		},
		{
			name:      "nil requested set returns empty",
			requested: nil,
			supported: supportedFixture,
			want:      []string{},
		},
		{
			name:      "bare star returns all supported",
			requested: []string{"*"},
			supported: supportedFixture,
			want:      supportedFixture,
		},
		{
			name:      "exact uri",
			requested: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
			supported: supportedFixture,
			want:      []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		},
		{
			name:      "case differences still match",
			requested: []string{"URN:IETF:PARAMS:SCIM:EVENT:PROV:DELETE"},
			supported: supportedFixture,
			want:      []string{"urn:ietf:params:scim:event:prov:delete"},
		},
		{
			name:      "prefix wildcard",
			requested: []string{"*/caep/event-type/session-revoked"},
			supported: supportedFixture,
			want:      []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
		},
		{
			name:      "suffix wildcard",
			requested: []string{"urn:ietf:params:scim:event:prov:*"},
			supported: supportedFixture,
			want: []string{
				"urn:ietf:params:scim:event:prov:create:full",
				"urn:ietf:params:scim:event:prov:delete",
			},
		},
		{
			name:      "embedded wildcard",
			requested: []string{"https://schemas.openid.net/secevent/*/event-type/account-disabled"},
			supported: supportedFixture,
			want:      []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		},
		{
			name:      "no match yields nil",
			requested: []string{"urn:example:nothing:matches:this"},
			supported: supportedFixture,
			want:      nil,
		},
		{
			// Not fatal here — ValidateEventPatterns is what rejects it, upstream.
			name:      "malformed pattern contributes nothing",
			requested: []string{"urn:ietf:params:scim:event:prov:[unclosed"},
			supported: supportedFixture,
			want:      nil,
		},
		{
			name: "malformed pattern skipped while siblings still match",
			requested: []string{
				"*[unclosed",
				"urn:ietf:params:scim:event:prov:delete",
			},
			supported: supportedFixture,
			want:      []string{"urn:ietf:params:scim:event:prov:delete"},
		},
		{
			name:      "multiple patterns accumulate in pattern order",
			requested: []string{"*risc*", "*caep/event-type/session-revoked"},
			supported: supportedFixture,
			want: []string{
				"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
				"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
			},
		},
		{
			name:      "empty supported set yields nil",
			requested: []string{"*caep*"},
			supported: []string{},
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchDeliveredEvents(tt.requested, tt.supported)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MatchDeliveredEvents(%v) = %v, want %v", tt.requested, got, tt.want)
			}
		})
	}
}

// An uncompilable pattern silently matches nothing, so without this gate a
// receiver's typo produces a registered stream that delivers a narrower set than
// it asked for and reports no error at all.
func TestValidateEventPatterns(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		wantErr   bool
	}{
		{name: "nil is valid", requested: nil},
		{name: "empty is valid", requested: []string{}},
		{name: "bare star is valid", requested: []string{"*"}},
		{name: "exact uri is valid", requested: []string{"urn:ietf:params:scim:event:prov:delete"}},
		{name: "wildcard is valid", requested: []string{"urn:ietf:params:scim:event:prov:*"}},
		{name: "alternation is valid", requested: []string{"*:event:(feed|sig):*"}},
		{name: "unclosed class is rejected", requested: []string{"urn:ietf:params:scim:event:prov:[typo"}, wantErr: true},
		{name: "unclosed group is rejected", requested: []string{"*:event:(feed|sig:*"}, wantErr: true},
		{name: "dangling quantifier is rejected", requested: []string{"+prov"}, wantErr: true},
		{name: "a bad pattern among good ones is still rejected", requested: []string{
			"urn:ietf:params:scim:event:prov:delete",
			"urn:[typo",
		}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEventPatterns(tt.requested)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateEventPatterns(%v) = nil, want an error", tt.requested)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateEventPatterns(%v) = %v, want nil", tt.requested, err)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "events_requested") {
				t.Errorf("error must name the field it rejects, got %q", err.Error())
			}
		})
	}
}

// The validator and the matcher must agree on what a pattern means: anything
// ValidateEventPatterns accepts has to be compilable by MatchesEventPattern, or
// a registration passes the gate and then matches nothing anyway.
func TestValidateEventPatternsAgreesWithMatcher(t *testing.T) {
	for _, pattern := range []string{"*", "*:event:(feed|sig):*", "^urn:ietf.*delete$", "[df]eed"} {
		if err := ValidateEventPatterns([]string{pattern}); err != nil {
			t.Fatalf("ValidateEventPatterns(%q) = %v, want nil", pattern, err)
		}
		// Compiles, so the matcher answers on the URI rather than on a compile
		// error: a pattern built to match this URI must return true.
		if !MatchesEventPattern(pattern, "urn:ietf:params:scim:event:feed:delete") {
			t.Errorf("MatchesEventPattern(%q, ...) = false; validator and matcher disagree", pattern)
		}
	}
}

func TestMatchesEventPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		eventUri string
		want     bool
	}{
		{name: "bare star matches anything", pattern: "*", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},
		{name: "exact match", pattern: "urn:ietf:params:scim:event:prov:delete", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},
		{name: "case-insensitive match", pattern: "URN:IETF:PARAMS:SCIM:EVENT:PROV:DELETE", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},
		{name: "prefix wildcard", pattern: "*prov:delete", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},
		{name: "suffix wildcard", pattern: "urn:ietf:params:scim:event:prov:*", eventUri: "urn:ietf:params:scim:event:prov:create:full", want: true},
		{name: "embedded wildcard", pattern: "https://schemas.openid.net/secevent/*/event-type/account-disabled", eventUri: "https://schemas.openid.net/secevent/risc/event-type/account-disabled", want: true},
		{name: "no match", pattern: "urn:example:other", eventUri: "urn:ietf:params:scim:event:prov:delete", want: false},
		{name: "empty pattern matches (unanchored search)", pattern: "", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},

		// The pattern language is a regular expression with "*" additionally
		// rewritten to ".*" — alternation, classes and anchors are live, and the
		// CLI relies on them to select a subset of the catalog in one pattern.
		{name: "alternation selects one branch", pattern: "*:event:(prov|sig):*", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},
		{name: "alternation excludes an unlisted branch", pattern: "*:event:(feed|sig):*", eventUri: "urn:ietf:params:scim:event:prov:delete", want: false},
		{name: "character class matches", pattern: "[dp]rov", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},
		{name: "start anchor matches", pattern: "^urn:ietf", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},
		{name: "start anchor rejects a non-prefix", pattern: "^https", eventUri: "urn:ietf:params:scim:event:prov:delete", want: false},
		{name: "end anchor matches", pattern: "prov:delete$", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},

		// A pattern that does not compile answers false. ValidateEventPatterns is
		// what turns that into a rejected registration; the matcher must simply
		// not panic on one.
		{name: "malformed pattern returns false", pattern: "urn:[unclosed", eventUri: "urn:ietf:params:scim:event:prov:delete", want: false},
		{name: "malformed pattern with wildcard returns false", pattern: "*[unclosed", eventUri: "urn:ietf:params:scim:event:prov:delete", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesEventPattern(tt.pattern, tt.eventUri); got != tt.want {
				t.Errorf("MatchesEventPattern(%q, %q) = %v, want %v", tt.pattern, tt.eventUri, got, tt.want)
			}
		})
	}
}
