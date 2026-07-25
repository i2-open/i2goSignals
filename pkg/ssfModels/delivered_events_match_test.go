package model

import (
	"reflect"
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
			name:      "malformed pattern is skipped not fatal",
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
		{name: "malformed pattern returns false", pattern: "urn:[unclosed", eventUri: "urn:ietf:params:scim:event:prov:delete", want: false},
		{name: "malformed pattern with wildcard returns false", pattern: "*[unclosed", eventUri: "urn:ietf:params:scim:event:prov:delete", want: false},
		{name: "empty pattern matches (unanchored search)", pattern: "", eventUri: "urn:ietf:params:scim:event:prov:delete", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesEventPattern(tt.pattern, tt.eventUri); got != tt.want {
				t.Errorf("MatchesEventPattern(%q, %q) = %v, want %v", tt.pattern, tt.eventUri, got, tt.want)
			}
		})
	}
}
