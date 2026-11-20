package model

import (
	"encoding/json"
	"testing"
)

func TestIsSstpBootstrapBody(t *testing.T) {
	sstp, _ := json.Marshal(SstpPairBootstrap{
		Role:    SstpRoleResponder,
		Primary: SstpDirection{Iss: "https://a"},
		Inbound: SstpDirection{Iss: "https://b"},
	})
	if !IsSstpBootstrapBody(sstp) {
		t.Fatalf("responder bootstrap body should be discriminated as SSTP")
	}

	streamCfg := []byte(`{"iss":"https://a","aud":["https://b"],"delivery":{"method":"urn:ietf:params:SSF:1.0:delivery:push_2receiver"}}`)
	if IsSstpBootstrapBody(streamCfg) {
		t.Fatalf("StreamConfiguration body must NOT be discriminated as SSTP")
	}

	// role present but no direction objects -> not SSTP.
	if IsSstpBootstrapBody([]byte(`{"role":"responder"}`)) {
		t.Fatalf("role alone without primary/inbound must not be SSTP")
	}

	// unknown role -> not SSTP.
	if IsSstpBootstrapBody([]byte(`{"role":"gateway","primary":{}}`)) {
		t.Fatalf("unknown role must not be SSTP")
	}

	if IsSstpBootstrapBody([]byte(`not json`)) {
		t.Fatalf("malformed body must return false")
	}
}

func TestSstpModeToRouteMode(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		valid bool
	}{
		{"", RouteModePublish, true},
		{SstpModePublish, RouteModePublish, true},
		{SstpModeForward, RouteModeForward, true},
		{SstpModeImport, RouteModeImport, true},
		{"bogus", "", false},
	}
	for _, c := range cases {
		got, ok := SstpModeToRouteMode(c.in)
		if ok != c.valid {
			t.Fatalf("mode %q: valid=%v want %v", c.in, ok, c.valid)
		}
		if got != c.want {
			t.Fatalf("mode %q: got %q want %q", c.in, got, c.want)
		}
	}
}
