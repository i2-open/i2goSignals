package server

import (
	"reflect"
	"testing"
)

// TestPeerRouteTable_MatchesPeerRoutes (#373): every route the peer surface
// exports is the gateway's own peerRoutes() entry of the same name — same
// method, pattern and handler — and the exported set is the eight-route subset
// the seam block names.
func TestPeerRouteTable_MatchesPeerRoutes(t *testing.T) {
	sa := &SignalsApplication{}
	full := map[string]Route{}
	for _, r := range (&HttpRouter{sa: sa}).peerRoutes() {
		full[r.Name] = r
	}

	got := sa.PeerRouteTable()
	wantNames := []string{"GenerateIat", "RegisterClient", "TriggerEvent", "ReceivePushEvent",
		"VerificationRequestSSF", "JwksJson", "JwksJsonTenant", "PollEvents"}
	if len(got) != len(wantNames) {
		t.Fatalf("PeerRouteTable: got %d routes, want %d", len(got), len(wantNames))
	}
	for i, name := range wantNames {
		g := got[i]
		if g.Name != name {
			t.Fatalf("route %d: got %s, want %s", i, g.Name, name)
		}
		f, ok := full[name]
		if !ok {
			t.Fatalf("%s is not in peerRoutes()", name)
		}
		if g.Method != f.Method || g.Pattern != f.Pattern || g.IsIdQuery != f.IsIdQuery {
			t.Errorf("%s: got {%s %s %v}, peerRoutes has {%s %s %v}", name, g.Method, g.Pattern, g.IsIdQuery, f.Method, f.Pattern, f.IsIdQuery)
		}
		if reflect.ValueOf(g.HandlerFunc).Pointer() != reflect.ValueOf(f.HandlerFunc).Pointer() {
			t.Errorf("%s: handler differs from peerRoutes()", name)
		}
	}
}
