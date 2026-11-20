package server

import (
	"sort"
	"testing"
)

// nameSet returns the set of route Names in the slice.
func nameSet(routes Routes) map[string]int {
	m := make(map[string]int, len(routes))
	for _, r := range routes {
		m[r.Name]++
	}
	return m
}

// TestRouteSplitPartitionsFullSet asserts the admin/peer split (issue #215) is a
// pure partition of getRoutes(): peerRoutes() and adminRoutes() are disjoint and
// their union is exactly getRoutes(). This guards the refactor from silently
// dropping, duplicating, or reclassifying a route.
func TestRouteSplitPartitionsFullSet(t *testing.T) {
	h := &HttpRouter{sa: &SignalsApplication{}}

	full := h.getRoutes()
	peer := h.peerRoutes()
	admin := h.adminRoutes()

	if len(peer)+len(admin) != len(full) {
		t.Fatalf("partition size mismatch: peer(%d)+admin(%d) != full(%d)",
			len(peer), len(admin), len(full))
	}

	peerNames := nameSet(peer)
	adminNames := nameSet(admin)

	// Disjoint: no route name appears in both subsets.
	for name := range peerNames {
		if _, dup := adminNames[name]; dup {
			t.Errorf("route %q appears in BOTH peer and admin subsets", name)
		}
	}

	// Union equals full: every full route is in exactly one subset, and each
	// subset only contains full routes.
	union := make(map[string]int)
	for name, c := range peerNames {
		union[name] += c
	}
	for name, c := range adminNames {
		union[name] += c
	}
	fullNames := nameSet(full)
	for name, c := range fullNames {
		if union[name] != c {
			t.Errorf("route %q: union count %d != full count %d", name, union[name], c)
		}
	}
	for name := range union {
		if _, ok := fullNames[name]; !ok {
			t.Errorf("route %q in a subset but not in getRoutes()", name)
		}
	}
}

// TestAdminRoutesMembership pins the exact admin-family membership against issue
// #215 Scope §1 so a future edit cannot quietly move an admin route into the
// always-on peer set (which the pkg/goSignalsServer wrapper would then fail to
// mount) or vice versa.
func TestAdminRoutesMembership(t *testing.T) {
	h := &HttpRouter{sa: &SignalsApplication{}}

	wantAdmin := []string{
		"StreamDelete", "ListStreamStates", "GetStreamState", "StreamGet",
		"StreamCreate", "CreateServer", "ServerList", "ServerGet", "ServerUpdate",
		"ServerDelete", "StreamReplace", "StreamPatch", "UpdateStatus", "GetStatus",
		"AddSubject", "RemoveSubject", "ReviewSubjectFilter", "CreateKey",
		"CreateKeyLegacy", "KeyStatus", "JwksIssuers", "JwksSummaries",
	}
	sort.Strings(wantAdmin)

	got := make([]string, 0)
	for name := range nameSet(h.adminRoutes()) {
		got = append(got, name)
	}
	sort.Strings(got)

	if len(got) != len(wantAdmin) {
		t.Fatalf("admin route count = %d, want %d\n got=%v\nwant=%v",
			len(got), len(wantAdmin), got, wantAdmin)
	}
	for i := range wantAdmin {
		if got[i] != wantAdmin[i] {
			t.Errorf("admin route mismatch at %d: got %q want %q", i, got[i], wantAdmin[i])
		}
	}
}

// TestPeerRoutesExcludeAdmin asserts the Q16 peer-set exclusion list (issue
// #215): the peer subset must contain the always-on routes and must NOT contain
// any admin route.
func TestPeerRoutesExcludeAdmin(t *testing.T) {
	h := &HttpRouter{sa: &SignalsApplication{}}
	peerNames := nameSet(h.peerRoutes())

	mustBePeer := []string{
		"Health", "GenerateIat", "RegisterClient", "PollEvents",
		"ReceivePushEvent", "VerificationRequest", "Introspect", "Revoke",
		"WellKnownSsfConfigurationGet", "ReceiveSstpEvent", "JwksJson",
	}
	for _, n := range mustBePeer {
		if _, ok := peerNames[n]; !ok {
			t.Errorf("peer route %q missing from peerRoutes()", n)
		}
	}

	mustNotBePeer := []string{
		"StreamCreate", "StreamDelete", "CreateServer", "CreateKey", "UpdateStatus",
		"AddSubject", "RemoveSubject", "ReviewSubjectFilter",
	}
	for _, n := range mustNotBePeer {
		if _, ok := peerNames[n]; ok {
			t.Errorf("admin route %q must NOT be in peerRoutes()", n)
		}
	}
}
