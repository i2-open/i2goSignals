package goSsfServer

import (
	"net/http"
	"testing"
)

// TestSsfServerHardDeleteRouteGone confirms the goSsfServer spec-server route
// table no longer exposes any hard-delete key surface (DELETE /key or
// DELETE /jwks) and instead exposes the revoke/suspend status route. This is the
// goSsfServer half of the acceptance for community ADR 0028 / admin ADR 0013.
func TestSsfServerHardDeleteRouteGone(t *testing.T) {
	h := &HttpRouter{sa: &SsfApplication{}}
	statusFound := false
	for _, rt := range h.getRoutes() {
		if rt.Method == http.MethodDelete && (rt.Pattern == "/key/{keyName}" || rt.Pattern == "/jwks/{keyName}") {
			t.Fatalf("hard-delete route still present: %s %s", rt.Method, rt.Pattern)
		}
		if rt.Method == http.MethodPost && rt.Pattern == "/key/{keyName}/status" {
			statusFound = true
		}
	}
	if !statusFound {
		t.Fatal("POST /key/{keyName}/status route not registered on goSsfServer")
	}
}
