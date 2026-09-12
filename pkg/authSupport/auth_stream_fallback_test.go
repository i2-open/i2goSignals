package authSupport

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// TestValidateAuthorizationAny_StreamIdFallsBackToTokenBinding pins the #303
// precedence for AuthContext.StreamId: the stream the request names (stream_id
// query parameter, then mux path var) first, and only when it names none, the
// token's own stream binding — and only when that binding is exactly one real
// stream. A broad-scope token (empty StreamIds), a pair bearer (tx+rx SIDs) and
// a wildcard binding all leave StreamId empty, so the fallback can never point a
// request at a stream the token was not issued for.
func TestValidateAuthorizationAny_StreamIdFallsBackToTokenBinding(t *testing.T) {
	boundToken, err := auth.IssueStreamToken("1", "abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	pairToken, err := auth.IssueSstpPairToken("tx-1", "rx-1", "abc", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	anyToken, err := auth.IssueStreamToken(StreamAny, "abc", nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		bearer     string
		target     string
		vars       map[string]string
		wantStatus int
		wantStream string
	}{
		{name: "bound token, no parameter, resolves to its own stream", bearer: boundToken, target: "/status", wantStatus: http.StatusOK, wantStream: "1"},
		{name: "bound token, query parameter still wins", bearer: boundToken, target: "/status?stream_id=1", wantStatus: http.StatusOK, wantStream: "1"},
		{name: "bound token, path var still wins", bearer: boundToken, target: "/events/1", vars: map[string]string{"id": "1"}, wantStatus: http.StatusOK, wantStream: "1"},
		{name: "bound token naming another stream is still refused", bearer: boundToken, target: "/status?stream_id=2", wantStatus: http.StatusForbidden},
		{name: "broad-scope token, no parameter, stays unbound", bearer: testTokens.client, target: "/status", wantStatus: http.StatusOK, wantStream: ""},
		{name: "broad-scope token, parameter names the target", bearer: testTokens.client, target: "/status?stream_id=xyz", wantStatus: http.StatusOK, wantStream: "xyz"},
		{name: "pair bearer binding two SIDs does not fall back", bearer: pairToken, target: "/status", wantStatus: http.StatusOK, wantStream: ""},
		{name: "wildcard binding does not fall back", bearer: anyToken, target: "/status", wantStatus: http.StatusOK, wantStream: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com"+tt.target, nil)
			req.Header.Set("Authorization", "Bearer "+tt.bearer)
			if tt.vars != nil {
				req = mux.SetURLVars(req, tt.vars)
			}

			got, status := auth.ValidateAuthorizationAny(req, []string{ScopeEventDelivery})
			if status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", status, tt.wantStatus)
			}
			if tt.wantStatus != http.StatusOK {
				if got != nil {
					t.Fatalf("a refused request must carry no AuthContext, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("an authorized request must carry an AuthContext")
			}
			if got.StreamId != tt.wantStream {
				t.Errorf("StreamId = %q, want %q", got.StreamId, tt.wantStream)
			}
			if got.Eat == nil {
				t.Error("a local token's AuthContext must carry its EAT")
			}
		})
	}
}
