package authUtil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
)

// newBearerRequest builds a GET request carrying the supplied bearer token.
func newBearerRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/iat", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// TestBootstrapResolver_AcceptsMatchingSecret verifies that when
// I2SIG_BOOTSTRAP_TOKEN is set, a bearer equal to it resolves to a
// key-scope AuthContext.
func TestBootstrapResolver_AcceptsMatchingSecret(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "s3cret-bootstrap")

	ctx, status := auth.ValidateAuthorizationAny(newBearerRequest("s3cret-bootstrap"), []string{authSupport.ScopeKey})
	if status != http.StatusOK {
		t.Fatalf("expected 200 for matching bootstrap secret, got %d", status)
	}
	if ctx == nil || ctx.Eat == nil {
		t.Fatalf("expected non-nil AuthContext with Eat")
	}
	if !ctx.Eat.IsScopeMatch([]string{authSupport.ScopeKey}) {
		t.Errorf("bootstrap AuthContext must carry the key scope; roles=%v", ctx.Eat.Roles)
	}
	// The bootstrap identity must NOT carry broader capabilities.
	if ctx.Eat.IsScopeMatch([]string{authSupport.ScopeStreamAdmin}) ||
		ctx.Eat.IsScopeMatch([]string{authSupport.ScopeRoot}) {
		t.Errorf("bootstrap AuthContext must not carry admin/root; roles=%v", ctx.Eat.Roles)
	}
}

// TestBootstrapResolver_RejectsWrongSecret verifies a non-matching bearer is
// not granted key scope via the bootstrap path.
func TestBootstrapResolver_RejectsWrongSecret(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "s3cret-bootstrap")

	ctx, status := auth.ValidateAuthorizationAny(newBearerRequest("not-the-secret"), []string{authSupport.ScopeKey})
	if status == http.StatusOK && ctx != nil && ctx.Eat != nil && ctx.Eat.IsScopeMatch([]string{authSupport.ScopeKey}) {
		t.Fatalf("wrong bootstrap secret must not resolve to a key-scope context")
	}
}

// TestBootstrapResolver_UnsetFailsClosed verifies that when
// I2SIG_BOOTSTRAP_TOKEN is unset, no bearer is ever accepted via the
// bootstrap path (the anonymous door is gone).
func TestBootstrapResolver_UnsetFailsClosed(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")

	// An empty presented bearer must never match an unset secret.
	ctx, status := auth.ValidateAuthorizationAny(newBearerRequest(""), []string{authSupport.ScopeKey})
	if status == http.StatusOK {
		t.Fatalf("with bootstrap unset, an empty bearer must not be authorized; got 200")
	}
	if ctx != nil && ctx.Eat != nil && ctx.Eat.IsScopeMatch([]string{authSupport.ScopeKey}) {
		t.Fatalf("with bootstrap unset, no key-scope context may be synthesized")
	}

	// A caller presenting the empty string as its bearer must likewise not match.
	ctx2, status2 := auth.ValidateAuthorizationAny(newBearerRequest("anything"), []string{authSupport.ScopeKey})
	if status2 == http.StatusOK && ctx2 != nil && ctx2.Eat != nil && ctx2.Eat.IsScopeMatch([]string{authSupport.ScopeKey}) {
		t.Fatalf("with bootstrap unset, arbitrary bearer must not resolve to key scope")
	}
}
