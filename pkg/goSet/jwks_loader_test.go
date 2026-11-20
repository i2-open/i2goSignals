package goSet

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rsaPublicJWKS renders a minimal, standards-valid JWKS document for the public
// half of an RSA key under the given kid.
func rsaPublicJWKS(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := map[string]any{
		"keys": []map[string]any{
			{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// TestGetJwksWithClient_FetchesFreeFormUrlVerbatim locks in SSF §7.2.4's
// free-form jwks_uri rule: the JWKS loader fetches whatever URL it is handed —
// here a path that bears no relationship to any issuer identifier — and never
// derives the location from `iss`/`issuer`. A regression that coupled
// iss==jwks_uri would have to change this call site and would fail here.
func TestGetJwksWithClient_FetchesFreeFormUrlVerbatim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "free-form-key-1"
	jwksJSON := rsaPublicJWKS(t, kid, &key.PublicKey)

	// Serve the JWKS at a path deliberately unrelated to any issuer identifier.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys/over-here.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer srv.Close()

	jwks, err := GetJwksWithClient(srv.URL+"/keys/over-here.json", srv.Client())
	if err != nil {
		t.Fatalf("GetJwksWithClient on a free-form jwks_uri must succeed: %v", err)
	}

	found := false
	for _, k := range jwks.KIDs() {
		if k == kid {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("kid %q from the free-form jwks_uri was not loaded; got KIDs=%v", kid, jwks.KIDs())
	}
}
