package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func pkcs8PEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// signedHeader signs a bench event with key and returns the JWS header after
// verifying the signature with pub.
func signedHeader(t *testing.T, key signingKey, pub crypto.PublicKey) map[string]any {
	t.Helper()
	ev := buildEvent(0, "https://bench.example.com", []string{"aud.example.com"})
	jws, err := ev.signNow(key)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Parse(jws, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return tok.Header
}

// TestEnsureIssuerKey_MintsAnyTypeAndSavesKid: on a server whose default key
// type is ES256, the first run saves the PEM and <issuer-key-file>.kid, and
// signNow signs ES256 with that kid (spec #114).
func TestEnsureIssuerKey_MintsAnyTypeAndSavesKid(t *testing.T) {
	const issuer = "https://bench.example.com"
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Key-Id", "es-kid-1")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(pkcs8PEM(t, ecKey))
	}))
	defer stub.Close()
	gs1 := &node{name: "goSignals1", hostBase: stub.URL, http: stub.Client()}
	keyFile := filepath.Join(t.TempDir(), "issuer.pem")
	o := &options{issuer: issuer, issuerKeyFile: keyFile, bootstrapToken: "boot"}

	key, err := ensureIssuerKey(gs1, o)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := os.ReadFile(keyFile + ".kid")
	if err != nil || string(kid) != "es-kid-1\n" {
		t.Fatalf("sidecar = %q, %v", kid, err)
	}
	hdr := signedHeader(t, key, &ecKey.PublicKey)
	if hdr["alg"] != "ES256" || hdr["kid"] != "es-kid-1" {
		t.Fatalf("header = %v", hdr)
	}

	// A later run reads the saved PEM and sidecar.
	stub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	again, err := ensureIssuerKey(gs1, o)
	if err != nil {
		t.Fatal(err)
	}
	hdr = signedHeader(t, again, &ecKey.PublicKey)
	if hdr["alg"] != "ES256" || hdr["kid"] != "es-kid-1" {
		t.Fatalf("reloaded header = %v", hdr)
	}
}

// TestEnsureIssuerKey_LegacyRSAPemNoSidecar: an existing RSA PEM with no
// sidecar still signs RS256 with kid = issuer.
func TestEnsureIssuerKey_LegacyRSAPemNoSidecar(t *testing.T) {
	const issuer = "cluster.scim.example.com"
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyFile := filepath.Join(t.TempDir(), "issuer.pem")
	if err := os.WriteFile(keyFile, pkcs8PEM(t, rsaKey), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/jwks/") {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer stub.Close()
	gs1 := &node{name: "goSignals1", hostBase: stub.URL, http: stub.Client()}
	o := &options{issuer: issuer, issuerKeyFile: keyFile}

	key, err := ensureIssuerKey(gs1, o)
	if err != nil {
		t.Fatal(err)
	}
	hdr := signedHeader(t, key, &rsaKey.PublicKey)
	if hdr["alg"] != "RS256" || hdr["kid"] != issuer {
		t.Fatalf("header = %v", hdr)
	}
}
