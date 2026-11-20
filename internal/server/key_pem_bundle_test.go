package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// TestParsePemBundlePicksTheLeafByPublicKey: the certificate kept for a private
// key is the one certifying that key, whatever order the chain was
// concatenated in — here CA first, then the leaf (#318 review).
func TestParsePemBundlePicksTheLeafByPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	na := nb.Add(24 * time.Hour)
	caCert := certFor(t, caKey.Public(), nb.Add(-time.Hour), na.Add(time.Hour))
	leaf := certFor(t, key.Public(), nb, na)

	body := append(append(pkcs8PEM(t, key), caCert...), leaf...)
	b, err := parsePemBundle(body)
	if err != nil {
		t.Fatalf("CA-first bundle: %v", err)
	}
	if b.cert == nil || !key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(b.cert.PublicKey) {
		t.Fatal("the leaf kept is not the private key's certificate")
	}
	if !b.cert.NotBefore.Equal(nb) || !b.cert.NotAfter.Equal(na) {
		t.Errorf("leaf validity = %v..%v, want %v..%v", b.cert.NotBefore, b.cert.NotAfter, nb, na)
	}

	// Only non-matching certificates: refused.
	if _, err := parsePemBundle(append(pkcs8PEM(t, key), caCert...)); err == nil {
		t.Error("a bundle with no certificate for the private key was accepted")
	}
}
