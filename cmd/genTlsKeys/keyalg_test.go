package main

// Post-quantum internal mTLS certificates (i2goSignals#278).
//
// The claim under test is narrow and concrete: with CERT_KEY_ALG=ML-DSA-65 this
// command issues an ML-DSA leaf from an ML-DSA CA, and TLS 1.3 completes a
// handshake with that chain. Go 1.27 is the first release where that is true —
// x509 gained ML-DSA signing and crypto/tls will negotiate it — so this is as
// much a check on the toolchain assumption as on the code.

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNormalizeKeyAlg_DefaultsToRSAAndRefusesGarbage(t *testing.T) {
	for _, in := range []string{"", "RSA", "rsa", " rsa "} {
		got, err := normalizeKeyAlg(in)
		if err != nil || got != KeyAlgRSA {
			t.Fatalf("normalizeKeyAlg(%q) = %q, %v; want RSA, nil", in, got, err)
		}
	}
	if got, err := normalizeKeyAlg("ml-dsa-65"); err != nil || got != KeyAlgMLDSA65 {
		t.Fatalf("normalizeKeyAlg(ml-dsa-65) = %q, %v", got, err)
	}
	// An operator who asked for post-quantum certificates and silently got RSA
	// would have no way to notice, so an unknown value is an error.
	if _, err := normalizeKeyAlg("ML-DSA-44"); err == nil {
		t.Fatal("normalizeKeyAlg must reject an unsupported algorithm rather than fall back to RSA")
	}
}

func TestInitializeKeys_DefaultRemainsRSA(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvCertDirectory, dir)

	config := GetKeyConfig()
	if err := config.InitializeKeys(); err != nil {
		t.Fatalf("InitializeKeys: %v", err)
	}

	// These certificates are trusted by every node in a deployment; changing
	// the default would invalidate every existing CA on upgrade.
	cert := parseServerCert(t, dir)
	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Fatalf("default certificate key algorithm = %v, want RSA", cert.PublicKeyAlgorithm)
	}
}

func TestInitializeKeys_MLDSALeafFromMLDSACAHandshakesOverTLS13(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvCertDirectory, dir)
	t.Setenv(EnvCertKeyAlg, KeyAlgMLDSA65)

	config := GetKeyConfig()
	if err := config.InitializeKeys(); err != nil {
		t.Fatalf("InitializeKeys: %v", err)
	}

	leaf := parseServerCert(t, dir)
	if _, ok := leaf.PublicKey.(*mldsa.PublicKey); !ok {
		t.Fatalf("leaf public key is %T, want *mldsa.PublicKey", leaf.PublicKey)
	}
	// The leaf must be SIGNED by the ML-DSA CA, not merely carry an ML-DSA key:
	// a classical signature over a PQ leaf is still classically forgeable,
	// which is the property the option exists to remove.
	if leaf.SignatureAlgorithm != x509.MLDSA65 {
		t.Fatalf("leaf signature algorithm = %v, want MLDSA65", leaf.SignatureAlgorithm)
	}

	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(config.CaCertFile)
	if err != nil {
		t.Fatalf("reading CA cert: %v", err)
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA certificate is not usable as a trust root")
	}
	caBlock, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	if _, ok := caCert.PublicKey.(*mldsa.PublicKey); !ok {
		t.Fatalf("CA public key is %T, want *mldsa.PublicKey", caCert.PublicKey)
	}

	// X509KeyPair is itself part of the claim: the PKCS#8 private-key PEM this
	// command writes for ML-DSA has to be readable by crypto/tls.
	serverCert, err := tls.LoadX509KeyPair(config.ServerCertPath, config.ServerKeyPath)
	if err != nil {
		t.Fatalf("loading ML-DSA key pair into crypto/tls: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
		ServerName: "localhost",
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("TLS 1.3 handshake with an ML-DSA chain: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version = %x, want TLS 1.3", resp.TLS.Version)
	}
}
