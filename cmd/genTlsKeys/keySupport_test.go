package main

import (
    "crypto/x509"
    "encoding/pem"
    "net/url"
    "os"
    "path/filepath"
    "testing"
)

func parseServerCert(t *testing.T, dir string) *x509.Certificate {
    t.Helper()
    certBytes, err := os.ReadFile(filepath.Join(dir, "server-cert.pem"))
    if err != nil {
        t.Fatalf("reading server cert: %v", err)
    }
    block, _ := pem.Decode(certBytes)
    if block == nil {
        t.Fatal("server cert is not valid PEM")
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        t.Fatalf("parsing server cert: %v", err)
    }
    return cert
}

func TestInitializeKeys_FreshCertCoversAllHostnames(t *testing.T) {
    dir := t.TempDir()
    t.Setenv(EnvCertDirectory, dir)

    config := GetKeyConfig()
    if err := config.InitializeKeys(); err != nil {
        t.Fatalf("InitializeKeys: %v", err)
    }

    cert := parseServerCert(t, dir)
    have := make(map[string]bool, len(cert.DNSNames))
    for _, n := range cert.DNSNames {
        have[n] = true
    }
    for _, want := range defaultServerDNSNames() {
        if !have[want] {
            t.Errorf("server cert missing DNS SAN %q", want)
        }
    }
    if len(cert.URIs) != 1 {
        t.Fatalf("expected exactly one URI SAN, got %d", len(cert.URIs))
    }
}

func TestInitializeKeys_CompleteCertLeftUntouched(t *testing.T) {
    dir := t.TempDir()
    t.Setenv(EnvCertDirectory, dir)

    config := GetKeyConfig()
    if err := config.InitializeKeys(); err != nil {
        t.Fatalf("first InitializeKeys: %v", err)
    }
    first := parseServerCert(t, dir)

    config = GetKeyConfig()
    if err := config.InitializeKeys(); err != nil {
        t.Fatalf("second InitializeKeys: %v", err)
    }
    second := parseServerCert(t, dir)

    if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
        t.Errorf("expected complete certificate to be left untouched, but it was regenerated")
    }
}

func TestCertNeedsRegeneration_AbsentCertificate(t *testing.T) {
    regen, reason := certNeedsRegeneration(nil, defaultServerDNSNames())
    if !regen {
        t.Fatalf("expected regeneration for absent certificate, got keep (%s)", reason)
    }
}

func TestCertNeedsRegeneration_CompleteCertificateKept(t *testing.T) {
    cert := &x509.Certificate{
        DNSNames: defaultServerDNSNames(),
        URIs:     []*url.URL{mustURL(t, "spiffe://cluster.i2gosignals.internal/workload/gosignals-node")},
    }
    regen, reason := certNeedsRegeneration(cert, defaultServerDNSNames())
    if regen {
        t.Fatalf("expected complete certificate to be kept, got regenerate (%s)", reason)
    }
}

func TestCertNeedsRegeneration_MissingDNSSAN(t *testing.T) {
    // A certificate generated before grafana was added to the desired set.
    legacy := []string{"goSignals1", "goSignals2", "goSsfServer",
        "scim_cluster1", "scim_cluster2", "keycloak", "localhost"}
    cert := &x509.Certificate{
        DNSNames: legacy,
        URIs:     []*url.URL{mustURL(t, "spiffe://cluster.i2gosignals.internal/workload/gosignals-node")},
    }
    regen, reason := certNeedsRegeneration(cert, defaultServerDNSNames())
    if !regen {
        t.Fatalf("expected regeneration when a required DNS SAN is missing, got keep (%s)", reason)
    }
}

func TestCertNeedsRegeneration_MissingSpiffeURI(t *testing.T) {
    cases := []struct {
        name string
        uris []*url.URL
    }{
        {"no uri san", nil},
        {"two uri sans", []*url.URL{
            mustURL(t, "spiffe://cluster.i2gosignals.internal/workload/a"),
            mustURL(t, "spiffe://cluster.i2gosignals.internal/workload/b"),
        }},
        {"non-spiffe uri", []*url.URL{mustURL(t, "https://example.com/workload")}},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            cert := &x509.Certificate{DNSNames: defaultServerDNSNames(), URIs: tc.uris}
            regen, reason := certNeedsRegeneration(cert, defaultServerDNSNames())
            if !regen {
                t.Fatalf("expected regeneration for %s, got keep (%s)", tc.name, reason)
            }
        })
    }
}

func mustURL(t *testing.T, raw string) *url.URL {
    t.Helper()
    u, err := url.Parse(raw)
    if err != nil {
        t.Fatalf("parsing %q: %v", raw, err)
    }
    return u
}
