package tlsSupport

import "testing"

// Slice #69 tracer: ClusterTrustDomain must read the SPIFFE trust domain
// through envcompat so the deprecated SPIFFE_TRUST_DOMAIN still resolves
// (with a one-time WARN, asserted in envcompat's own tests), and the
// new I2SIG_SPIFFE_TRUST_DOMAIN wins when both are set.

func TestClusterTrustDomain_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_SPIFFE_TRUST_DOMAIN", "")
    t.Setenv("SPIFFE_TRUST_DOMAIN", "legacy.example.com")

    td, err := ClusterTrustDomain()
    if err != nil {
        t.Fatalf("ClusterTrustDomain returned err: %v", err)
    }
    if td.Name() != "legacy.example.com" {
        t.Errorf("trust domain = %q, want %q (deprecated SPIFFE_TRUST_DOMAIN should still work)", td.Name(), "legacy.example.com")
    }
}

func TestClusterTrustDomain_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_SPIFFE_TRUST_DOMAIN", "new.example.com")
    t.Setenv("SPIFFE_TRUST_DOMAIN", "legacy.example.com")

    td, err := ClusterTrustDomain()
    if err != nil {
        t.Fatalf("ClusterTrustDomain returned err: %v", err)
    }
    if td.Name() != "new.example.com" {
        t.Errorf("trust domain = %q, want %q (new I2SIG_SPIFFE_TRUST_DOMAIN must win)", td.Name(), "new.example.com")
    }
}
