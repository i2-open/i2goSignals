package main

import (
    "crypto/sha256"
    "encoding/base64"
    "regexp"
    "testing"
)

// RFC 7636: verifier is 43-128 chars from the unreserved set [A-Za-z0-9-._~].
var pkceVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

func TestGeneratePKCE_VerifierFormat(t *testing.T) {
    p, err := generatePKCE()
    if err != nil {
        t.Fatalf("generatePKCE error: %v", err)
    }
    if !pkceVerifierPattern.MatchString(p.Verifier) {
        t.Errorf("verifier %q does not match RFC7636 charset/length", p.Verifier)
    }
}

func TestGeneratePKCE_ChallengeIsS256OfVerifier(t *testing.T) {
    p, err := generatePKCE()
    if err != nil {
        t.Fatalf("generatePKCE error: %v", err)
    }
    if p.Method != "S256" {
        t.Errorf("expected method S256, got %q", p.Method)
    }
    sum := sha256.Sum256([]byte(p.Verifier))
    want := base64.RawURLEncoding.EncodeToString(sum[:])
    if p.Challenge != want {
        t.Errorf("challenge is not BASE64URL(SHA256(verifier)); got %q want %q", p.Challenge, want)
    }
}

func TestGeneratePKCE_VerifiersAreUnique(t *testing.T) {
    p1, _ := generatePKCE()
    p2, _ := generatePKCE()
    if p1.Verifier == p2.Verifier {
        t.Errorf("two PKCE verifiers were identical; randomness broken")
    }
}
