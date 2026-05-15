package authUtil

import (
    "testing"
)

// Slice #66 tracer: GetOAuthServers must read I2SIG_AUTH_OAUTH_SERVERS
// through envcompat so the deprecated OAUTH_SERVERS still configures the
// list (with a deprecation WARN, asserted in envcompat's own tests), and
// the new name takes precedence when both are set.

func TestGetOAuthServers_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", "")
    t.Setenv("OAUTH_SERVERS", "https://legacy.example.com/.well-known/openid-configuration")

    issuer := &AuthIssuer{}
    servers := issuer.GetOAuthServers()

    if len(servers) != 1 || servers[0] != "https://legacy.example.com/.well-known/openid-configuration" {
        t.Fatalf("GetOAuthServers = %v, want one entry from deprecated OAUTH_SERVERS", servers)
    }
}

func TestGetOAuthServers_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", "https://new.example.com/.well-known/openid-configuration")
    t.Setenv("OAUTH_SERVERS", "https://legacy.example.com/.well-known/openid-configuration")

    issuer := &AuthIssuer{}
    servers := issuer.GetOAuthServers()

    if len(servers) != 1 || servers[0] != "https://new.example.com/.well-known/openid-configuration" {
        t.Fatalf("GetOAuthServers = %v, want only the new I2SIG_AUTH_OAUTH_SERVERS entry", servers)
    }
}
