package memory_provider

import (
    "testing"

    "github.com/i2-open/i2goSignals/pkg/authSupport"
)

// Wiring tracer (originally internal/services/stream_service_envcompat_test.go,
// slice #66). The STREAM env vars are now read in the wiring tree by
// streamServiceConfigFromEnv, which honors the deprecated undecorated names
// (with a deprecation WARN, asserted in envcompat's own tests) and lets the new
// I2SIG_STREAM_* names take precedence. The services package no longer reads the
// environment (#179).

func TestStreamServiceConfigFromEnv_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_STREAM_MIN_VERIFICATION_INTERVAL", "")
    t.Setenv("I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT", "")
    t.Setenv("MIN_VERIFICATION_INTERVAL", "42")
    t.Setenv("MAX_INACTIVITY_TIMEOUT", "84")

    cfg := streamServiceConfigFromEnv()

    if cfg.MinVerificationInterval != 42 {
        t.Errorf("MinVerificationInterval = %d, want 42 (deprecated MIN_VERIFICATION_INTERVAL should still work)", cfg.MinVerificationInterval)
    }
    if cfg.MaxInactivityTimeout != 84 {
        t.Errorf("MaxInactivityTimeout = %d, want 84 (deprecated MAX_INACTIVITY_TIMEOUT should still work)", cfg.MaxInactivityTimeout)
    }
}

func TestStreamServiceConfigFromEnv_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_STREAM_MIN_VERIFICATION_INTERVAL", "99")
    t.Setenv("I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT", "999")
    t.Setenv("MIN_VERIFICATION_INTERVAL", "42")
    t.Setenv("MAX_INACTIVITY_TIMEOUT", "84")

    cfg := streamServiceConfigFromEnv()

    if cfg.MinVerificationInterval != 99 {
        t.Errorf("MinVerificationInterval = %d, want 99 (new I2SIG_STREAM_MIN_VERIFICATION_INTERVAL must win)", cfg.MinVerificationInterval)
    }
    if cfg.MaxInactivityTimeout != 999 {
        t.Errorf("MaxInactivityTimeout = %d, want 999 (new I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT must win)", cfg.MaxInactivityTimeout)
    }
}

// These tests assert the production wiring of OAuth-server discovery. The
// envcompat aliasing (deprecated OAUTH_SERVERS still works; new
// I2SIG_AUTH_OAUTH_SERVERS takes precedence) lives in the wiring tree
// (oauthServersFromEnv) and is injected into authSupport.AuthIssuer via
// OAuthServersLookup, keeping the services package free of internal/envcompat
// (#179). Originally internal/services/key_service_oauth_servers_test.go.

func TestOAuthServersFromEnv_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", "")
    t.Setenv("OAUTH_SERVERS", "https://legacy.example.com/.well-known/openid-configuration")

    issuer := &authSupport.AuthIssuer{OAuthServersLookup: oauthServersFromEnv}
    servers := issuer.GetOAuthServers()

    if len(servers) != 1 || servers[0] != "https://legacy.example.com/.well-known/openid-configuration" {
        t.Fatalf("GetOAuthServers = %v, want one entry from deprecated OAUTH_SERVERS", servers)
    }
}

func TestOAuthServersFromEnv_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", "https://new.example.com/.well-known/openid-configuration")
    t.Setenv("OAUTH_SERVERS", "https://legacy.example.com/.well-known/openid-configuration")

    issuer := &authSupport.AuthIssuer{OAuthServersLookup: oauthServersFromEnv}
    servers := issuer.GetOAuthServers()

    if len(servers) != 1 || servers[0] != "https://new.example.com/.well-known/openid-configuration" {
        t.Fatalf("GetOAuthServers = %v, want only the new I2SIG_AUTH_OAUTH_SERVERS entry", servers)
    }
}
