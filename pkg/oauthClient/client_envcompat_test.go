package oauthClient

import (
    "testing"
)

// Slice #66 tracer: configFromEnv must read STS configuration through
// envcompat so the deprecated STS_* names still configure the manager
// (with a deprecation WARN, asserted in envcompat's own tests), and the
// new I2SIG_AUTH_STS_* names take precedence when both are set.

func TestConfigFromEnv_OldStsNames_StillWork(t *testing.T) {
    t.Setenv("I2SIG_AUTH_STS_TOKEN_URL", "")
    t.Setenv("I2SIG_AUTH_STS_CLIENT_ID", "")
    t.Setenv("I2SIG_AUTH_STS_CLIENT_SECRET", "")
    t.Setenv("I2SIG_AUTH_STS_AUDIENCE", "")
    t.Setenv("I2SIG_AUTH_STS_RESOURCE", "")
    t.Setenv("I2SIG_AUTH_STS_SCOPES", "")
    t.Setenv("STS_TOKEN_URL", "https://legacy.example.com/token")
    t.Setenv("STS_CLIENT_ID", "legacy-id")
    t.Setenv("STS_CLIENT_SECRET", "legacy-secret")
    t.Setenv("STS_AUDIENCE", "legacy-aud")
    t.Setenv("STS_RESOURCE", "legacy-res")
    t.Setenv("STS_SCOPES", "scope-a scope-b")

    cfg := configFromEnv()

    if cfg.TokenURL != "https://legacy.example.com/token" {
        t.Errorf("TokenURL = %q, want legacy value", cfg.TokenURL)
    }
    if cfg.ClientID != "legacy-id" {
        t.Errorf("ClientID = %q, want legacy value", cfg.ClientID)
    }
    if cfg.ClientSecret != "legacy-secret" {
        t.Errorf("ClientSecret = %q, want legacy value", cfg.ClientSecret)
    }
    if cfg.Audience != "legacy-aud" {
        t.Errorf("Audience = %q, want legacy value", cfg.Audience)
    }
    if cfg.Resource != "legacy-res" {
        t.Errorf("Resource = %q, want legacy value", cfg.Resource)
    }
    if len(cfg.Scopes) != 2 || cfg.Scopes[0] != "scope-a" || cfg.Scopes[1] != "scope-b" {
        t.Errorf("Scopes = %v, want [scope-a scope-b]", cfg.Scopes)
    }
}

func TestConfigFromEnv_NewStsNamesTakePrecedence(t *testing.T) {
    t.Setenv("I2SIG_AUTH_STS_TOKEN_URL", "https://new.example.com/token")
    t.Setenv("I2SIG_AUTH_STS_CLIENT_ID", "new-id")
    t.Setenv("I2SIG_AUTH_STS_CLIENT_SECRET", "new-secret")
    t.Setenv("I2SIG_AUTH_STS_AUDIENCE", "new-aud")
    t.Setenv("I2SIG_AUTH_STS_RESOURCE", "new-res")
    t.Setenv("I2SIG_AUTH_STS_SCOPES", "new-scope")
    t.Setenv("STS_TOKEN_URL", "https://legacy.example.com/token")
    t.Setenv("STS_CLIENT_ID", "legacy-id")
    t.Setenv("STS_CLIENT_SECRET", "legacy-secret")
    t.Setenv("STS_AUDIENCE", "legacy-aud")
    t.Setenv("STS_RESOURCE", "legacy-res")
    t.Setenv("STS_SCOPES", "scope-a scope-b")

    cfg := configFromEnv()

    if cfg.TokenURL != "https://new.example.com/token" {
        t.Errorf("TokenURL = %q, want new value", cfg.TokenURL)
    }
    if cfg.ClientID != "new-id" {
        t.Errorf("ClientID = %q, want new value", cfg.ClientID)
    }
    if cfg.ClientSecret != "new-secret" {
        t.Errorf("ClientSecret = %q, want new value", cfg.ClientSecret)
    }
    if cfg.Audience != "new-aud" {
        t.Errorf("Audience = %q, want new value", cfg.Audience)
    }
    if cfg.Resource != "new-res" {
        t.Errorf("Resource = %q, want new value", cfg.Resource)
    }
    if len(cfg.Scopes) != 1 || cfg.Scopes[0] != "new-scope" {
        t.Errorf("Scopes = %v, want [new-scope]", cfg.Scopes)
    }
}
