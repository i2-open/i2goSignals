package services

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
)

// These tests assert the production wiring of OAuth-server discovery. The
// envcompat aliasing (deprecated OAUTH_SERVERS still works; new
// I2SIG_AUTH_OAUTH_SERVERS takes precedence) now lives in the wiring tree
// (oauthServersFromEnv) and is injected into authSupport.AuthIssuer via
// OAuthServersLookup, keeping pkg/authSupport free of internal/envcompat.
// Originally internal/authUtil/auth_token_envcompat_test.go (slice #66 tracer).

func TestGetOAuthServers_OldNameStillWorks(t *testing.T) {
	t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", "")
	t.Setenv("OAUTH_SERVERS", "https://legacy.example.com/.well-known/openid-configuration")

	issuer := &authSupport.AuthIssuer{OAuthServersLookup: oauthServersFromEnv}
	servers := issuer.GetOAuthServers()

	if len(servers) != 1 || servers[0] != "https://legacy.example.com/.well-known/openid-configuration" {
		t.Fatalf("GetOAuthServers = %v, want one entry from deprecated OAUTH_SERVERS", servers)
	}
}

func TestGetOAuthServers_NewNameTakesPrecedence(t *testing.T) {
	t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", "https://new.example.com/.well-known/openid-configuration")
	t.Setenv("OAUTH_SERVERS", "https://legacy.example.com/.well-known/openid-configuration")

	issuer := &authSupport.AuthIssuer{OAuthServersLookup: oauthServersFromEnv}
	servers := issuer.GetOAuthServers()

	if len(servers) != 1 || servers[0] != "https://new.example.com/.well-known/openid-configuration" {
		t.Fatalf("GetOAuthServers = %v, want only the new I2SIG_AUTH_OAUTH_SERVERS entry", servers)
	}
}
