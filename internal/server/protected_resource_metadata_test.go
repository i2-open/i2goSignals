package server

import (
    "testing"

    "github.com/i2-open/i2goSignals/pkg/authSupport"
)

// TestBuildProtectedResourceMetadata_AdvertisesCliClientIdAndKeyScope verifies
// that the Protected Resource Metadata advertises the recommended public CLI
// client_id and that the "key" scope is among scopes_supported (slice #122).
func TestBuildProtectedResourceMetadata_AdvertisesCliClientIdAndKeyScope(t *testing.T) {
    meta := buildProtectedResourceMetadata("https://gosignals.example.com", []string{"https://idp.example.com"}, "my-cli")

    if meta.ClientID == nil || *meta.ClientID != "my-cli" {
        t.Fatalf("expected client_id 'my-cli', got %v", meta.ClientID)
    }

    foundKey := false
    for _, s := range meta.ScopesSupported {
        if s == authSupport.ScopeKey {
            foundKey = true
        }
    }
    if !foundKey {
        t.Errorf("expected scopes_supported to include %q, got %v", authSupport.ScopeKey, meta.ScopesSupported)
    }

    if meta.Resource == nil || *meta.Resource != "https://gosignals.example.com" {
        t.Errorf("expected resource to be set to base url, got %v", meta.Resource)
    }
    if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://idp.example.com" {
        t.Errorf("expected authorization_servers to carry the configured AS, got %v", meta.AuthorizationServers)
    }
}

// TestCliClientId_DefaultsToGosignalsCli verifies the I2SIG_CLI_CLIENT_ID
// default value.
func TestCliClientId_DefaultsToGosignalsCli(t *testing.T) {
    t.Setenv("I2SIG_CLI_CLIENT_ID", "")
    if got := cliClientId(); got != "gosignals-cli" {
        t.Errorf("expected default client id 'gosignals-cli', got %q", got)
    }
    t.Setenv("I2SIG_CLI_CLIENT_ID", "custom")
    if got := cliClientId(); got != "custom" {
        t.Errorf("expected override 'custom', got %q", got)
    }
}
