package main

import (
    "path/filepath"
    "testing"
    "time"
)

// TestServerBearer_PrefersSessionToken verifies the management-call bearer
// resolver returns the logged-in session access token when a valid session
// exists for the server's active issuer.
func TestServerBearer_PrefersSessionToken(t *testing.T) {
    dir := t.TempDir()
    g := &Globals{ConfigFile: filepath.Join(dir, "config.json")}

    store := &CredentialStore{Path: credentialsPath(g)}
    store.Set("https://idp.example.com", &Session{
        AccessToken: "session-token",
        Expiry:      time.Now().Add(time.Hour),
    })
    if err := store.Save(); err != nil {
        t.Fatalf("save store: %v", err)
    }

    server := &SsfServer{
        Alias:        "gs1",
        ActiveIssuer: "https://idp.example.com",
        ClientToken:  "legacy-client-token",
    }

    bearer, err := serverBearer(g, server)
    if err != nil {
        t.Fatalf("serverBearer error: %v", err)
    }
    if bearer != "session-token" {
        t.Errorf("expected session access token, got %q", bearer)
    }
}

// AC6: with no ActiveIssuer set, serverBearer falls back to a trusted
// logged-in realm (issuer advertised in AuthorizationServers).
func TestServerBearer_FallsBackToTrustedRealm(t *testing.T) {
    dir := t.TempDir()
    g := &Globals{ConfigFile: filepath.Join(dir, "config.json")}

    store := &CredentialStore{Path: credentialsPath(g)}
    store.Set("https://idp.example.com", &Session{
        AccessToken: "trusted-token",
        Expiry:      time.Now().Add(time.Hour),
        LoggedInAt:  time.Now(),
    })
    if err := store.Save(); err != nil {
        t.Fatalf("save store: %v", err)
    }

    server := &SsfServer{
        Alias:                "gs1",
        AuthorizationServers: []string{"https://idp.example.com"},
    }
    bearer, err := serverBearer(g, server)
    if err != nil {
        t.Fatalf("serverBearer error: %v", err)
    }
    if bearer != "trusted-token" {
        t.Errorf("expected fallback to trusted realm session token, got %q", bearer)
    }
}

// TestServerBearer_FallsBackToClientToken verifies that when there is no active
// session, the resolver falls back to a configured client token (non-interactive
// path), preserving existing behavior.
func TestServerBearer_FallsBackToClientToken(t *testing.T) {
    dir := t.TempDir()
    g := &Globals{ConfigFile: filepath.Join(dir, "config.json")}

    server := &SsfServer{Alias: "gs1", ClientToken: "legacy-client-token"}
    bearer, err := serverBearer(g, server)
    if err != nil {
        t.Fatalf("serverBearer error: %v", err)
    }
    if bearer != "legacy-client-token" {
        t.Errorf("expected fallback to client token, got %q", bearer)
    }
}
