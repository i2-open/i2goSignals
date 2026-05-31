package main

import (
    "path/filepath"
    "testing"
    "time"
)

// AC2 helper: a server "trusts" a realm when the issuer is among its advertised
// AuthorizationServers (falling back to its ActiveIssuer pointer).
func TestServersTrustingIssuer(t *testing.T) {
    servers := map[string]SsfServer{
        "alpha": {Alias: "alpha", AuthorizationServers: []string{"https://r1", "https://r2"}},
        "beta":  {Alias: "beta", AuthorizationServers: []string{"https://r2"}},
        "gamma": {Alias: "gamma", ActiveIssuer: "https://r3"},
    }
    got := serversTrustingIssuer(servers, "https://r2")
    if len(got) != 2 {
        t.Fatalf("expected alpha+beta to trust r2, got %v", got)
    }
    if got := serversTrustingIssuer(servers, "https://r3"); len(got) != 1 || got[0] != "gamma" {
        t.Errorf("expected gamma to trust r3 via ActiveIssuer fallback, got %v", got)
    }
    if got := serversTrustingIssuer(servers, "https://none"); len(got) != 0 {
        t.Errorf("expected no servers trust unknown issuer, got %v", got)
    }
}

// AC6: when ActiveIssuer is set and has a session, it is selected.
func TestSelectIssuerForServer_PrefersActiveIssuer(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "c.json")}
    store.Set("https://r1", &Session{AccessToken: "a1", LoggedInAt: time.Now()})
    store.Set("https://r2", &Session{AccessToken: "a2", LoggedInAt: time.Now()})
    server := &SsfServer{ActiveIssuer: "https://r1", AuthorizationServers: []string{"https://r1", "https://r2"}}
    if iss := selectIssuerForServer(store, server); iss != "https://r1" {
        t.Errorf("expected active issuer r1, got %q", iss)
    }
}

// AC6: when ActiveIssuer is empty, fall back to the most-recently-logged-in
// trusted realm.
func TestSelectIssuerForServer_FallbackMostRecent(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "c.json")}
    store.Set("https://r1", &Session{AccessToken: "a1", LoggedInAt: time.Now().Add(-time.Hour)})
    store.Set("https://r2", &Session{AccessToken: "a2", LoggedInAt: time.Now()})
    server := &SsfServer{AuthorizationServers: []string{"https://r1", "https://r2"}}
    if iss := selectIssuerForServer(store, server); iss != "https://r2" {
        t.Errorf("expected most-recent trusted realm r2, got %q", iss)
    }
}

// AC6: an ActiveIssuer with no stored session falls back to a trusted realm.
func TestSelectIssuerForServer_ActiveIssuerNoSession(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "c.json")}
    store.Set("https://r2", &Session{AccessToken: "a2", LoggedInAt: time.Now()})
    server := &SsfServer{ActiveIssuer: "https://stale", AuthorizationServers: []string{"https://r2"}}
    if iss := selectIssuerForServer(store, server); iss != "https://r2" {
        t.Errorf("expected fallback to trusted r2 when active issuer has no session, got %q", iss)
    }
}
