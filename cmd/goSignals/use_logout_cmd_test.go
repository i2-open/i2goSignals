package main

import (
    "path/filepath"
    "testing"
    "time"
)

func newTestCLI(t *testing.T) *CLI {
    t.Helper()
    dir := t.TempDir()
    g := Globals{ConfigFile: filepath.Join(dir, "config.json")}
    c := &CLI{Globals: g}
    c.Data.Servers = map[string]SsfServer{}
    return c
}

// AC3: a realm logout clears the ActiveIssuer pointer on EVERY server using it.
func TestLogoutCmd_IssuerAffectsAllServers(t *testing.T) {
    c := newTestCLI(t)
    store := &CredentialStore{Path: credentialsPath(&c.Globals)}
    store.Set("https://shared", &Session{AccessToken: "tok", LoggedInAt: time.Now()})
    if err := store.Save(); err != nil {
        t.Fatalf("save store: %v", err)
    }
    c.Data.Servers["gs1"] = SsfServer{Alias: "gs1", ActiveIssuer: "https://shared", AuthorizationServers: []string{"https://shared"}}
    c.Data.Servers["gs2"] = SsfServer{Alias: "gs2", ActiveIssuer: "https://shared", AuthorizationServers: []string{"https://shared"}}

    cmd := &LogoutCmd{Issuer: "https://shared"}
    if err := cmd.Run(c); err != nil {
        t.Fatalf("logout: %v", err)
    }

    reloaded := &CredentialStore{Path: credentialsPath(&c.Globals)}
    _ = reloaded.Load()
    if reloaded.Get("https://shared") != nil {
        t.Errorf("expected shared realm session removed")
    }
    if c.Data.Servers["gs1"].ActiveIssuer != "" || c.Data.Servers["gs2"].ActiveIssuer != "" {
        t.Errorf("expected ActiveIssuer cleared on both servers, got gs1=%q gs2=%q",
            c.Data.Servers["gs1"].ActiveIssuer, c.Data.Servers["gs2"].ActiveIssuer)
    }
}

// AC3: --all drops every realm session.
func TestLogoutCmd_AllDropsEverySession(t *testing.T) {
    c := newTestCLI(t)
    store := &CredentialStore{Path: credentialsPath(&c.Globals)}
    store.Set("https://r1", &Session{AccessToken: "1"})
    store.Set("https://r2", &Session{AccessToken: "2"})
    if err := store.Save(); err != nil {
        t.Fatalf("save store: %v", err)
    }

    cmd := &LogoutCmd{All: true}
    if err := cmd.Run(c); err != nil {
        t.Fatalf("logout --all: %v", err)
    }
    reloaded := &CredentialStore{Path: credentialsPath(&c.Globals)}
    _ = reloaded.Load()
    if len(reloaded.Issuers()) != 0 {
        t.Errorf("expected all sessions dropped, got %v", reloaded.Issuers())
    }
}

// AC5: use server --issuer overrides the active issuer (last-login-wins default
// is overridable).
func TestUseServerCmd_OverridesActiveIssuer(t *testing.T) {
    c := newTestCLI(t)
    store := &CredentialStore{Path: credentialsPath(&c.Globals)}
    // Give both sessions a live expiry so serverBearer presents the stored
    // token directly (a zero Expiry is treated as "unknown -> needs refresh"
    // per GH #142, which is not what this routing test is exercising).
    store.Set("https://r1", &Session{AccessToken: "1", Expiry: time.Now().Add(time.Hour), LoggedInAt: time.Now().Add(-time.Hour)})
    store.Set("https://r2", &Session{AccessToken: "2", Expiry: time.Now().Add(time.Hour), LoggedInAt: time.Now()})
    if err := store.Save(); err != nil {
        t.Fatalf("save store: %v", err)
    }
    // Default would be r2 (most recent); override to r1.
    c.Data.Servers["gs1"] = SsfServer{Alias: "gs1", ActiveIssuer: "https://r2", AuthorizationServers: []string{"https://r1", "https://r2"}}

    cmd := &UseServerCmd{Alias: "gs1", Issuer: "https://r1"}
    if err := cmd.Run(c); err != nil {
        t.Fatalf("use server: %v", err)
    }
    if c.Data.Servers["gs1"].ActiveIssuer != "https://r1" {
        t.Errorf("expected active issuer overridden to r1, got %q", c.Data.Servers["gs1"].ActiveIssuer)
    }

    // And serverBearer should now resolve via r1.
    server := c.Data.Servers["gs1"]
    bearer, err := serverBearer(&c.Globals, &server)
    if err != nil {
        t.Fatalf("serverBearer: %v", err)
    }
    if bearer != "1" {
        t.Errorf("expected r1 token after override, got %q", bearer)
    }
}
