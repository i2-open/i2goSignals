package main

import (
    "path/filepath"
    "strings"
    "testing"
    "time"
)

// AC2: whoami lists ALL sessions and shows which server aliases trust each
// realm. renderWhoami is a pure function so we can assert its output directly.
func TestRenderWhoami_ListsAllSessionsWithTrustingServers(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "c.json")}
    store.Set("https://realm-a", &Session{
        AccessToken: "a", Subject: "alice", Email: "alice@example.com",
        Scopes: []string{"admin"}, Expiry: time.Now().Add(time.Hour), LoggedInAt: time.Now(),
    })
    store.Set("https://realm-b", &Session{
        AccessToken: "b", Subject: "bob", Scopes: []string{"stream"},
        Expiry: time.Now().Add(time.Hour), LoggedInAt: time.Now(),
    })
    servers := map[string]SsfServer{
        "gs1": {Alias: "gs1", AuthorizationServers: []string{"https://realm-a"}, ActiveIssuer: "https://realm-a"},
        "gs2": {Alias: "gs2", AuthorizationServers: []string{"https://realm-a", "https://realm-b"}, ActiveIssuer: "https://realm-b"},
    }

    out := renderWhoami(store, servers)

    for _, want := range []string{"https://realm-a", "https://realm-b", "alice@example.com", "bob", "admin", "stream"} {
        if !strings.Contains(out, want) {
            t.Errorf("whoami output missing %q:\n%s", want, out)
        }
    }
    // realm-a is trusted by gs1 and gs2; realm-b only by gs2.
    lines := strings.Split(out, "\n")
    var aLine, bLine string
    for _, l := range lines {
        if strings.Contains(l, "https://realm-a") {
            aLine = l
        }
        if strings.Contains(l, "https://realm-b") {
            bLine = l
        }
    }
    if !strings.Contains(aLine, "gs1") || !strings.Contains(aLine, "gs2") {
        t.Errorf("expected realm-a trusted by gs1+gs2, line: %q", aLine)
    }
    if strings.Contains(bLine, "gs1") || !strings.Contains(bLine, "gs2") {
        t.Errorf("expected realm-b trusted only by gs2, line: %q", bLine)
    }
}

// AC2: empty store renders a clear not-logged-in message rather than a blank.
func TestRenderWhoami_EmptyStore(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "c.json")}
    out := renderWhoami(store, map[string]SsfServer{})
    if !strings.Contains(strings.ToLower(out), "no ") {
        t.Errorf("expected an empty-state message, got %q", out)
    }
}
