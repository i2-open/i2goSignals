package main

import (
    "path/filepath"
    "testing"
    "time"
)

// AC1: Logging into two different realms produces two stored sessions; neither
// overwrites the other, and the most-recently-logged-in realm is identifiable.
func TestCredentialStore_TwoRealmsCoexist(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "credentials.json")}

    earlier := time.Now().Add(-time.Hour)
    later := time.Now()
    store.Set("https://realm-a.example.com", &Session{AccessToken: "a", LoggedInAt: earlier})
    store.Set("https://realm-b.example.com", &Session{AccessToken: "b", LoggedInAt: later})

    a := store.Get("https://realm-a.example.com")
    b := store.Get("https://realm-b.example.com")
    if a == nil || b == nil {
        t.Fatalf("expected both realm sessions to persist, got a=%v b=%v", a, b)
    }
    if a.AccessToken != "a" || b.AccessToken != "b" {
        t.Errorf("sessions overwrote each other: a=%q b=%q", a.AccessToken, b.AccessToken)
    }
    if len(store.Issuers()) != 2 {
        t.Errorf("expected 2 issuers in store, got %v", store.Issuers())
    }
}
