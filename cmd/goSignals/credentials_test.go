package main

import (
    "os"
    "path/filepath"
    "runtime"
    "testing"
    "time"
)

func TestCredentialStore_SaveLoadRoundTrip(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "credentials.json")

    store := &CredentialStore{Path: path}
    sess := &Session{
        AccessToken:  "at-123",
        RefreshToken: "rt-456",
        Expiry:       time.Now().Add(time.Hour).UTC().Truncate(time.Second),
        Subject:      "user-1",
        Email:        "user@example.com",
        Scopes:       []string{"admin", "stream"},
        ClientId:     "gosignals-cli",
    }
    store.Set("https://idp.example.com", sess)
    if err := store.Save(); err != nil {
        t.Fatalf("save failed: %v", err)
    }

    // Reload from disk into a fresh store
    reloaded := &CredentialStore{Path: path}
    if err := reloaded.Load(); err != nil {
        t.Fatalf("load failed: %v", err)
    }
    got := reloaded.Get("https://idp.example.com")
    if got == nil {
        t.Fatalf("expected session for issuer, got nil")
    }
    if got.AccessToken != "at-123" || got.RefreshToken != "rt-456" {
        t.Errorf("tokens not round-tripped: %+v", got)
    }
    if got.Subject != "user-1" || got.Email != "user@example.com" {
        t.Errorf("identity not round-tripped: %+v", got)
    }
    if len(got.Scopes) != 2 || got.ClientId != "gosignals-cli" {
        t.Errorf("scopes/clientId not round-tripped: %+v", got)
    }
}

func TestCredentialStore_FileIs0600(t *testing.T) {
    if runtime.GOOS == "windows" {
        t.Skip("posix file permissions not enforced on windows")
    }
    dir := t.TempDir()
    path := filepath.Join(dir, "credentials.json")
    store := &CredentialStore{Path: path}
    store.Set("https://idp.example.com", &Session{AccessToken: "at"})
    if err := store.Save(); err != nil {
        t.Fatalf("save failed: %v", err)
    }
    info, err := os.Stat(path)
    if err != nil {
        t.Fatalf("stat failed: %v", err)
    }
    if perm := info.Mode().Perm(); perm != 0o600 {
        t.Errorf("expected credentials.json mode 0600, got %o", perm)
    }
}

func TestCredentialStore_DeleteRemovesSession(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
    store.Set("https://idp.example.com", &Session{AccessToken: "at"})
    store.Delete("https://idp.example.com")
    if store.Get("https://idp.example.com") != nil {
        t.Errorf("expected session removed after Delete")
    }
}

func TestCredentialStore_LoadMissingFileIsEmpty(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "nope.json")}
    if err := store.Load(); err != nil {
        t.Fatalf("loading a missing credentials file should not error, got %v", err)
    }
    if store.Get("anything") != nil {
        t.Errorf("expected empty store for missing file")
    }
}
