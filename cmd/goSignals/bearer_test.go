package main

import (
    "errors"
    "net/http"
    "net/http/httptest"
    "path/filepath"
    "testing"
    "time"
)

func TestResolveBearer_ReturnsValidToken(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
    store.Set("https://idp.example.com", &Session{
        AccessToken: "still-good",
        Expiry:      time.Now().Add(time.Hour),
    })

    br := &bearerResolver{store: store, tokenEndpoint: func(string) (string, error) { return "", nil }}
    tok, err := br.resolve("https://idp.example.com")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if tok != "still-good" {
        t.Errorf("expected unrefreshed valid token, got %q", tok)
    }
}

func TestResolveBearer_SilentRefreshOnExpiry(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = r.ParseForm()
        if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "rt-live" {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"access_token":"fresh-token","refresh_token":"rt-new","expires_in":3600,"token_type":"Bearer"}`))
    }))
    defer ts.Close()

    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
    store.Set("https://idp.example.com", &Session{
        AccessToken:  "expired",
        RefreshToken: "rt-live",
        Expiry:       time.Now().Add(-time.Hour),
        ClientId:     "gosignals-cli",
    })

    br := &bearerResolver{store: store, tokenEndpoint: func(string) (string, error) { return ts.URL, nil }}
    tok, err := br.resolve("https://idp.example.com")
    if err != nil {
        t.Fatalf("silent refresh failed: %v", err)
    }
    if tok != "fresh-token" {
        t.Errorf("expected refreshed access token, got %q", tok)
    }
    // The new tokens should be persisted back into the store.
    sess := store.Get("https://idp.example.com")
    if sess.AccessToken != "fresh-token" || sess.RefreshToken != "rt-new" {
        t.Errorf("refreshed session not persisted: %+v", sess)
    }
}

func TestResolveBearer_DeadRefreshInstructsRelogin(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusBadRequest)
        _, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
    }))
    defer ts.Close()

    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
    store.Set("https://idp.example.com", &Session{
        AccessToken:  "expired",
        RefreshToken: "rt-dead",
        Expiry:       time.Now().Add(-time.Hour),
    })

    br := &bearerResolver{store: store, tokenEndpoint: func(string) (string, error) { return ts.URL, nil }}
    _, err := br.resolve("https://idp.example.com")
    if err == nil {
        t.Fatal("expected error when refresh token is dead")
    }
    if !errors.Is(err, errReloginRequired) {
        t.Errorf("expected errReloginRequired sentinel, got %v", err)
    }
}

func TestResolveBearer_NoSessionInstructsLogin(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
    br := &bearerResolver{store: store, tokenEndpoint: func(string) (string, error) { return "", nil }}
    _, err := br.resolve("https://idp.example.com")
    if !errors.Is(err, errReloginRequired) {
        t.Errorf("expected errReloginRequired when no session, got %v", err)
    }
}
