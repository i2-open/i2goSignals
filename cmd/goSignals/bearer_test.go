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

// TestSession_ZeroExpiryIsExpired guards GH #142: an IdP that omits expires_in
// yields a zero Expiry. A zero Expiry means "expiry unknown", which must be
// treated as needing a refresh (Expired() == true), not as never-expiring.
func TestSession_ZeroExpiryIsExpired(t *testing.T) {
    sess := &Session{AccessToken: "at", RefreshToken: "rt"}
    if !sess.Expiry.IsZero() {
        t.Fatalf("test precondition: expected a zero Expiry")
    }
    if !sess.Expired() {
        t.Errorf("a session with a zero (unknown) Expiry should report Expired()==true so it refreshes")
    }
}

// TestResolveBearer_ZeroExpiryRefreshesWhenRefreshTokenPresent guards GH #142:
// when the session lacks a known expiry but has a refresh token, resolve() must
// attempt a refresh_token grant rather than presenting the stale access token.
func TestResolveBearer_ZeroExpiryRefreshesWhenRefreshTokenPresent(t *testing.T) {
    refreshed := false
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = r.ParseForm()
        if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "rt-live" {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        refreshed = true
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"access_token":"fresh-token","refresh_token":"rt-new","expires_in":3600,"token_type":"Bearer"}`))
    }))
    defer ts.Close()

    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
    store.Set("https://idp.example.com", &Session{
        AccessToken:  "stale-no-expiry",
        RefreshToken: "rt-live",
        // No Expiry set -> zero value -> expiry unknown.
        ClientId: "gosignals-cli",
    })

    br := &bearerResolver{store: store, tokenEndpoint: func(string) (string, error) { return ts.URL, nil }}
    tok, err := br.resolve("https://idp.example.com")
    if err != nil {
        t.Fatalf("resolve with zero-expiry + refresh token should refresh, got error: %v", err)
    }
    if !refreshed {
        t.Errorf("expected a refresh_token grant to be attempted for a zero-expiry session")
    }
    if tok != "fresh-token" {
        t.Errorf("expected refreshed access token, got %q", tok)
    }
}

// TestResolveBearer_ZeroExpiryNoRefreshTokenInstructsRelogin guards GH #142
// against a refresh storm: a session with no known expiry AND no refresh token
// must surface the relogin-required path rather than loop or silently present a
// stale token forever.
func TestResolveBearer_ZeroExpiryNoRefreshTokenInstructsRelogin(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
    store.Set("https://idp.example.com", &Session{
        AccessToken: "stale-no-expiry",
        // No RefreshToken, no Expiry.
    })

    endpointCalled := false
    br := &bearerResolver{store: store, tokenEndpoint: func(string) (string, error) {
        endpointCalled = true
        return "", nil
    }}
    _, err := br.resolve("https://idp.example.com")
    if !errors.Is(err, errReloginRequired) {
        t.Errorf("expected errReloginRequired for a zero-expiry session with no refresh token, got %v", err)
    }
    if endpointCalled {
        t.Errorf("must not attempt a refresh (no refresh token); should fall through to relogin")
    }
}
