package main

import (
    "net/http"
    "net/http/httptest"
    "path/filepath"
    "sort"
    "testing"
    "time"
)

// AC3: logout targeting matrix. resolveLogoutIssuers maps the (alias, issuer,
// all) inputs to the set of realm issuers to drop.
func TestResolveLogoutIssuers(t *testing.T) {
    store := &CredentialStore{Path: filepath.Join(t.TempDir(), "c.json")}
    store.Set("https://r1", &Session{AccessToken: "1"})
    store.Set("https://r2", &Session{AccessToken: "2"})
    servers := map[string]SsfServer{
        "gs1": {Alias: "gs1", ActiveIssuer: "https://r1"},
        "gs2": {Alias: "gs2", ActiveIssuer: "https://r2"},
    }

    // --all drops every stored issuer.
    got, err := resolveLogoutIssuers(store, servers, "", "", true)
    if err != nil {
        t.Fatalf("--all error: %v", err)
    }
    sort.Strings(got)
    if len(got) != 2 || got[0] != "https://r1" || got[1] != "https://r2" {
        t.Errorf("--all expected both issuers, got %v", got)
    }

    // --issuer drops exactly that realm.
    got, err = resolveLogoutIssuers(store, servers, "", "https://r1", false)
    if err != nil || len(got) != 1 || got[0] != "https://r1" {
        t.Errorf("--issuer expected [r1], got %v err=%v", got, err)
    }

    // <alias> resolves via that server's active issuer.
    got, err = resolveLogoutIssuers(store, servers, "gs2", "", false)
    if err != nil || len(got) != 1 || got[0] != "https://r2" {
        t.Errorf("alias gs2 expected [r2], got %v err=%v", got, err)
    }

    // no target at all is an error (avoid accidental全logout).
    if _, err := resolveLogoutIssuers(store, servers, "", "", false); err == nil {
        t.Errorf("expected error when no logout target specified")
    }
}

// AC4: best-effort RFC 7009 revocation. The revocation request must POST the
// refresh token with token_type_hint=refresh_token and the client_id.
func TestRevokeRefreshToken_RequestShape(t *testing.T) {
    var gotToken, gotHint, gotClient string
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = r.ParseForm()
        gotToken = r.Form.Get("token")
        gotHint = r.Form.Get("token_type_hint")
        gotClient = r.Form.Get("client_id")
        w.WriteHeader(http.StatusOK)
    }))
    defer ts.Close()

    sess := &Session{RefreshToken: "rt-xyz", ClientId: "cli-app"}
    revokeRefreshToken(ts.URL, sess)

    if gotToken != "rt-xyz" {
        t.Errorf("expected token=rt-xyz, got %q", gotToken)
    }
    if gotHint != "refresh_token" {
        t.Errorf("expected token_type_hint=refresh_token, got %q", gotHint)
    }
    if gotClient != "cli-app" {
        t.Errorf("expected client_id=cli-app, got %q", gotClient)
    }
}

// AC4: revocation is best-effort — a server error or unreachable endpoint must
// not surface as a failure (logout still succeeds).
func TestRevokeRefreshToken_BestEffortSwallowsFailure(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusInternalServerError)
    }))
    defer ts.Close()

    // Should not panic or block; failures are ignored.
    revokeRefreshToken(ts.URL, &Session{RefreshToken: "rt"})
    // Empty endpoint / no refresh token must also be no-ops.
    revokeRefreshToken("", &Session{RefreshToken: "rt"})
    revokeRefreshToken(ts.URL, &Session{})
    _ = time.Now()
}
