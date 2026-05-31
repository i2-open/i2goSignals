package main

import (
    "net/http"
    "net/http/httptest"
    "net/url"
    "testing"
    "time"
)

// TestRunLogin_EndToEndLoopback drives the full PKCE loopback flow with a
// synthetic "browser" (the openBrowser hook) that immediately redirects to the
// loopback callback with a code, and a fake token endpoint. This exercises the
// listener + callback + exchange seam without a real browser.
func TestRunLogin_EndToEndLoopback(t *testing.T) {
    // Pin the capability detection so this test deterministically exercises the
    // PKCE loopback path on any host. Without this it passes on a desktop (where
    // browserAvailable() is true) but on a headless CI runner the engine
    // auto-falls back to device-code and the loopback seam is never tested.
    origBrowser := browserAvailable
    origBind := canBindLoopback
    defer func() {
        browserAvailable = origBrowser
        canBindLoopback = origBind
    }()
    browserAvailable = func() bool { return true }
    canBindLoopback = func() bool { return true }

    idToken := makeUnsignedIDToken(map[string]any{"sub": "alice", "email": "alice@example.com"})

    token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = r.ParseForm()
        if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "the-code" {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        if r.Form.Get("code_verifier") == "" {
            t.Error("expected code_verifier in token exchange")
        }
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"access_token":"acc","refresh_token":"ref","expires_in":3600,"scope":"admin","id_token":"` + idToken + `"}`))
    }))
    defer token.Close()

    // Replace the browser opener with one that posts the synthetic code back to
    // the loopback redirect_uri, preserving the state value.
    origOpen := openBrowser
    defer func() { openBrowser = origOpen }()
    openBrowser = func(target string) error {
        u, err := url.Parse(target)
        if err != nil {
            return err
        }
        q := u.Query()
        redirect := q.Get("redirect_uri")
        state := q.Get("state")
        go func() {
            cbURL := redirect + "?code=the-code&state=" + url.QueryEscape(state)
            resp, err := http.Get(cbURL)
            if err == nil {
                _ = resp.Body.Close()
            }
        }()
        return nil
    }

    sess, err := runLogin(loginOptions{
        Issuer:   "https://idp.example.com",
        ClientId: "gosignals-cli",
        Scopes:   []string{"openid", "admin"},
        Endpoints: &oidcEndpoints{
            Authorization: "https://idp.example.com/auth",
            Token:         token.URL,
            Issuer:        "https://idp.example.com",
        },
        Timeout: 5 * time.Second,
    })
    if err != nil {
        t.Fatalf("runLogin failed: %v", err)
    }
    if sess.AccessToken != "acc" || sess.Subject != "alice" {
        t.Errorf("login did not yield expected session: %+v", sess)
    }
}
