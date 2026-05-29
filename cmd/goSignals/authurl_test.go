package main

import (
    "net/url"
    "testing"
)

func TestBuildAuthorizationURL_CarriesPKCEAndState(t *testing.T) {
    pkce := &pkceParams{Verifier: "v", Challenge: "chal", Method: "S256"}
    raw := buildAuthorizationURL("https://idp.example.com/auth", "gosignals-cli",
        "http://127.0.0.1:5555/callback", "state-xyz", pkce, []string{"openid", "admin"})

    u, err := url.Parse(raw)
    if err != nil {
        t.Fatalf("authorization URL did not parse: %v", err)
    }
    q := u.Query()
    if q.Get("response_type") != "code" {
        t.Errorf("expected response_type=code, got %q", q.Get("response_type"))
    }
    if q.Get("code_challenge") != "chal" || q.Get("code_challenge_method") != "S256" {
        t.Errorf("PKCE challenge not in URL: %v", q)
    }
    if q.Get("state") != "state-xyz" {
        t.Errorf("state not in URL: %q", q.Get("state"))
    }
    if q.Get("client_id") != "gosignals-cli" {
        t.Errorf("client_id not in URL: %q", q.Get("client_id"))
    }
    if q.Get("redirect_uri") != "http://127.0.0.1:5555/callback" {
        t.Errorf("redirect_uri not in URL: %q", q.Get("redirect_uri"))
    }
    if q.Get("scope") != "openid admin" {
        t.Errorf("scope not joined: %q", q.Get("scope"))
    }
}
