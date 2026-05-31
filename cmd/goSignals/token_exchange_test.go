package main

import (
    "encoding/base64"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)

// makeUnsignedIDToken builds a JWT-shaped token (header.payload.sig) whose
// payload carries the given claims. The CLI only parses the payload for
// display (the access token, not the id_token, is what authorizes calls), so an
// unsigned shape is sufficient for exercising claim extraction.
func makeUnsignedIDToken(claims map[string]any) string {
    hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
    pb, _ := json.Marshal(claims)
    payload := base64.RawURLEncoding.EncodeToString(pb)
    return hdr + "." + payload + ".sig"
}

func TestExchangeCodeForSession_BuildsSessionFromTokenResponse(t *testing.T) {
    idToken := makeUnsignedIDToken(map[string]any{
        "sub":   "user-42",
        "email": "user42@example.com",
    })

    var gotForm url.Values
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = r.ParseForm()
        gotForm = r.Form
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{
            "access_token":"access-xyz",
            "refresh_token":"refresh-xyz",
            "token_type":"Bearer",
            "expires_in":3600,
            "scope":"admin stream",
            "id_token":"` + idToken + `"
        }`))
    }))
    defer ts.Close()

    sess, err := exchangeCodeForSession(exchangeRequest{
        TokenEndpoint: ts.URL,
        ClientId:      "gosignals-cli",
        Code:          "synthetic-code",
        Verifier:      "verifier-abc",
        RedirectURI:   "http://127.0.0.1:5555/callback",
    })
    if err != nil {
        t.Fatalf("exchange failed: %v", err)
    }

    // Verify it sent a proper authorization_code + PKCE request.
    if gotForm.Get("grant_type") != "authorization_code" {
        t.Errorf("expected grant_type=authorization_code, got %q", gotForm.Get("grant_type"))
    }
    if gotForm.Get("code") != "synthetic-code" || gotForm.Get("code_verifier") != "verifier-abc" {
        t.Errorf("PKCE code/verifier not sent: %v", gotForm)
    }
    if gotForm.Get("client_id") != "gosignals-cli" {
        t.Errorf("client_id not sent: %q", gotForm.Get("client_id"))
    }

    if sess.AccessToken != "access-xyz" || sess.RefreshToken != "refresh-xyz" {
        t.Errorf("tokens not populated: %+v", sess)
    }
    if sess.Subject != "user-42" || sess.Email != "user42@example.com" {
        t.Errorf("identity not extracted from id_token: %+v", sess)
    }
    if strings.Join(sess.Scopes, " ") != "admin stream" {
        t.Errorf("scopes not parsed: %v", sess.Scopes)
    }
    if sess.Expiry.IsZero() {
        t.Errorf("expiry should be set from expires_in")
    }
    if sess.ClientId != "gosignals-cli" {
        t.Errorf("clientId not recorded on session: %q", sess.ClientId)
    }
}
