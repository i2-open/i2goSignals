package main

import (
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "time"
)

// errReloginRequired is returned by the bearer resolver when there is no usable
// session and silent refresh is impossible (no session, or a dead refresh
// token). Callers surface a clear "please run `goSignals login` again" message.
var errReloginRequired = errors.New("re-login required")

// tokenEndpointFunc resolves the OAuth token endpoint for an issuer. It is a
// function so tests can inject a fake endpoint without network discovery.
type tokenEndpointFunc func(issuer string) (string, error)

// bearerResolver presents the per-issuer session access token on management
// calls, silently refreshing it when expired and instructing re-login when the
// refresh token is dead.
type bearerResolver struct {
    store         *CredentialStore
    tokenEndpoint tokenEndpointFunc
}

// resolve returns a currently-valid access token for the issuer, refreshing if
// needed. It persists any refreshed tokens back to the credential store.
func (b *bearerResolver) resolve(issuer string) (string, error) {
    sess := b.store.Get(issuer)
    if sess == nil || sess.AccessToken == "" {
        return "", fmt.Errorf("no session for issuer %s: %w", issuer, errReloginRequired)
    }
    if !sess.Expired() {
        return sess.AccessToken, nil
    }

    if sess.RefreshToken == "" {
        return "", fmt.Errorf("session for %s has expired and has no refresh token: %w", issuer, errReloginRequired)
    }

    endpoint, err := b.tokenEndpoint(issuer)
    if err != nil {
        return "", fmt.Errorf("could not discover token endpoint for %s: %w", issuer, err)
    }

    refreshed, err := refreshSession(endpoint, sess)
    if err != nil {
        return "", fmt.Errorf("token refresh failed for %s (%v): %w", issuer, err, errReloginRequired)
    }

    b.store.Set(issuer, refreshed)
    // Best-effort persist; resolution still succeeds if the write fails.
    _ = b.store.Save()
    return refreshed.AccessToken, nil
}

// refreshSession performs an RFC6749 refresh_token grant and returns an updated
// Session. Identity claims (subject/email) are carried forward from the prior
// session since refresh responses typically omit them.
func refreshSession(tokenEndpoint string, prior *Session) (*Session, error) {
    form := url.Values{}
    form.Set("grant_type", "refresh_token")
    form.Set("refresh_token", prior.RefreshToken)
    if prior.ClientId != "" {
        form.Set("client_id", prior.ClientId)
    }

    client := getHttpClient(30 * time.Second)
    resp, err := client.PostForm(tokenEndpoint, form)
    if err != nil {
        return nil, err
    }
    defer func() { _ = resp.Body.Close() }()
    body, _ := io.ReadAll(resp.Body)
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("refresh endpoint returned %s: %s", resp.Status, string(body))
    }

    var tr tokenResponse
    if err := json.Unmarshal(body, &tr); err != nil {
        return nil, err
    }
    if tr.AccessToken == "" {
        return nil, errors.New("refresh response did not include an access_token")
    }

    updated := sessionFromTokenResponse(&tr, prior.ClientId)
    if updated.RefreshToken == "" {
        updated.RefreshToken = prior.RefreshToken
    }
    if updated.Subject == "" {
        updated.Subject = prior.Subject
    }
    if updated.Email == "" {
        updated.Email = prior.Email
    }
    if len(updated.Scopes) == 0 {
        updated.Scopes = prior.Scopes
    }
    return updated, nil
}

// revokeRefreshToken makes a best-effort RFC 7009 token revocation request for
// a session's refresh token. It is intentionally side-effect-only: any error
// (missing endpoint, no refresh token, transport failure, non-2xx response) is
// swallowed so that logout always succeeds locally even when the IdP is
// unreachable or does not support revocation.
func revokeRefreshToken(revocationEndpoint string, sess *Session) {
    if revocationEndpoint == "" || sess == nil || sess.RefreshToken == "" {
        return
    }
    form := url.Values{}
    form.Set("token", sess.RefreshToken)
    form.Set("token_type_hint", "refresh_token")
    if sess.ClientId != "" {
        form.Set("client_id", sess.ClientId)
    }
    client := getHttpClient(15 * time.Second)
    resp, err := client.PostForm(revocationEndpoint, form)
    if err != nil {
        return
    }
    _ = resp.Body.Close()
}

// serverBearer resolves the Authorization bearer to present on a management
// call for the given server. It prefers a logged-in IdP session (with silent
// refresh) keyed by the server's active issuer; absent a session it falls back
// to a configured client token (non-interactive). When a session exists but
// refresh is dead, the errReloginRequired sentinel is wrapped so callers can
// surface a clear re-login instruction.
func serverBearer(g *Globals, server *SsfServer) (string, error) {
    store, err := LoadCredentialStore(g)
    if err != nil {
        return "", err
    }
    // Resolve which realm session authorizes this call: the server's active
    // issuer wins when it has a live session, else the most-recently-logged-in
    // trusted realm (last-login-wins).
    issuer := selectIssuerForServer(store, server)
    if issuer != "" {
        br := &bearerResolver{
            store: store,
            tokenEndpoint: func(issuer string) (string, error) {
                ep, derr := discoverEndpoints(issuer)
                if derr != nil {
                    return "", derr
                }
                return ep.Token, nil
            },
        }
        return br.resolve(issuer)
    }
    if server.ClientToken != "" {
        return server.ClientToken, nil
    }
    return "", nil
}
