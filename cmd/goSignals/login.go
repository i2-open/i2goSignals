package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "runtime"
    "strings"
    "time"
)

// pkceParams carries an RFC 7636 PKCE pair for an authorization-code flow.
type pkceParams struct {
    Verifier  string
    Challenge string
    Method    string
}

// generatePKCE produces a cryptographically-random code_verifier and its
// S256 code_challenge per RFC 7636. The verifier is 43 base64url chars
// (32 random bytes), well within the 43-128 spec bounds.
func generatePKCE() (*pkceParams, error) {
    raw := make([]byte, 32)
    if _, err := rand.Read(raw); err != nil {
        return nil, err
    }
    verifier := base64.RawURLEncoding.EncodeToString(raw)
    sum := sha256.Sum256([]byte(verifier))
    challenge := base64.RawURLEncoding.EncodeToString(sum[:])
    return &pkceParams{
        Verifier:  verifier,
        Challenge: challenge,
        Method:    "S256",
    }, nil
}

// callbackResult carries the outcome of the OAuth redirect back to the
// ephemeral loopback listener.
type callbackResult struct {
    code string
    err  error
}

// loopbackCallback is the ephemeral 127.0.0.1 HTTP handler that receives the
// authorization-code redirect. It validates the CSRF state, surfaces IdP
// errors, and delivers the captured code on a channel so the login engine can
// proceed to the token exchange.
type loopbackCallback struct {
    expectedState string
    result        chan callbackResult
}

func newLoopbackCallback(expectedState string) *loopbackCallback {
    return &loopbackCallback{
        expectedState: expectedState,
        result:        make(chan callbackResult, 1),
    }
}

func (c *loopbackCallback) handler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()

    if e := q.Get("error"); e != "" {
        desc := q.Get("error_description")
        c.fail(w, fmt.Errorf("authorization failed: %s: %s", e, desc))
        return
    }

    if q.Get("state") != c.expectedState {
        c.fail(w, fmt.Errorf("state mismatch: possible CSRF, aborting login"))
        return
    }

    code := q.Get("code")
    if code == "" {
        c.fail(w, fmt.Errorf("authorization response missing code"))
        return
    }

    w.Header().Set("Content-Type", "text/html; charset=UTF-8")
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("<html><body><h3>goSignals login complete.</h3><p>You may close this window and return to the terminal.</p></body></html>"))
    c.result <- callbackResult{code: code}
}

func (c *loopbackCallback) fail(w http.ResponseWriter, err error) {
    w.Header().Set("Content-Type", "text/html; charset=UTF-8")
    w.WriteHeader(http.StatusBadRequest)
    _, _ = w.Write([]byte("<html><body><h3>goSignals login failed.</h3><p>" + err.Error() + "</p></body></html>"))
    c.result <- callbackResult{err: err}
}

// tokenResponse is the subset of the OAuth2 token endpoint response we consume.
type tokenResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    Scope        string `json:"scope"`
    IDToken      string `json:"id_token"`
}

// exchangeRequest carries the parameters for an authorization_code + PKCE token
// exchange.
type exchangeRequest struct {
    TokenEndpoint string
    ClientId      string
    Code          string
    Verifier      string
    RedirectURI   string
}

// exchangeCodeForSession performs the RFC6749/RFC7636 authorization_code grant
// (with PKCE code_verifier) at the token endpoint and builds a Session from the
// response, extracting the subject/email from the id_token when present.
func exchangeCodeForSession(req exchangeRequest) (*Session, error) {
    form := url.Values{}
    form.Set("grant_type", "authorization_code")
    form.Set("code", req.Code)
    form.Set("code_verifier", req.Verifier)
    form.Set("client_id", req.ClientId)
    form.Set("redirect_uri", req.RedirectURI)

    client := getHttpClient(30 * time.Second)
    resp, err := client.PostForm(req.TokenEndpoint, form)
    if err != nil {
        return nil, err
    }
    defer func() { _ = resp.Body.Close() }()
    body, _ := io.ReadAll(resp.Body)
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("token endpoint returned %s: %s", resp.Status, string(body))
    }

    return sessionFromTokenBody(body, req.ClientId)
}

// sessionFromTokenBody parses a successful token endpoint response body into a
// Session, validating that an access_token is present. Shared by the PKCE
// authorization_code exchange and the device-code polling loop.
func sessionFromTokenBody(body []byte, clientId string) (*Session, error) {
    var tr tokenResponse
    if err := json.Unmarshal(body, &tr); err != nil {
        return nil, fmt.Errorf("could not parse token response: %w", err)
    }
    if tr.AccessToken == "" {
        return nil, fmt.Errorf("token response did not include an access_token")
    }
    return sessionFromTokenResponse(&tr, clientId), nil
}

// sessionFromTokenResponse converts a token endpoint response into a Session.
func sessionFromTokenResponse(tr *tokenResponse, clientId string) *Session {
    sess := &Session{
        AccessToken:  tr.AccessToken,
        RefreshToken: tr.RefreshToken,
        ClientId:     clientId,
    }
    if tr.ExpiresIn > 0 {
        sess.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()
    }
    if tr.Scope != "" {
        sess.Scopes = strings.Fields(tr.Scope)
    }
    sub, email := claimsFromJWT(tr.IDToken)
    sess.Subject = sub
    sess.Email = email
    return sess
}

// claimsFromJWT extracts the sub and email claims from a JWT payload without
// verifying the signature. The CLI uses these only for display; authorization
// is enforced server-side against the access token.
func claimsFromJWT(token string) (subject, email string) {
    if token == "" {
        return "", ""
    }
    parts := strings.Split(token, ".")
    if len(parts) < 2 {
        return "", ""
    }
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return "", ""
    }
    var claims struct {
        Sub               string `json:"sub"`
        Email             string `json:"email"`
        PreferredUsername string `json:"preferred_username"`
    }
    if err := json.Unmarshal(payload, &claims); err != nil {
        return "", ""
    }
    sub := claims.Sub
    if sub == "" {
        sub = claims.PreferredUsername
    }
    return sub, claims.Email
}

// randomState returns a cryptographically-random opaque CSRF state value.
func randomState() (string, error) {
    raw := make([]byte, 24)
    if _, err := rand.Read(raw); err != nil {
        return "", err
    }
    return base64.RawURLEncoding.EncodeToString(raw), nil
}

// openBrowser is the hook used to launch the system browser at the authorization
// URL. It is a package var so tests (and headless environments) can override it.
var openBrowser = func(target string) error {
    var cmd string
    var args []string
    switch runtime.GOOS {
    case "darwin":
        cmd = "open"
    case "windows":
        cmd = "rundll32"
        args = []string{"url.dll,FileProtocolHandler"}
    default:
        cmd = "xdg-open"
    }
    args = append(args, target)
    return exec.Command(cmd, args...).Start()
}

// browserAvailable reports whether a system browser can plausibly be launched.
// On a headless host (no DISPLAY/WAYLAND on Linux, or no browser launcher on
// PATH) this returns false so the engine auto-falls back to the device-code
// flow. It is a package var so tests can override it.
var browserAvailable = func() bool {
    switch runtime.GOOS {
    case "darwin", "windows":
        // The OS-provided launcher (open / rundll32) is always present.
        return true
    default:
        // On Linux/Unix a GUI requires a display server; xdg-open is useless
        // without one (typical of SSH sessions and containers).
        if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
            return false
        }
        _, err := exec.LookPath("xdg-open")
        return err == nil
    }
}

// canBindLoopback reports whether an ephemeral 127.0.0.1 listener can be bound.
// Sandboxed containers and locked-down hosts may forbid this; in that case the
// engine auto-falls back to the device-code flow. It is a package var so tests
// can override it.
var canBindLoopback = func() bool {
    l, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        return false
    }
    _ = l.Close()
    return true
}

// loginOptions parameterize the interactive PKCE login flow.
type loginOptions struct {
    Issuer    string
    ClientId  string
    Scopes    []string
    Endpoints *oidcEndpoints
    // Timeout bounds how long we wait for the browser round-trip.
    Timeout time.Duration
    // ForceDevice forces the RFC 8628 device-code flow even when a browser and
    // loopback listener are available (the --device flag).
    ForceDevice bool
    // sleep is a test seam for the device-code polling loop; nil means
    // time.Sleep.
    sleep func(time.Duration)
}

// runLogin selects and runs the appropriate login flow. With both a browser and
// a loopback listener available (and no --device override) it runs the
// docker-login-style PKCE loopback flow. On a headless host — no browser, no
// bindable loopback listener — or when --device is given, it runs the RFC 8628
// device-code flow instead. Both paths yield an identically-shaped Session.
func runLogin(opts loginOptions) (*Session, error) {
    if opts.Endpoints == nil {
        return nil, fmt.Errorf("login requires discovered OIDC endpoints")
    }

    method := selectLoginMethod(loginCapabilities{
        ForceDevice:     opts.ForceDevice,
        CanBindLoopback: canBindLoopback(),
        CanOpenBrowser:  browserAvailable(),
    })

    if method == loginMethodDevice {
        if opts.Endpoints.DeviceAuthorization == "" {
            return nil, fmt.Errorf("device-code login required (no browser/loopback available or --device given) but issuer %s does not advertise a device_authorization_endpoint", opts.Endpoints.Issuer)
        }
        return runDeviceLogin(opts)
    }
    return runLoopbackLogin(opts)
}

// runLoopbackLogin performs the docker-login-style PKCE loopback flow: it
// generates a PKCE pair + CSRF state, starts an ephemeral 127.0.0.1 listener,
// opens the browser at the authorization endpoint, awaits the redirect, then
// exchanges the code for a session.
func runLoopbackLogin(opts loginOptions) (*Session, error) {
    pkce, err := generatePKCE()
    if err != nil {
        return nil, err
    }
    state, err := randomState()
    if err != nil {
        return nil, err
    }

    // Ephemeral loopback listener on an OS-assigned port.
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        return nil, fmt.Errorf("could not start loopback listener: %w", err)
    }
    defer func() { _ = listener.Close() }()

    redirectURI := fmt.Sprintf("http://%s/callback", listener.Addr().String())

    cb := newLoopbackCallback(state)
    mux := http.NewServeMux()
    mux.HandleFunc("/callback", cb.handler)
    srv := &http.Server{Handler: mux}
    go func() { _ = srv.Serve(listener) }()
    defer func() {
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer cancel()
        _ = srv.Shutdown(ctx)
    }()

    authURL := buildAuthorizationURL(opts.Endpoints.Authorization, opts.ClientId, redirectURI, state, pkce, opts.Scopes)

    fmt.Println("Opening browser to log in:")
    fmt.Println("  " + authURL)
    if err := openBrowser(authURL); err != nil {
        fmt.Printf("(could not open browser automatically: %v)\n", err)
        fmt.Println("Please open the URL above manually to continue.")
    }

    timeout := opts.Timeout
    if timeout == 0 {
        timeout = 3 * time.Minute
    }

    select {
    case res := <-cb.result:
        if res.err != nil {
            return nil, res.err
        }
        sess, err := exchangeCodeForSession(exchangeRequest{
            TokenEndpoint: opts.Endpoints.Token,
            ClientId:      opts.ClientId,
            Code:          res.code,
            Verifier:      pkce.Verifier,
            RedirectURI:   redirectURI,
        })
        if err != nil {
            return nil, err
        }
        return sess, nil
    case <-time.After(timeout):
        return nil, fmt.Errorf("timed out waiting for browser login after %s", timeout)
    }
}

// buildAuthorizationURL constructs the RFC6749 authorization-code request URL
// with PKCE parameters.
func buildAuthorizationURL(authEndpoint, clientId, redirectURI, state string, pkce *pkceParams, scopes []string) string {
    q := url.Values{}
    q.Set("response_type", "code")
    q.Set("client_id", clientId)
    q.Set("redirect_uri", redirectURI)
    q.Set("state", state)
    q.Set("code_challenge", pkce.Challenge)
    q.Set("code_challenge_method", pkce.Method)
    scope := "openid email profile"
    if len(scopes) > 0 {
        scope = strings.Join(scopes, " ")
    }
    q.Set("scope", scope)

    sep := "?"
    if strings.Contains(authEndpoint, "?") {
        sep = "&"
    }
    return authEndpoint + sep + q.Encode()
}

// LoginCmd performs an interactive docker-login-style PKCE login against the
// IdP advertised by the server's Protected Resource Metadata, storing the
// resulting session in credentials.json (keyed by issuer).
type LoginCmd struct {
    Alias    string `arg:"" help:"The alias of the server to log in to."`
    Issuer   string `optional:"" help:"Override the OAuth issuer (when multiple are advertised)."`
    ClientId string `optional:"" name:"client-id" help:"Override the advertised public OAuth client_id."`
    Scopes   string `optional:"" help:"Space-separated OAuth scopes to request (default: openid email profile)."`
    Device   bool   `optional:"" help:"Force the OAuth device-code flow (headless: prints a URL + code to complete on another device)."`
}

func (l *LoginCmd) Run(c *CLI) error {
    server, err := c.Data.GetServer(l.Alias)
    if err != nil {
        return err
    }

    prm, err := discoverProtectedResource(server.Host)
    if err != nil {
        return fmt.Errorf("could not fetch protected resource metadata from %s: %w; the server may not advertise OAuth (use --bootstrap/--token on 'add server')", server.Host, err)
    }

    issuer, err := resolveIssuer(prm, l.Issuer)
    if err != nil {
        return err
    }
    clientId := resolveClientId(prm, l.ClientId)
    if clientId == "" {
        return fmt.Errorf("no client_id advertised and none provided; pass --client-id")
    }

    endpoints, err := discoverEndpoints(issuer)
    if err != nil {
        return err
    }

    var scopes []string
    if l.Scopes != "" {
        scopes = strings.Fields(l.Scopes)
    }

    sess, err := runLogin(loginOptions{
        Issuer:      issuer,
        ClientId:    clientId,
        Scopes:      scopes,
        Endpoints:   endpoints,
        ForceDevice: l.Device,
    })
    if err != nil {
        return err
    }

    store, err := LoadCredentialStore(&c.Globals)
    if err != nil {
        return err
    }
    store.Set(issuer, sess)
    if err := store.Save(); err != nil {
        return err
    }

    // Cache the (non-secret) active issuer + advertised servers on the server
    // record; never store tokens in config.json.
    server.ActiveIssuer = issuer
    server.AuthorizationServers = prm.AuthorizationServers
    c.Data.Servers[l.Alias] = *server
    if err := c.Data.Save(&c.Globals); err != nil {
        return err
    }

    fmt.Printf("Logged in to %s as %s\n", l.Alias, sess.describe(issuer))
    return nil
}

// WhoamiCmd prints the active session for a server (issuer, subject/email,
// scopes, expiry).
type WhoamiCmd struct {
    Alias string `arg:"" optional:"" help:"The alias of the server (defaults to the selected server)."`
}

func (cmd *WhoamiCmd) Run(c *CLI) error {
    server, err := c.Data.GetServer(cmd.Alias)
    if err != nil {
        return err
    }
    if server.ActiveIssuer == "" {
        fmt.Printf("Not logged in to %s. Run 'login %s'.\n", server.Alias, server.Alias)
        return nil
    }
    store, err := LoadCredentialStore(&c.Globals)
    if err != nil {
        return err
    }
    sess := store.Get(server.ActiveIssuer)
    if sess == nil {
        fmt.Printf("No stored session for issuer %s. Run 'login %s'.\n", server.ActiveIssuer, server.Alias)
        return nil
    }
    status := "valid"
    if sess.Expired() {
        status = "expired (will refresh on next call)"
    }
    fmt.Printf("%s\nstatus: %s\n", sess.describe(server.ActiveIssuer), status)
    c.GetOutputWriter().WriteString(sess.describe(server.ActiveIssuer), true)
    return nil
}

// LogoutCmd clears the stored session for a server's active issuer.
type LogoutCmd struct {
    Alias string `arg:"" optional:"" help:"The alias of the server (defaults to the selected server)."`
}

func (cmd *LogoutCmd) Run(c *CLI) error {
    server, err := c.Data.GetServer(cmd.Alias)
    if err != nil {
        return err
    }
    if server.ActiveIssuer == "" {
        fmt.Printf("Not logged in to %s.\n", server.Alias)
        return nil
    }
    store, err := LoadCredentialStore(&c.Globals)
    if err != nil {
        return err
    }
    issuer := server.ActiveIssuer
    store.Delete(issuer)
    if err := store.Save(); err != nil {
        return err
    }
    server.ActiveIssuer = ""
    c.Data.Servers[server.Alias] = *server
    if err := c.Data.Save(&c.Globals); err != nil {
        return err
    }
    fmt.Printf("Logged out of %s (issuer %s).\n", server.Alias, issuer)
    return nil
}
