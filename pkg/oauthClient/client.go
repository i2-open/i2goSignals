package oauthClient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
	"golang.org/x/oauth2"
)

var clientLog = logger.Sub("OAUTH")

// Config for STS/OAuth exchanges, read from the environment by callers if desired.
type Config struct {
	TokenURL     string // OAuth2 token endpoint capable of RFC8693 token exchange
	ClientID     string
	ClientSecret string
	// Optional audience or resource param names depend on AS; not used by default
	Audience string
	// Resource is an optional default protected resource identifier. Can be overridden per call.
	Resource string
	// Scopes required for the client credentials flow
	Scopes []string
}

// Manager caches HTTP clients per (subjectToken, scopes) tuple and reuses auto-refreshing TokenSources.
type Manager struct {
	cfg   Config
	mu    sync.Mutex
	cache map[string]*http.Client
	hc    *http.Client
}

// NewManager constructs a Manager with the given config. httpClient is optional; http.DefaultClient is used if nil.
func NewManager(cfg Config, httpClient *http.Client) *Manager {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Manager{cfg: cfg, cache: make(map[string]*http.Client), hc: httpClient}
}

var (
	defaultOnce sync.Once
	defaultMgr  *Manager
)

// DefaultManager returns a process-wide Manager initialized from environment variables:
//
//	STS_TOKEN_URL, STS_CLIENT_ID, STS_CLIENT_SECRET, optional STS_AUDIENCE, STS_RESOURCE.
//
// STS_RESOURCE acts only as a default; callers can override the resource per request.
func DefaultManager() *Manager {
	defaultOnce.Do(func() {
		cfg := Config{
			TokenURL:     strings.TrimSpace(os.Getenv("STS_TOKEN_URL")),
			ClientID:     strings.TrimSpace(os.Getenv("STS_CLIENT_ID")),
			ClientSecret: strings.TrimSpace(os.Getenv("STS_CLIENT_SECRET")),
			Audience:     strings.TrimSpace(os.Getenv("STS_AUDIENCE")),
			Resource:     strings.TrimSpace(os.Getenv("STS_RESOURCE")),
		}
		if scopes := os.Getenv("STS_SCOPES"); scopes != "" {
			cfg.Scopes = strings.Split(scopes, " ")
		}
		defaultMgr = NewManager(cfg, nil)
	})
	return defaultMgr
}

// GetHTTPClient returns an http.Client that uses an oauth2.Transport with a TokenSource that
// performs an RFC8693 token exchange for the provided subject access token and scopes, and
// automatically refreshes when expired (using refresh_token when provided, else re-exchanges).
// resource allows per-call selection of the protected resource identifier. If empty, the
// Manager's default (from Config.Resource) is used.
func (m *Manager) GetHTTPClient(ctx context.Context, subjectAccessToken string, scopes []string, resource string) (*http.Client, error) {
	if m.cfg.TokenURL == "" || m.cfg.ClientID == "" || m.cfg.ClientSecret == "" {
		return nil, errors.New("oauthclient: STS token configuration missing")
	}
	// Use provided resource or fallback to default configured resource
	if strings.TrimSpace(resource) == "" {
		resource = m.cfg.Resource
	}
	key := cacheKey(subjectAccessToken, scopes, resource)
	m.mu.Lock()
	if c, ok := m.cache[key]; ok {
		m.mu.Unlock()
		return c, nil
	}
	m.mu.Unlock()

	base := &tokenExchangeSource{
		ctx:          context.WithoutCancel(ctx),
		hc:           m.hc,
		tokenURL:     m.cfg.TokenURL,
		clientID:     m.cfg.ClientID,
		clientSecret: m.cfg.ClientSecret,
		subjectToken: subjectAccessToken,
		scopes:       normalizeScopes(scopes),
		audience:     m.cfg.Audience,
		resource:     resource,
	}

	// Wrap with ReuseTokenSource to cache the token in memory across requests.
	ts := oauth2.ReuseTokenSource(nil, base)
	oauthClient := &http.Client{
		Transport:     &oauth2.Transport{Source: ts, Base: m.hc.Transport},
		Timeout:       m.hc.Timeout,
		CheckRedirect: m.hc.CheckRedirect,
		Jar:           m.hc.Jar,
	}

	m.mu.Lock()
	m.cache[key] = oauthClient
	m.mu.Unlock()
	return oauthClient, nil
}

func GetStaticTokenClient(ctx context.Context, server *model.Server) (*http.Client, error) {
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}
	if server.ClientToken == nil {
		return nil, errors.New("client token cannot be nil")
	}
	token := *server.ClientToken
	if !strings.Contains(token, " ") {
		token = "Bearer " + token
	}

	tlsConfig := GetTlsConfigForServer(server)
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}

	return &http.Client{
		Transport: &staticTokenRoundTripper{
			token:   token,
			wrapped: transport,
		},
		Timeout: 30 * time.Second,
	}, nil
}

// staticTokenRoundTripper is an http.RoundTripper that adds a static Authorization header.
type staticTokenRoundTripper struct {
	token   string
	wrapped http.RoundTripper
}

func (s *staticTokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", s.token)
	return s.wrapped.RoundTrip(req)
}

// GetClient is a convenience wrapper around DefaultManager().GetHTTPClient.
// resource overrides the default resource set in environment (STS_RESOURCE). Pass "" to use default.
func GetClient(ctx context.Context, subjectAccessToken string, scopes []string, resource string) (*http.Client, error) {
	return DefaultManager().GetHTTPClient(ctx, subjectAccessToken, scopes, resource)
}

// tokenExchangeSource is an oauth2.TokenSource that executes token exchange and
// attempts refresh when possible.
type tokenExchangeSource struct {
	ctx          context.Context
	hc           *http.Client
	tokenURL     string
	clientID     string
	clientSecret string
	subjectToken string
	scopes       []string
	audience     string
	resource     string

	// last token to allow refresh when refresh_token is present
	last *oauth2.Token
}

func (s *tokenExchangeSource) Token() (*oauth2.Token, error) {
	// If we have a token and it's still valid, return it.
	if s.last != nil && s.last.Valid() {
		clientLog.Debug("Using cached token")
		return s.last, nil
	}
	// If we have a refresh_token, attempt refresh via standard OAuth2.
	if s.last != nil {
		if rt := s.last.RefreshToken; rt != "" {
			clientLog.Debug("Refreshing cached token")
			t, err := s.refreshWithRefreshToken(rt)
			if err == nil {
				s.last = t
				return t, nil
			}
			// fallthrough to full exchange on error
		}
	}
	// Perform token exchange
	clientLog.Debug("Exchanging user token for access token")
	t, err := s.exchange()
	if err != nil {
		return nil, err
	}
	s.last = t
	return t, nil
}

func (s *tokenExchangeSource) exchange() (*oauth2.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("subject_token", s.subjectToken)
	form.Set("resource", s.resource)
	if len(s.scopes) > 0 {
		form.Set("scope", strings.Join(s.scopes, " "))
	}
	if s.audience != "" {
		form.Set("audience", s.audience)
	}
	if s.resource != "" {
		form.Set("resource", s.resource)
	}

	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.clientID), url.QueryEscape(s.clientSecret))

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpSupport.HandleRespClose(resp)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, errors.New("token exchange failed: " + resp.Status + ": " + string(b))
	}
	var tr tokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return tr.toOAuth2Token(), nil
}

func (s *tokenExchangeSource) refreshWithRefreshToken(refreshToken string) (*oauth2.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	if len(s.scopes) > 0 {
		form.Set("scope", strings.Join(s.scopes, " "))
	}
	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.clientID), url.QueryEscape(s.clientSecret))

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpSupport.HandleRespClose(resp)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, errors.New("token refresh failed: " + resp.Status + ": " + string(b))
	}
	var tr tokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return tr.toOAuth2Token(), nil
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (tr tokenResp) toOAuth2Token() *oauth2.Token {
	// Ensure the access token itself doesn't have a Bearer prefix, as oauth2.Transport adds it.
	accessToken := strings.TrimSpace(tr.AccessToken)
	for {
		lower := strings.ToLower(accessToken)
		if strings.HasPrefix(lower, "bearer") {
			accessToken = strings.TrimSpace(accessToken[len("bearer"):])
		} else {
			break
		}
	}

	t := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
	}
	if tr.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return t
}

func cacheKey(subjectToken string, scopes []string, resource string) string {
	scopes = normalizeScopes(scopes)
	r := strings.TrimSpace(resource)
	h := sha256.Sum256([]byte(subjectToken + "|" + strings.Join(scopes, " ") + "|" + r))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GetClientCredentialsHTTPClient returns an http.Client that uses an oauth2.Transport with a TokenSource that
// performs an OAuth Client Credentials flow for the provided scopes, and automatically refreshes when expired.
// resource allows per-call selection of the protected resource identifier. If empty, the Manager's default (from Config.Resource) is used.
func (m *Manager) GetClientCredentialsHTTPClient(ctx context.Context, scopes []string, resource string, server *model.Server) (*http.Client, error) {
	if m.cfg.TokenURL == "" || m.cfg.ClientID == "" || m.cfg.ClientSecret == "" {
		return nil, errors.New("oauthclient: client credentials configuration missing")
	}
	// Use provided resource or fallback to default configured resource
	if strings.TrimSpace(resource) == "" {
		resource = m.cfg.Resource
	}

	// Use provided scopes or fallback to default configured scopes
	if len(scopes) == 0 {
		scopes = m.cfg.Scopes
	}

	// For client credentials flow, we use an empty subjectToken in the cacheKey
	key := cacheKey("client_credentials", scopes, resource)
	m.mu.Lock()
	if c, ok := m.cache[key]; ok {
		m.mu.Unlock()
		return c, nil
	}
	m.mu.Unlock()

	// Create TLS configuration for both token endpoint and resource requests
	tlsConfig := GetTlsConfigForServer(server)
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Create HTTP client with TLS config for token endpoint requests
	tokenHTTPClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	base := &clientCredentialsSource{
		ctx:          context.WithoutCancel(ctx),
		hc:           tokenHTTPClient, // Use client with proper TLS config
		tokenURL:     m.cfg.TokenURL,
		clientID:     m.cfg.ClientID,
		clientSecret: m.cfg.ClientSecret,
		scopes:       normalizeScopes(scopes),
		audience:     m.cfg.Audience,
		resource:     resource,
	}

	// Wrap with ReuseTokenSource to cache the token in memory across requests.
	ts := oauth2.ReuseTokenSource(nil, base)
	oauthClient := &http.Client{
		Transport:     &oauth2.Transport{Source: ts, Base: transport},
		Timeout:       30 * time.Second,
		CheckRedirect: m.hc.CheckRedirect,
		Jar:           m.hc.Jar,
	}

	m.mu.Lock()
	m.cache[key] = oauthClient
	m.mu.Unlock()
	return oauthClient, nil
}

// clientCredentialsSource is an oauth2.TokenSource that executes client credentials flow.
type clientCredentialsSource struct {
	ctx          context.Context
	hc           *http.Client
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string
	audience     string
	resource     string

	// last token
	last *oauth2.Token
}

func (s *clientCredentialsSource) Token() (*oauth2.Token, error) {
	// If we have a token and it's still valid, return it.
	if s.last != nil && s.last.Valid() {
		clientLog.Debug("Using cached client credentials token")
		return s.last, nil
	}

	// Perform client credentials flow
	clientLog.Debug("Fetching client credentials token")
	t, err := s.fetch()
	if err != nil {
		return nil, err
	}
	s.last = t
	return t, nil
}

func (s *clientCredentialsSource) fetch() (*oauth2.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(s.scopes) > 0 {
		form.Set("scope", strings.Join(s.scopes, " "))
	}
	if s.audience != "" {
		form.Set("audience", s.audience)
	}
	if s.resource != "" {
		form.Set("resource", s.resource)
	}

	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.clientID), url.QueryEscape(s.clientSecret))

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpSupport.HandleRespClose(resp)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, errors.New("client credentials flow failed: " + resp.Status + ": " + string(b))
	}
	var tr tokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return tr.toOAuth2Token(), nil
}

// ValidateClientCredentials checks if a token can be obtained using the provided client credentials configuration.
func ValidateClientCredentials(ctx context.Context, cfg Config, server *model.Server) error {
	if cfg.TokenURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return errors.New("oauthclient: configuration missing")
	}
	m := NewManager(cfg, nil)
	client, err := m.GetClientCredentialsHTTPClient(ctx, cfg.Scopes, cfg.Resource, server)
	if err != nil {
		return err
	}
	_, err = client.Transport.(*oauth2.Transport).Source.Token()
	return err
}

var (
	managersMu sync.Mutex
	managers   = make(map[string]*Manager)
)

// GetClientCredentialsClient returns a cached or new http.Client for the provided client credentials configuration.
func GetClientCredentialsClient(ctx context.Context, cfg Config, server *model.Server) (*http.Client, error) {
	managersMu.Lock()
	key := cfg.key()
	m, ok := managers[key]
	if !ok {
		m = NewManager(cfg, nil)
		managers[key] = m
	}
	managersMu.Unlock()

	return m.GetClientCredentialsHTTPClient(ctx, cfg.Scopes, cfg.Resource, server)
}

// GetClientForServer returns an http.Client configured for the given server based on its auth mode.
// It prioritizes OAuth2 Client Credentials flow, then static token, then fallback to base client with TLS.
// The returned client automatically handles the Authorization header for both OAuth2 and Static Token modes.
func GetClientForServer(ctx context.Context, server *model.Server) (*http.Client, error) {
	if server == nil {
		return nil, errors.New("server is nil")
	}

	// Try OAuth client credentials first
	if server.OAuthClientConfig != nil {
		cfg := Config{
			TokenURL:     server.OAuthClientConfig.TokenURL,
			ClientID:     server.OAuthClientConfig.ClientID,
			ClientSecret: server.OAuthClientConfig.ClientSecret,
			Audience:     server.OAuthClientConfig.Audience,
			Resource:     server.OAuthClientConfig.Resource,
			Scopes:       server.OAuthClientConfig.Scopes,
		}

		return GetClientCredentialsClient(ctx, cfg, server)
	}

	// Fallback to static token from server with proper TLS
	if server.ClientToken != nil && *server.ClientToken != "" {
		return GetStaticTokenClient(ctx, server)
	}

	// Default client with server TLS settings
	return GetBaseHTTPClientForServer(server), nil
}

func (c Config) key() string {
	s := c.TokenURL + "|" + c.ClientID + "|" + c.ClientSecret + "|" + c.Audience + "|" + c.Resource + "|" + strings.Join(normalizeScopes(c.Scopes), " ")
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// DiscoverTokenURL uses the Server Host value to query the Protected Resource Metadata endpoint (RFC9728)
// to obtain authorization server information and the TokenURL value (RFC8414).
func DiscoverTokenURL(ctx context.Context, host string, client *http.Client) (string, error) {
	if host == "" {
		return "", errors.New("host is empty")
	}

	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
		tlsSupport.CheckCaInstalled(client)
	}

	metadata, err := wellKnownSupport.FetchProtectedResourceMetadata(ctx, client, host)
	if err != nil {
		return "", err
	}

	if len(metadata.AuthorizationServers) == 0 {
		return "", errors.New("no authorization servers found in protected resource metadata")
	}

	// Try to find token_endpoint for each authorization server
	for _, as := range metadata.AuthorizationServers {
		tokenURL, err := discoverTokenEndpoint(ctx, as)
		if err == nil {
			return tokenURL, nil
		}
	}

	return "", errors.New("could not discover token endpoint from any authorization server")
}

func discoverTokenEndpoint(ctx context.Context, as string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	tlsSupport.CheckCaInstalled(client)

	// Try OAuth 2.0 Authorization Server Metadata (RFC 8414)
	metadata, err := wellKnownSupport.FetchWellKnown[struct {
		TokenEndpoint string `json:"token_endpoint"`
	}](ctx, client, as, wellKnownSupport.OAuthAuthorizationServerPath)

	if err == nil && metadata.TokenEndpoint != "" {
		return metadata.TokenEndpoint, nil
	}

	// Try OpenID Provider Configuration (OIDC)
	oidcMetadata, err := wellKnownSupport.FetchOpenIDConfiguration(ctx, client, as)
	if err == nil && oidcMetadata.TokenEndpoint != "" {
		return oidcMetadata.TokenEndpoint, nil
	}

	return "", errors.New("token endpoint not found")
}

func normalizeScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if ss := strings.TrimSpace(s); ss != "" {
			out = append(out, ss)
		}
	}
	sort.Strings(out)
	return out
}
