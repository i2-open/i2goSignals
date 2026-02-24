package oauthclient

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

	"github.com/i2-open/i2goSignals/internal/logger"

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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
