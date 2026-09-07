package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// node is one goSignals server the harness talks to.
//
// hostBase is the URL the harness (on the host) uses. internalBase is the URL
// the *other* server uses to reach this one (the docker network name). The
// server reports its own BASE_URL in every endpoint it returns, so
// internalBase is learned from the first stream created unless overridden.
type node struct {
	name         string
	hostBase     string
	internalBase string
	token        string // registered client token (stream + event scopes)
	http         *http.Client
}

func newHTTPClient(caFile string, insecure bool) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if insecure {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- opt-in for dev stacks
	} else if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates found in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 256,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{Transport: transport, Timeout: 120 * time.Second}, nil
}

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.status, strings.TrimSpace(e.body))
}

func (n *node) do(method, path, bearer, contentType string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, n.hostBase+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		if !strings.HasPrefix(bearer, "Bearer ") {
			bearer = "Bearer " + bearer
		}
		req.Header.Set("Authorization", bearer)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, err
}

func (n *node) doJSON(method, path, bearer string, in any, out any, okStatus ...int) error {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	status, respBody, err := n.do(method, path, bearer, "application/json", body)
	if err != nil {
		return fmt.Errorf("%s %s %s: %w", n.name, method, path, err)
	}
	ok := false
	for _, s := range okStatus {
		if s == status {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("%s %s %s: %w", n.name, method, path, &httpError{status, string(respBody)})
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("%s %s %s: decode: %w", n.name, method, path, err)
		}
	}
	return nil
}

// bootstrap mints an IAT with the bootstrap secret and registers a client that
// carries the stream + event scopes. That single token can create streams and
// push/poll on any stream in its project.
func (n *node) bootstrap(bootstrapToken string) error {
	var iat model.RegisterResponse
	if err := n.doJSON(http.MethodGet, "/iat", bootstrapToken, nil, &iat, http.StatusOK); err != nil {
		return fmt.Errorf("mint IAT: %w", err)
	}
	var client model.RegisterResponse
	reg := model.RegisterParameters{
		Scopes:      []string{"stream", "event"},
		Email:       "bench@example.com",
		Description: "goSignalsBench harness",
	}
	if err := n.doJSON(http.MethodPost, "/register", iat.Token, reg, &client, http.StatusOK, http.StatusCreated); err != nil {
		return fmt.Errorf("register client: %w", err)
	}
	n.token = client.Token
	return nil
}

// hasIssuerKey reports whether the server already publishes a JWKS for issuer.
func (n *node) hasIssuerKey(issuer string) bool {
	status, _, err := n.do(http.MethodGet, "/jwks/"+url.PathEscape(issuer), "", "", nil)
	return err == nil && status == http.StatusOK
}

// createIssuerKey asks the server to mint an RSA signing key whose kid is the
// issuer name and returns the PKCS#8 private key the server hands back.
func (n *node) createIssuerKey(bootstrapToken, issuer string) (*rsa.PrivateKey, []byte, error) {
	status, body, err := n.do(http.MethodPost, "/key/"+url.PathEscape(issuer), bootstrapToken, "", nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, nil, &httpError{status, string(body)}
	}
	key, err := parseRSAPrivateKeyPEM(body)
	if err != nil {
		return nil, nil, err
	}
	return key, body, nil
}

func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := k.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("PKCS#8 key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// streamRequest is the subset of the POST /stream body the harness uses. The
// delivery block is a plain map so the ":receive" method variants marshal
// exactly as the CLI sends them.
type streamRequest struct {
	Iss             string         `json:"iss,omitempty"`
	Aud             []string       `json:"aud,omitempty"`
	EventsRequested []string       `json:"events_requested"`
	IssuerJWKSUrl   string         `json:"issuerJWKSUrl,omitempty"`
	RouteMode       string         `json:"route_mode,omitempty"`
	Description     string         `json:"description,omitempty"`
	DefaultSubjects string         `json:"default_subjects,omitempty"`
	Delivery        map[string]any `json:"delivery"`
}

func (n *node) createStream(req streamRequest) (*model.StreamConfiguration, error) {
	var cfg model.StreamConfiguration
	if err := n.doJSON(http.MethodPost, "/stream", n.token, req, &cfg, http.StatusCreated, http.StatusOK); err != nil {
		return nil, err
	}
	if cfg.Id == "" {
		return nil, fmt.Errorf("%s: stream create returned no stream_id", n.name)
	}
	return &cfg, nil
}

func (n *node) deleteStream(id string) error {
	status, body, err := n.do(http.MethodDelete, "/stream?stream_id="+url.QueryEscape(id), n.token, "", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusAccepted {
		return &httpError{status, string(body)}
	}
	return nil
}

// pushSET delivers one compact JWS to a push-receive endpoint (RFC 8935).
func (n *node) pushSET(path, bearer, jws string) (int, error) {
	req, err := http.NewRequest(http.MethodPost, n.hostBase+path, strings.NewReader(jws))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	resp, err := n.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp.StatusCode, &httpError{resp.StatusCode, string(b)}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// splitEndpoint separates a server-reported endpoint URL into its base
// (scheme://host[:port]) and path+query. The base is the server's BASE_URL,
// which inside docker is the container name, so the harness keeps the path and
// substitutes its own host-side base.
func splitEndpoint(endpoint string) (base, path string, err error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", err
	}
	base = u.Scheme + "://" + u.Host
	path = u.Path
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return base, path, nil
}

// rebase swaps the scheme+host of endpoint for base, keeping the path.
func rebase(endpoint, base string) (string, error) {
	_, path, err := splitEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(base, "/") + path, nil
}
