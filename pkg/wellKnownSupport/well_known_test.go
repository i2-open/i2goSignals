package wellKnownSupport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type WellKnownSupportTestSuite struct {
	suite.Suite
}

func (suite *WellKnownSupportTestSuite) TestBuildWellKnownURLs() {
	// Test case: No path in baseURL
	urls, err := BuildWellKnownURLs("https://example.com", SSFConfigurationPath)
	suite.NoError(err)
	suite.Equal([]string{"https://example.com/.well-known/ssf-configuration"}, urls)

	// Test case: Path in baseURL
	urls, err = BuildWellKnownURLs("https://example.com/issuer1", SSFConfigurationPath)
	suite.NoError(err)
	suite.Contains(urls, "https://example.com/.well-known/ssf-configuration/issuer1")
	suite.Contains(urls, "https://example.com/issuer1/.well-known/ssf-configuration")

	// Test case: baseURL without scheme
	urls, err = BuildWellKnownURLs("example.com", SSFConfigurationPath)
	suite.NoError(err)
	suite.Equal([]string{"https://example.com/.well-known/ssf-configuration"}, urls)
}

// TestInsertWellKnownURL covers RFC 8615 / SSF §7.2 path insertion: the
// well-known component is spliced between the host and the issuer path, never
// appended. Figure 17: issuer https://tr.example.com/issuer1 ->
// https://tr.example.com/.well-known/ssf-configuration/issuer1.
func (suite *WellKnownSupportTestSuite) TestInsertWellKnownURL() {
	// Issuer with a path: insert between host and path.
	got, err := InsertWellKnownURL("https://tr.example.com/issuer1", SSFConfigurationPath)
	suite.NoError(err)
	suite.Equal("https://tr.example.com/.well-known/ssf-configuration/issuer1", got)

	// Issuer with a host-only base: result is host + well-known path.
	got, err = InsertWellKnownURL("https://tr.example.com", SSFConfigurationPath)
	suite.NoError(err)
	suite.Equal("https://tr.example.com/.well-known/ssf-configuration", got)

	// Trailing slash on a host-only base behaves like host-only.
	got, err = InsertWellKnownURL("https://tr.example.com/", SSFConfigurationPath)
	suite.NoError(err)
	suite.Equal("https://tr.example.com/.well-known/ssf-configuration", got)

	// Multi-segment path with a trailing slash (the conformance suite shape:
	// /test/a/<alias>/) inserts before the whole path.
	got, err = InsertWellKnownURL("https://localhost:8443/test/a/abc/", SSFConfigurationPath)
	suite.NoError(err)
	suite.Equal("https://localhost:8443/.well-known/ssf-configuration/test/a/abc", got)

	// Base without scheme defaults to https.
	got, err = InsertWellKnownURL("tr.example.com/issuer1", SSFConfigurationPath)
	suite.NoError(err)
	suite.Equal("https://tr.example.com/.well-known/ssf-configuration/issuer1", got)
}

func (suite *WellKnownSupportTestSuite) TestFetchSSFConfiguration() {
	config := &model.TransmitterConfiguration{
		Issuer: "https://example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ssf-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	res, err := FetchSSFConfiguration(context.Background(), server.Client(), server.URL)
	suite.NoError(err)
	suite.Equal(config.Issuer, res.Issuer)
}

func (suite *WellKnownSupportTestSuite) TestFetchSSFConfigurationFallback() {
	config := &model.TransmitterConfiguration{
		Issuer: "https://example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/sse-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	res, err := FetchSSFConfiguration(context.Background(), server.Client(), server.URL)
	suite.NoError(err)
	suite.Equal(config.Issuer, res.Issuer)
}

// GH #209 problem 2: the legacy sse-configuration fallback must engage ONLY on a
// primary 404. A non-404 status (here 500) surfaces directly from the
// ssf-configuration attempt and must NOT trigger an sse-configuration request.
func (suite *WellKnownSupportTestSuite) TestFetchSSFConfigurationNon404NoFallback() {
	var sseRequested bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == SSEConfigurationPath {
			sseRequested = true
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := FetchSSFConfiguration(context.Background(), server.Client(), server.URL)
	suite.Error(err)
	suite.False(sseRequested, "must not fall back to sse-configuration on a non-404 primary error")
	suite.Contains(err.Error(), "ssf-configuration", "surfaced error must name the ssf-configuration attempt")
	suite.Contains(err.Error(), "500", "surfaced error must carry the primary status")
}

// GH #209 problem 2: a primary attempt that returns 200 with an undecodable body
// is a decode error, not a 404 — the fallback must not engage, and the decode
// error surfaces from the ssf-configuration attempt.
func (suite *WellKnownSupportTestSuite) TestFetchSSFConfigurationDecodeErrorNoFallback() {
	var sseRequested bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == SSEConfigurationPath {
			sseRequested = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "this is not json")
	}))
	defer server.Close()

	_, err := FetchSSFConfiguration(context.Background(), server.Client(), server.URL)
	suite.Error(err)
	suite.False(sseRequested, "a decode error must not trigger the sse-configuration fallback")
	suite.Contains(err.Error(), "ssf-configuration", "decode error must reference the ssf-configuration attempt")
}

// GH #209 problem 2: when the spec endpoint 404s and the legacy fallback also
// fails, the surfaced error must still carry the primary ssf-configuration
// failure — never present only the fabricated sse-configuration URL the operator
// originally saw.
func (suite *WellKnownSupportTestSuite) TestFetchSSFConfigurationFallbackPreservesPrimary() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchSSFConfiguration(context.Background(), server.Client(), server.URL)
	suite.Error(err)
	suite.Contains(err.Error(), SSFConfigurationPath,
		"a failed fallback must still surface the primary ssf-configuration attempt")
}

func (suite *WellKnownSupportTestSuite) TestFetchOpenIDConfiguration() {
	config := &OIDCConfiguration{
		Issuer:  "https://example.com",
		JWKSURI: "https://example.com/jwks",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	res, err := FetchOpenIDConfiguration(context.Background(), server.Client(), server.URL)
	suite.NoError(err)
	suite.Equal(config.Issuer, res.Issuer)
	suite.Equal(config.JWKSURI, res.JWKSURI)
}

func (suite *WellKnownSupportTestSuite) TestFetchProtectedResourceMetadata() {
	config := &model.ProtectedResourceMetadata{
		AuthorizationServers: []string{"https://as.example.com"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	res, err := FetchProtectedResourceMetadata(context.Background(), server.Client(), server.URL)
	suite.NoError(err)
	suite.Equal(config.AuthorizationServers, res.AuthorizationServers)
}

// FetchOAuthAuthorizationServerRaw returns the upstream RFC 8414 document
// verbatim — including fields not modeled by OIDCConfiguration — so a proxy can
// reflect the real authorization server losslessly.
func (suite *WellKnownSupportTestSuite) TestFetchOAuthAuthorizationServerRaw() {
	body := `{"issuer":"https://as.example.com","token_endpoint":"https://as.example.com/token","x_custom":"keep-me"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == OAuthAuthorizationServerPath {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	raw, err := FetchOAuthAuthorizationServerRaw(context.Background(), server.Client(), server.URL)
	suite.NoError(err)
	var parsed map[string]interface{}
	suite.NoError(json.Unmarshal(raw, &parsed))
	suite.Equal("https://as.example.com", parsed["issuer"])
	suite.Equal("keep-me", parsed["x_custom"], "unmodeled fields must survive verbatim")
}

// When oauth-authorization-server is absent (404), the OpenID Provider
// openid-configuration is reflected instead (Keycloak commonly serves only it).
func (suite *WellKnownSupportTestSuite) TestFetchOAuthAuthorizationServerRawFallback() {
	body := `{"issuer":"https://op.example.com","token_endpoint":"https://op.example.com/token"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == OpenIDConfigurationPath {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	raw, err := FetchOAuthAuthorizationServerRaw(context.Background(), server.Client(), server.URL)
	suite.NoError(err)
	var parsed map[string]interface{}
	suite.NoError(json.Unmarshal(raw, &parsed))
	suite.Equal("https://op.example.com", parsed["issuer"])
}

// When neither document resolves, the error carries the primary
// oauth-authorization-server attempt with the fallback noted.
func (suite *WellKnownSupportTestSuite) TestFetchOAuthAuthorizationServerRawBothFail() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchOAuthAuthorizationServerRaw(context.Background(), server.Client(), server.URL)
	suite.Error(err)
	suite.Contains(err.Error(), OAuthAuthorizationServerPath,
		"error must surface the primary oauth-authorization-server attempt")
	suite.Contains(err.Error(), "openid-configuration",
		"error must note the openid-configuration fallback")
}

func (suite *WellKnownSupportTestSuite) TestFetchWellKnownError() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, "internal error")
	}))
	defer server.Close()

	_, err := FetchOpenIDConfiguration(context.Background(), server.Client(), server.URL)
	suite.Error(err)
	suite.Contains(err.Error(), "500")
}

func (suite *WellKnownSupportTestSuite) TestFetch() {
	config := &OIDCConfiguration{
		Issuer: "https://example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	}))
	defer server.Close()

	res, err := Fetch[OIDCConfiguration](context.Background(), server.Client(), server.URL)
	suite.NoError(err)
	suite.Equal(config.Issuer, res.Issuer)
}

func (suite *WellKnownSupportTestSuite) TestCheckWellKnown() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ssf-configuration" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	err := CheckSSFConfiguration(context.Background(), server.Client(), server.URL)
	suite.NoError(err)
}

func TestWellKnownSupportTestSuite(t *testing.T) {
	suite.Run(t, new(WellKnownSupportTestSuite))
}
