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
