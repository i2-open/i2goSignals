package wellKnownSupport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/model"
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
