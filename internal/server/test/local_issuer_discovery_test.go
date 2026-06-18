package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// LocalIssuerDiscoverySuite exercises GH #188 / ADR 0023: serving SSF
// transmitter discovery and JWKS for path-bearing local issuers (issuers whose
// root scheme://host[:port] equals the server base URL, addressed by their path
// component).
type LocalIssuerDiscoverySuite struct {
	suite.Suite
	instance *ssfInstance
}

func (suite *LocalIssuerDiscoverySuite) SetupSuite() {
	instance, err := createServer(suite.T(), "local_issuer_discovery_test", true)
	require.NoError(suite.T(), err)
	suite.instance = instance
}

func (suite *LocalIssuerDiscoverySuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func TestLocalIssuerDiscoverySuite(t *testing.T) {
	suite.Run(t, new(LocalIssuerDiscoverySuite))
}

// createIssuerKey creates a signing key stored under the given full issuer URL
// (the keyName == issuer contract). The HTTP /key/{keyName} route cannot carry a
// full URL with slashes, so this mirrors how startup provisions the default
// issuer's key: directly via the KeyService.
func (suite *LocalIssuerDiscoverySuite) createIssuerKey(fullIssuer string) {
	t := suite.T()
	_, err := suite.instance.keySvc().CreateKeyPair(context.Background(), fullIssuer, "sig", suite.instance.projectId)
	require.NoError(t, err)
}

func (suite *LocalIssuerDiscoverySuite) getDiscovery(path string) (*http.Response, model.TransmitterConfiguration) {
	t := suite.T()
	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration/" + path)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var config model.TransmitterConfiguration
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.Unmarshal(body, &config))
	}
	return resp, config
}

// Criterion 1: single-segment local issuer path resolves to a full-URL issuer
// and a clean (non-encoded) jwks_uri.
func (suite *LocalIssuerDiscoverySuite) TestSingleSegmentLocalIssuer() {
	t := suite.T()
	base := suite.instance.ts.URL // scheme://host:port
	fullIssuer := base + "/issuer1"
	suite.createIssuerKey(fullIssuer)

	resp, config := suite.getDiscovery("issuer1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, fullIssuer, config.Issuer,
		"issuer must be the reconstructed full URL (SSF §7.2.4)")
	assert.Equal(t, base+"/jwks/issuer1", config.JwksUri,
		"jwks_uri must be a clean path component, not URL-encoded")
}

// Criterion 2: a multi-segment local issuer path resolves the same way.
func (suite *LocalIssuerDiscoverySuite) TestMultiSegmentLocalIssuer() {
	t := suite.T()
	base := suite.instance.ts.URL
	fullIssuer := base + "/tenants/acme"
	suite.createIssuerKey(fullIssuer)

	resp, config := suite.getDiscovery("tenants/acme")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, fullIssuer, config.Issuer,
		"multi-segment issuer must reconstruct to the full URL")
	assert.Equal(t, base+"/jwks/tenants/acme", config.JwksUri,
		"jwks_uri must carry the full multi-segment path")
}

// Criterion 3: a GET of the advertised jwks_uri returns that issuer's JWKS with
// non-empty keys.
func (suite *LocalIssuerDiscoverySuite) TestAdvertisedJwksUriResolves() {
	t := suite.T()
	base := suite.instance.ts.URL
	fullIssuer := base + "/jwksissuer"
	suite.createIssuerKey(fullIssuer)

	_, config := suite.getDiscovery("jwksissuer")
	require.Equal(t, base+"/jwks/jwksissuer", config.JwksUri)

	resp, err := http.Get(config.JwksUri)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(body, &jwks))
	assert.NotEmpty(t, jwks.Keys, "advertised jwks_uri must return non-empty keys")
}

// Criterion 4: an unknown issuer path returns 404 and synthesizes no metadata.
func (suite *LocalIssuerDiscoverySuite) TestUnknownIssuerReturns404() {
	t := suite.T()
	resp, _ := suite.getDiscovery("no-such-issuer")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"unknown issuer must 404, not synthesize metadata")
}

// Criterion 5: the host-only default issuer surface is unchanged — the bare
// /.well-known/ssf-configuration endpoint serves the default issuer with
// jwks_uri == /jwks.json, never routing through the {issuer} variant.
func (suite *LocalIssuerDiscoverySuite) TestHostOnlyIssuerUnchanged() {
	t := suite.T()
	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var config model.TransmitterConfiguration
	require.NoError(t, json.Unmarshal(body, &config))

	assert.Equal(t, suite.instance.app.GetDefIssuer(), config.Issuer,
		"host-only issuer must equal the default issuer")
	assert.Equal(t, suite.instance.ts.URL+"/jwks.json", config.JwksUri,
		"host-only jwks_uri must remain /jwks.json")
}

// JwksJsonIssuerHandler legacy fallback: a foreign/legacy keyName that is not a
// reconstructable local issuer still resolves by its stored name as-is.
func (suite *LocalIssuerDiscoverySuite) TestJwksLegacyFallback() {
	t := suite.T()
	// A foreign issuer: stored under an opaque name that is not baseURL-rooted.
	foreignName := "foreign.example.com"
	suite.createIssuerKey(foreignName)

	resp, err := http.Get(suite.instance.ts.URL + "/jwks/" + foreignName)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"legacy/foreign keyName must resolve by its stored name (fallback)")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(body, &jwks))
	assert.NotEmpty(t, jwks.Keys)
}
