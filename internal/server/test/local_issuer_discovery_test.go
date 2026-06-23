package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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
// (the keyName == issuer contract), mirroring how startup provisions the default
// issuer's key: directly via the KeyService. (The HTTP /key route can also carry
// a full URL when the keyName is percent-encoded — see
// TestCreateLocalIssuerKeyViaHttp — but going through the service keeps the
// discovery/JWKS assertions independent of the key-creation path.)
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

// TestCreateLocalIssuerKeyViaHttp proves a path-bearing local issuer's signing
// key CAN be provisioned over the HTTP POST /key route — the route is not
// limited to slash-free key names. The router runs with UseEncodedPath() and the
// CreateKey handler url.QueryUnescape's the captured var, so a percent-encoded
// full issuer URL (slashes as %2F) survives routing and is stored under the
// decoded name. This is the HTTP-API counterpart to startup key provisioning
// (GH #188 follow-up); the CLI `create key` builds exactly this encoded URL.
func (suite *LocalIssuerDiscoverySuite) TestCreateLocalIssuerKeyViaHttp() {
	t := suite.T()
	base := suite.instance.ts.URL
	fullIssuer := base + "/httptenant"

	// POST /key/<percent-encoded full issuer URL> with an admin bearer.
	encoded := url.QueryEscape(fullIssuer)
	req, err := http.NewRequest(http.MethodPost, base+"/key/"+encoded, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+suite.instance.streamMgmtToken)
	resp, err := suite.instance.client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, resp.StatusCode,
		"percent-encoded full-URL keyName must route to CreateKey and create the key")

	// The key is now stored under the decoded full issuer URL, so discovery for
	// the issuer path resolves exactly as a startup-provisioned issuer would.
	dresp, config := suite.getDiscovery("httptenant")
	assert.Equal(t, http.StatusOK, dresp.StatusCode)
	assert.Equal(t, fullIssuer, config.Issuer,
		"issuer created over HTTP must reconstruct to the full URL")
	assert.Equal(t, base+"/jwks/httptenant", config.JwksUri)

	// And the advertised jwks_uri serves that issuer's keys.
	jresp, err := http.Get(config.JwksUri)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, jresp.StatusCode)
	_ = jresp.Body.Close()
}

// GH #209: discovery must resolve a foreign issuer the same way JWKS does —
// local-rooted-then-bare. An issuer registered under its bare name (not
// baseURL-rooted) serves keys at /jwks/<name>; SSF §7.2.1 discovery for that
// same segment must return 200 and echo the bare name verbatim as `issuer`
// (§7.2.4: it MUST equal the `iss` of SETs that issuer signs), never the
// base-rooted form.
func (suite *LocalIssuerDiscoverySuite) TestForeignIssuerDiscovery() {
	t := suite.T()
	base := suite.instance.ts.URL
	// A foreign issuer stored under an opaque bare name, NOT baseURL-rooted.
	foreignName := "cluster.scim.example.com"
	suite.createIssuerKey(foreignName)

	resp, config := suite.getDiscovery(foreignName)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a registered foreign issuer must discover, not 404")
	assert.Equal(t, foreignName, config.Issuer,
		"issuer must be the bare registered name echoed verbatim (SSF §7.2.4), not base-rooted")
	assert.Equal(t, base+"/jwks/"+foreignName, config.JwksUri,
		"jwks_uri must be the bare-segment /jwks path the JWKS handler serves")
}

// GH #209 acceptance: discovery issuer resolution and JWKS issuer resolution
// must accept the same set of issuer segments — no issuer that serves a key at
// /jwks/<segment> may 404 at /.well-known/ssf-configuration/<segment>. Asserted
// across both a base-rooted local issuer and a bare foreign issuer.
func (suite *LocalIssuerDiscoverySuite) TestDiscoveryJwksSegmentParity() {
	t := suite.T()
	base := suite.instance.ts.URL
	segments := map[string]string{
		"parity-local":   base + "/parity-local", // base-rooted local issuer (ADR 0023)
		"parity.foreign": "parity.foreign",       // bare foreign issuer
	}
	for segment, fullName := range segments {
		suite.createIssuerKey(fullName)

		jresp, err := http.Get(base + "/jwks/" + segment)
		require.NoError(t, err)
		_ = jresp.Body.Close()
		require.Equal(t, http.StatusOK, jresp.StatusCode,
			"JWKS must resolve segment %q", segment)

		dresp, _ := suite.getDiscovery(segment)
		assert.Equal(t, http.StatusOK, dresp.StatusCode,
			"discovery must resolve any segment JWKS resolves (segment %q)", segment)
	}
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
