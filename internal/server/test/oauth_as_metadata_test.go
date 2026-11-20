package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// OAuthAsMetadataSuite exercises the RFC 8414 OAuth 2.0 Authorization Server
// Metadata endpoint (/.well-known/oauth-authorization-server[/{issuer}]).
// goSignals is a resource server that delegates OAuth to an external
// authorization server (ADR 0001); the endpoint therefore REFLECTS the
// configured authorization server's metadata verbatim (a discovery proxy) when
// one is configured, and otherwise advertises goSignals' own partial
// authorization-server surface (introspection/revocation/registration + jwks).
type OAuthAsMetadataSuite struct {
	suite.Suite
	instance *ssfInstance
}

func (suite *OAuthAsMetadataSuite) SetupSuite() {
	instance, err := createServer(suite.T(), "oauth_as_metadata_test", true)
	require.NoError(suite.T(), err)
	suite.instance = instance
}

func (suite *OAuthAsMetadataSuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

// noExternalAS clears any configured authorization server so the endpoint serves
// goSignals' own partial metadata. Tests that need the proxy path set it instead.
func (suite *OAuthAsMetadataSuite) noExternalAS() {
	suite.instance.app.GetAuth().OAuthServer = nil
}

// useExternalAS configures a single external authorization server for the
// duration of the calling test and restores no-AS afterward.
func (suite *OAuthAsMetadataSuite) useExternalAS(asURL string) {
	suite.instance.app.GetAuth().OAuthServer = []string{asURL}
	suite.T().Cleanup(suite.noExternalAS)
}

// createIssuerKey registers a signing key under the given full issuer name (the
// keyName == issuer contract), the same way startup provisions an issuer.
func (suite *OAuthAsMetadataSuite) createIssuerKey(fullIssuer string) {
	_, err := suite.instance.keySvc().CreateKeyPair(context.Background(), fullIssuer, "sig", suite.instance.projectId)
	require.NoError(suite.T(), err)
}

func TestOAuthAsMetadataSuite(t *testing.T) {
	suite.Run(t, new(OAuthAsMetadataSuite))
}

func (suite *OAuthAsMetadataSuite) getMetadata(path string) (*http.Response, map[string]interface{}) {
	t := suite.T()
	resp, err := http.Get(suite.instance.ts.URL + path)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var meta map[string]interface{}
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.Unmarshal(body, &meta))
	}
	return resp, meta
}

// Criterion 1 (tracer bullet): with no external authorization server configured,
// the bare endpoint advertises goSignals' OWN partial AS surface — the issuer,
// jwks_uri and the token-management endpoints it actually implements
// (introspection/revocation/registration) — and deliberately NOT an
// authorization_endpoint or token_endpoint, which goSignals does not run.
func (suite *OAuthAsMetadataSuite) TestPartialSelfMetadataWhenNoExternalAS() {
	t := suite.T()
	suite.noExternalAS()
	base := suite.instance.ts.URL

	resp, meta := suite.getMetadata("/.well-known/oauth-authorization-server")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, suite.instance.app.GetDefIssuer(), meta["issuer"],
		"bare endpoint issuer must be the default issuer")
	assert.Equal(t, base+"/jwks.json", meta["jwks_uri"])
	assert.Equal(t, base+"/introspect", meta["introspection_endpoint"])
	assert.Equal(t, base+"/revoke", meta["revocation_endpoint"])
	assert.Equal(t, base+"/register", meta["registration_endpoint"])
	assert.NotEmpty(t, meta["scopes_supported"], "must advertise supported scopes")

	_, hasAuthEp := meta["authorization_endpoint"]
	assert.False(t, hasAuthEp, "goSignals runs no authorization_endpoint of its own")
	_, hasTokenEp := meta["token_endpoint"]
	assert.False(t, hasTokenEp, "goSignals runs no token_endpoint of its own")
}

// Criterion 2: the {issuer} variant resolves a registered issuer the same
// local-rooted-then-bare way ssf-configuration/JWKS do (GH #209). A registered
// foreign issuer returns 200, echoes its bare name verbatim, and points jwks_uri
// at the /jwks/<segment> path that issuer's keys are served from.
func (suite *OAuthAsMetadataSuite) TestIssuerVariantSelfMetadata() {
	t := suite.T()
	suite.noExternalAS()
	base := suite.instance.ts.URL
	foreign := "cluster.scim.example.com"
	suite.createIssuerKey(foreign)

	resp, meta := suite.getMetadata("/.well-known/oauth-authorization-server/" + foreign)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a registered issuer must resolve, not 404")
	assert.Equal(t, foreign, meta["issuer"],
		"issuer must be the registered name echoed verbatim")
	assert.Equal(t, base+"/jwks/"+foreign, meta["jwks_uri"],
		"jwks_uri must be the /jwks/<segment> path that issuer's keys are served from")
}

// Criterion 3: an unknown issuer segment returns 404 and synthesizes no metadata.
func (suite *OAuthAsMetadataSuite) TestUnknownIssuerReturns404() {
	t := suite.T()
	suite.noExternalAS()
	resp, _ := suite.getMetadata("/.well-known/oauth-authorization-server/no-such-issuer")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"unknown issuer must 404, not synthesize metadata")
}

// Criterion 4: when an external authorization server is configured, the endpoint
// reflects its RFC 8414 metadata VERBATIM (a discovery proxy). The reflected doc
// carries the upstream AS's own issuer and token_endpoint, and preserves fields
// goSignals' own model does not know about — proving it is passed through, not
// re-marshaled through a lossy struct.
func (suite *OAuthAsMetadataSuite) TestProxyReflectsConfiguredASVerbatim() {
	t := suite.T()
	upstreamIssuer := "https://keycloak.example.com/realms/test"
	asBody := `{"issuer":"` + upstreamIssuer + `",` +
		`"authorization_endpoint":"` + upstreamIssuer + `/protocol/openid-connect/auth",` +
		`"token_endpoint":"` + upstreamIssuer + `/protocol/openid-connect/token",` +
		`"x_custom_marker":"verbatim-proof"}`
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, asBody)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer as.Close()
	suite.useExternalAS(as.URL)

	resp, meta := suite.getMetadata("/.well-known/oauth-authorization-server")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, upstreamIssuer, meta["issuer"],
		"reflected issuer must be the upstream AS's, not goSignals'")
	assert.Equal(t, upstreamIssuer+"/protocol/openid-connect/token", meta["token_endpoint"],
		"reflected doc must carry the upstream AS's token_endpoint")
	assert.Equal(t, "verbatim-proof", meta["x_custom_marker"],
		"unknown upstream fields must be preserved verbatim (no lossy re-marshal)")
	assert.NotEqual(t, suite.instance.app.GetDefIssuer(), meta["issuer"],
		"proxy must not advertise goSignals as the authorization server")
}

// Criterion 5: a Keycloak-style AS that serves no oauth-authorization-server
// document but does serve openid-configuration is still reflected, via the
// fallback FetchOAuthAuthorizationServerRaw applies.
func (suite *OAuthAsMetadataSuite) TestProxyFallsBackToOpenIDConfiguration() {
	t := suite.T()
	upstreamIssuer := "https://op.example.com"
	oidcBody := `{"issuer":"` + upstreamIssuer + `","token_endpoint":"` + upstreamIssuer + `/token"}`
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, oidcBody)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer as.Close()
	suite.useExternalAS(as.URL)

	resp, meta := suite.getMetadata("/.well-known/oauth-authorization-server")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, upstreamIssuer, meta["issuer"],
		"must reflect the openid-configuration when oauth-authorization-server is absent")
	assert.Equal(t, upstreamIssuer+"/token", meta["token_endpoint"])
}

// Criterion 6: a configured-but-unreachable authorization server yields 502 — the
// honest answer. Falling back to the self-document would falsely advertise
// goSignals as the authorization server.
func (suite *OAuthAsMetadataSuite) TestProxyUpstreamUnavailableReturns502() {
	t := suite.T()
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer as.Close()
	suite.useExternalAS(as.URL)

	resp, _ := suite.getMetadata("/.well-known/oauth-authorization-server")
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode,
		"unreachable configured AS must surface 502, not the self-document")
}
