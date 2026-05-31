package main

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// newDiscoveryStub returns an httptest server that answers the non-secret SSF
// discovery probe `add server` performs, so AddServerCmd.Run can complete
// without a live transmitter or Mongo.
func newDiscoveryStub(t *testing.T) *httptest.Server {
    t.Helper()
    return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/.well-known/ssf-configuration" {
            w.Header().Set("Content-Type", "application/json")
            _ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
                Issuer: "https://transmitter.example.com",
            })
            return
        }
        w.WriteHeader(http.StatusNotFound)
    }))
}

// TestAddServer_OAuthStaging proves that `add server` with --client-id stages
// the non-secret OAuth fields into config.json, EXCLUDES the secret from the
// persisted config, and does NOT change Selected.
func TestAddServer_OAuthStaging(t *testing.T) {
    stub := newDiscoveryStub(t)
    defer stub.Close()

    cli := newTestCLI(t)

    cmd := &AddServerCmd{
        Alias:        "ssfTxServer",
        Host:         stub.URL,
        ClientId:     "kc-client",
        ClientSecret: "super-secret",
        Scopes:       []string{"caep", "ssf"},
    }
    err := cmd.Run(cli)
    require.NoError(t, err)

    // In-memory: the staged server carries the non-secret OAuth config.
    srv, ok := cli.Data.Servers["ssfTxServer"]
    require.True(t, ok, "server should be staged in memory")
    require.NotNil(t, srv.OAuthClientConfig, "OAuthClientConfig should be staged")
    assert.Equal(t, "kc-client", srv.OAuthClientConfig.ClientID)
    assert.Equal(t, []string{"caep", "ssf"}, srv.OAuthClientConfig.Scopes)
    assert.Empty(t, srv.OAuthClientConfig.ClientSecret, "secret must not live on the in-memory SsfServer")

    // A transmitter-style add server must NOT change Selected.
    assert.Empty(t, cli.Data.Selected, "Selected must be unchanged for an OAuth add server")

    // Persisted config.json must contain the non-secret fields and NOT the secret.
    raw, err := os.ReadFile(cli.Globals.ConfigFile)
    require.NoError(t, err)
    text := string(raw)
    assert.Contains(t, text, "kc-client", "client-id should be persisted")
    assert.NotContains(t, text, "super-secret", "client secret must never be persisted to config.json")

    // The staged secret must be resolvable in-process from memory.
    assert.Equal(t, "super-secret", cli.Data.stagedSecret("ssfTxServer"))
}

// TestAddServer_ClientSecretWithoutClientIdSurrogate proves the legacy #127
// behavior is preserved: --client-secret WITHOUT --client-id stores the value
// as a ClientToken surrogate and does NOT create an OAuthClientConfig.
func TestAddServer_ClientSecretWithoutClientIdSurrogate(t *testing.T) {
    stub := newDiscoveryStub(t)
    defer stub.Close()

    cli := newTestCLI(t)

    cmd := &AddServerCmd{
        Alias:        "gosignals2",
        Host:         stub.URL,
        ClientSecret: "surrogate-token",
    }
    err := cmd.Run(cli)
    require.NoError(t, err)

    srv, ok := cli.Data.Servers["gosignals2"]
    require.True(t, ok)
    assert.Nil(t, srv.OAuthClientConfig, "no OAuthClientConfig without --client-id")
    assert.Equal(t, "surrogate-token", srv.ClientToken, "legacy surrogate stays as ClientToken")
}

// TestResolveOAuthSecret_Order proves the resolution order:
// in-memory staged -> --client-secret flag -> Kong env var.
func TestResolveOAuthSecret_Order(t *testing.T) {
    cli := newTestCLI(t)
    cli.Data.stageSecret("alias1", "from-memory")

    // 1. In-memory wins over flag and env.
    t.Setenv("TEST_OAUTH_SECRET", "from-env")
    got := cli.Data.ResolveOAuthSecret("alias1", "from-flag", "TEST_OAUTH_SECRET")
    assert.Equal(t, "from-memory", got)

    // 2. Flag wins over env when nothing staged.
    got = cli.Data.ResolveOAuthSecret("alias2", "from-flag", "TEST_OAUTH_SECRET")
    assert.Equal(t, "from-flag", got)

    // 3. Env used when neither staged nor flag.
    got = cli.Data.ResolveOAuthSecret("alias3", "", "TEST_OAUTH_SECRET")
    assert.Equal(t, "from-env", got)

    // 4. Empty when nothing available (no env var name).
    got = cli.Data.ResolveOAuthSecret("alias4", "", "")
    assert.Equal(t, "", got)
}

// TestBuildServerRegistration proves the POST /server body helper populates the
// server-side model.Server with the OAuthClientConfig (Type left empty so the
// receiver node infers it) and the resolved secret. This is the helper slice
// #86's `create stream poll receive --tx-alias` will call.
func TestBuildServerRegistration(t *testing.T) {
    cli := newTestCLI(t)
    cli.Data.stageSecret("ssfTxServer", "staged-secret")
    cli.Data.Servers["ssfTxServer"] = SsfServer{
        Alias: "ssfTxServer",
        Host:  "https://transmitter.example.com",
        OAuthClientConfig: &model.OAuthClientConfig{
            ClientID: "kc-client",
            TokenURL: "https://as.example.com/token",
            Scopes:   []string{"caep", "ssf"},
        },
    }

    reg, err := cli.Data.BuildServerRegistration("ssfTxServer", "", "")
    require.NoError(t, err)
    require.NotNil(t, reg)

    assert.Equal(t, "ssfTxServer", reg.Alias)
    assert.Equal(t, "https://transmitter.example.com", reg.Host)
    assert.Empty(t, reg.Type, "Type must be left empty for server-side inference")
    require.NotNil(t, reg.OAuthClientConfig)
    assert.Equal(t, "kc-client", reg.OAuthClientConfig.ClientID)
    assert.Equal(t, "https://as.example.com/token", reg.OAuthClientConfig.TokenURL)
    assert.Equal(t, []string{"caep", "ssf"}, reg.OAuthClientConfig.Scopes)
    assert.Equal(t, "staged-secret", reg.OAuthClientConfig.ClientSecret, "resolved secret must be on the POST body")
}

// TestBuildServerRegistration_NotOAuth errors clearly when the alias has no
// staged OAuth client config.
func TestBuildServerRegistration_NotOAuth(t *testing.T) {
    cli := newTestCLI(t)
    cli.Data.Servers["plain"] = SsfServer{Alias: "plain", Host: "https://x"}

    _, err := cli.Data.BuildServerRegistration("plain", "", "")
    assert.Error(t, err)
}
