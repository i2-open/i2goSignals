package main

import (
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "sync"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/authSupport"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// withConfirmYes pipes "Y\n" to os.Stdin so ConfirmProceed proceeds, restoring
// the original stdin when the returned func is called.
func withConfirmYes(t *testing.T) func() {
    t.Helper()
    orig := os.Stdin
    r, w, err := os.Pipe()
    require.NoError(t, err)
    _, _ = w.Write([]byte("Y\n"))
    _ = w.Close()
    os.Stdin = r
    return func() {
        os.Stdin = orig
        _ = r.Close()
    }
}

// stagedTxServer registers an OAuth-style foreign transmitter alias on the CLI
// (as `add server --client-id` would) plus a target receiver node pointing at
// the supplied host, mirroring how `create stream poll receive --tx-alias`
// operates: the alias names the foreign transmitter, the node is where the
// receive stream (and the /server registration) is created.
func stagedTxServer(t *testing.T, cli *CLI, alias, nodeHost string) {
    t.Helper()
    cli.Data.stageSecret(alias, "staged-secret")
    cli.Data.Servers[alias] = SsfServer{
        Alias: alias,
        Host:  "https://transmitter.example.com",
        OAuthClientConfig: &model.OAuthClientConfig{
            ClientID: "kc-client",
            TokenURL: "https://as.example.com/token",
            Scopes:   []string{"caep", "ssf"},
        },
    }
    cli.Data.Servers["node"] = SsfServer{
        Alias: "node",
        Host:  nodeHost,
        // An admin-scoped ClientToken so the offline precheck (#139) passes; the
        // POST /server call requires admin and the precheck mirrors that.
        ClientToken: mintClientToken(t, authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt),
        Streams:     map[string]Stream{},
    }
}

// TestRegisterTxAliasServer_PostsRegistration proves that registering a
// tx-alias against a node POSTs the BuildServerRegistration body to the node's
// /server endpoint, authenticated with the node's bearer credential, and that
// the resolved client secret rides on the request body (never on disk).
func TestRegisterTxAliasServer_PostsRegistration(t *testing.T) {
    cli := newTestCLI(t)

    var gotPath, gotAuth string
    var gotServer model.Server
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotPath = r.URL.Path
        gotAuth = r.Header.Get("Authorization")
        body, _ := io.ReadAll(r.Body)
        _ = json.Unmarshal(body, &gotServer)
        w.WriteHeader(http.StatusCreated)
        _ = json.NewEncoder(w).Encode(gotServer)
    }))
    defer stub.Close()

    stagedTxServer(t, cli, "ssfTx", stub.URL)
    node, err := cli.Data.GetServer("node")
    require.NoError(t, err)

    err = cli.registerTxAliasServer(node, "ssfTx", "", "")
    require.NoError(t, err)

    assert.Equal(t, "/server", gotPath)
    assert.Equal(t, "Bearer "+node.ClientToken, gotAuth, "the node's admin ClientToken must authenticate the POST /server call")
    assert.Equal(t, "ssfTx", gotServer.Alias)
    assert.Equal(t, "kc-client", gotServer.OAuthClientConfig.ClientID)
    assert.Equal(t, "staged-secret", gotServer.OAuthClientConfig.ClientSecret,
        "resolved secret must ride on the POST /server body")
}

// TestRegisterTxAliasServer_ConflictIsBenign proves a 409 (transmitter already
// registered on the node) is treated as success — the auto-registration path
// is idempotent.
func TestRegisterTxAliasServer_ConflictIsBenign(t *testing.T) {
    cli := newTestCLI(t)

    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusConflict)
    }))
    defer stub.Close()

    stagedTxServer(t, cli, "ssfTx", stub.URL)
    node, err := cli.Data.GetServer("node")
    require.NoError(t, err)

    err = cli.registerTxAliasServer(node, "ssfTx", "", "")
    assert.NoError(t, err, "409 Conflict must be benign")
}

// TestRegisterTxAliasServer_ServerErrorPropagates proves non-2xx/non-409
// statuses surface as errors so a genuine failure isn't silently swallowed.
func TestRegisterTxAliasServer_ServerErrorPropagates(t *testing.T) {
    cli := newTestCLI(t)

    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusBadRequest)
    }))
    defer stub.Close()

    stagedTxServer(t, cli, "ssfTx", stub.URL)
    node, err := cli.Data.GetServer("node")
    require.NoError(t, err)

    err = cli.registerTxAliasServer(node, "ssfTx", "", "")
    assert.Error(t, err)
}

// TestRegisterTxAliasServer_FlagSecretResolves proves the --secret flag is used
// when no secret was staged in-process, so non-interactive flows can supply the
// client secret without it ever living on disk.
func TestRegisterTxAliasServer_FlagSecretResolves(t *testing.T) {
    cli := newTestCLI(t)

    var gotSecret string
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        var srv model.Server
        body, _ := io.ReadAll(r.Body)
        _ = json.Unmarshal(body, &srv)
        if srv.OAuthClientConfig != nil {
            gotSecret = srv.OAuthClientConfig.ClientSecret
        }
        w.WriteHeader(http.StatusCreated)
        _, _ = w.Write([]byte("{}"))
    }))
    defer stub.Close()

    // Register the foreign transmitter WITHOUT staging a secret.
    cli.Data.Servers["ssfTx"] = SsfServer{
        Alias: "ssfTx",
        Host:  "https://transmitter.example.com",
        OAuthClientConfig: &model.OAuthClientConfig{
            ClientID: "kc-client",
            TokenURL: "https://as.example.com/token",
        },
    }
    cli.Data.Servers["node"] = SsfServer{Alias: "node", Host: stub.URL, ClientToken: "tok", Streams: map[string]Stream{}}
    node, err := cli.Data.GetServer("node")
    require.NoError(t, err)

    err = cli.registerTxAliasServer(node, "ssfTx", "flag-secret", "")
    require.NoError(t, err)
    assert.Equal(t, "flag-secret", gotSecret, "--secret flag must resolve onto the POST body when nothing staged")
}

// TestCreatePollReceive_TxAliasCarriesThroughAndRegisters proves the end-to-end
// CLI behaviour for `create stream poll receive --tx-alias`:
//   - the foreign transmitter is registered on the node via POST /server
//   - the stream-creation request carries tx_alias so it reaches the server-side
//     StreamService.CreateStream TxAlias auto-registration path
func TestCreatePollReceive_TxAliasCarriesThroughAndRegisters(t *testing.T) {
    cli := newTestCLI(t)
    require.NoError(t, cli.Data.checkConfigPath(&cli.Globals))

    var mu sync.Mutex
    serverPosted := false
    var streamReg model.StreamConfiguration

    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        mu.Lock()
        defer mu.Unlock()
        switch r.URL.Path {
        case "/server":
            serverPosted = true
            w.WriteHeader(http.StatusCreated)
            _, _ = w.Write([]byte("{}"))
        case "/stream":
            body, _ := io.ReadAll(r.Body)
            _ = json.Unmarshal(body, &streamReg)
            // Echo a minimal valid StreamConfiguration back.
            resp := model.StreamConfiguration{
                Id:  "stream-123",
                Aud: streamReg.Aud,
                Iss: streamReg.Iss,
                Delivery: &model.OneOfStreamConfigurationDelivery{
                    PollReceiveMethod: &model.PollReceiveMethod{
                        Method:      model.ReceivePoll,
                        EndpointUrl: "http://tx/poll/stream-123",
                    },
                },
            }
            w.WriteHeader(http.StatusCreated)
            _ = json.NewEncoder(w).Encode(resp)
        default:
            w.WriteHeader(http.StatusNotFound)
        }
    }))
    defer stub.Close()

    stagedTxServer(t, cli, "ssfTx", stub.URL)
    node := cli.Data.Servers["node"]
    node.ServerConfiguration = &model.TransmitterConfiguration{
        ConfigurationEndpoint: stub.URL + "/stream",
    }
    cli.Data.Servers["node"] = node

    cli.Create.Stream = CreateStreamCmd{
        Aud:    []string{"cluster.example.com"},
        Iss:    "tx.example.com",
        Name:   "scimPollRec",
        Events: []string{"*"},
    }

    cmd := &CreatePollReceiverCmd{
        Alias:   "node",
        TxAlias: "ssfTx",
        Mode:    "IMPORT",
    }

    restore := withConfirmYes(t)
    defer restore()

    err := cmd.Run(cli)
    require.NoError(t, err)

    mu.Lock()
    defer mu.Unlock()
    assert.True(t, serverPosted, "tx-alias must trigger POST /server registration on the node")
    require.NotNil(t, streamReg.TxAlias, "stream-create request must carry tx_alias")
    assert.Equal(t, "ssfTx", *streamReg.TxAlias, "tx_alias must reach the server-side auto-registration path")
}
