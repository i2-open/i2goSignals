package main

import (
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "sync"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/authSupport"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// sstpTestServers stages two server aliases on the CLI: a local "client" alias
// (the initiator the command POSTs against) pointing at the supplied stub host,
// and a "server" alias (the responder named for the peer cascade).
func sstpTestServers(t *testing.T, cli *CLI, clientHost string) {
    t.Helper()
    cli.Data.Servers["clientNode"] = SsfServer{
        Alias:       "clientNode",
        Host:        clientHost,
        ClientToken: mintClientToken(t, authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt),
        Streams:     map[string]Stream{},
        ServerConfiguration: &model.TransmitterConfiguration{
            ConfigurationEndpoint: clientHost + "/stream",
        },
    }
    cli.Data.Servers["serverNode"] = SsfServer{
        Alias:   "serverNode",
        Host:    "https://peer.example.com",
        Streams: map[string]Stream{},
    }
}

// sstpStubResponse echoes a StreamStateRecord-shaped response so the command can
// extract PairId, rxSid and the endpoint for its output.
func sstpStubResponse(boot model.SstpPairBootstrap) model.StreamStateRecord {
    return model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{Id: "pair-123"},
        SstpInbound:         &model.StreamConfiguration{Id: "rx-456"},
        PairId:              "pair-123",
        SstpMethod: &model.SstpMethod{
            Role:        boot.Role,
            EndpointUrl: "https://client.example.com/sstp/pair-123",
            PeerPairId:  "peer-789",
        },
    }
}

// TestCreateStreamSstp_SymmetricFlagsBody proves the symmetric-flags input mode
// serializes a symmetric SstpPairBootstrap (identical Primary/Inbound business
// plane) and POSTs it to the client node's /stream endpoint with the named peer
// alias for cascade.
func TestCreateStreamSstp_SymmetricFlagsBody(t *testing.T) {
    cli := newTestCLI(t)

    var mu sync.Mutex
    var gotPath string
    var gotBoot model.SstpPairBootstrap
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        mu.Lock()
        defer mu.Unlock()
        gotPath = r.URL.Path
        body, _ := io.ReadAll(r.Body)
        _ = json.Unmarshal(body, &gotBoot)
        w.WriteHeader(http.StatusCreated)
        _ = json.NewEncoder(w).Encode(sstpStubResponse(gotBoot))
    }))
    defer stub.Close()

    sstpTestServers(t, cli, stub.URL)

    cmd := &CreateStreamSstpCmd{
        ClientAlias: "clientNode",
        ServerAlias: "serverNode",
        Iss:         "tx.example.com",
        IssJwksUrl:  "https://tx.example.com/jwks",
        Aud:         []string{"cluster.example.com"},
        Events:      []string{"*"},
        Mode:        "PUBLISH",
    }

    restore := withConfirmYes(t)
    defer restore()

    err := cmd.Run(cli)
    require.NoError(t, err)

    mu.Lock()
    defer mu.Unlock()
    assert.Equal(t, "/stream", gotPath)
    assert.Equal(t, model.SstpRoleInitiator, gotBoot.Role, "the issuing client side plays initiator")
    assert.Equal(t, "serverNode", gotBoot.PeerServerAlias, "the named server alias cascades the mirror")

    // Symmetric: Primary and Inbound carry identical business-plane inputs.
    assert.Equal(t, "tx.example.com", gotBoot.Primary.Iss)
    assert.Equal(t, "tx.example.com", gotBoot.Inbound.Iss)
    assert.Equal(t, "https://tx.example.com/jwks", gotBoot.Primary.IssJwksUrl)
    assert.Equal(t, "https://tx.example.com/jwks", gotBoot.Inbound.IssJwksUrl)
    assert.Equal(t, []string{"cluster.example.com"}, gotBoot.Primary.Aud)
    assert.Equal(t, []string{"cluster.example.com"}, gotBoot.Inbound.Aud)
    assert.Equal(t, []string{"*"}, gotBoot.Primary.Events)
    assert.Equal(t, []string{"*"}, gotBoot.Inbound.Events)
    assert.Equal(t, "PUBLISH", gotBoot.Primary.Mode)
    assert.Equal(t, "PUBLISH", gotBoot.Inbound.Mode)
}

// TestCreateStreamSstp_ConfigFileBody proves the --config-file input mode reads
// a per-direction SstpPairBootstrap from a file (asymmetric pair) and POSTs that
// body verbatim (role + peer alias filled in by the command).
func TestCreateStreamSstp_ConfigFileBody(t *testing.T) {
    cli := newTestCLI(t)

    var mu sync.Mutex
    var gotBoot model.SstpPairBootstrap
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        mu.Lock()
        defer mu.Unlock()
        body, _ := io.ReadAll(r.Body)
        _ = json.Unmarshal(body, &gotBoot)
        w.WriteHeader(http.StatusCreated)
        _ = json.NewEncoder(w).Encode(sstpStubResponse(gotBoot))
    }))
    defer stub.Close()

    sstpTestServers(t, cli, stub.URL)

    asym := model.SstpPairBootstrap{
        Description: "asymmetric multi-hop",
        Primary: model.SstpDirection{
            Iss:    "a.example.com",
            Aud:    []string{"b.example.com"},
            Events: []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
            Mode:   "FORWARD",
        },
        Inbound: model.SstpDirection{
            Iss:    "c.example.com",
            Aud:    []string{"d.example.com"},
            Events: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
            Mode:   "IMPORT",
        },
    }
    cfgBytes, _ := json.MarshalIndent(asym, "", "  ")
    cfgPath := filepath.Join(t.TempDir(), "asym.json")
    require.NoError(t, os.WriteFile(cfgPath, cfgBytes, 0o600))

    cmd := &CreateStreamSstpCmd{
        ClientAlias: "clientNode",
        ServerAlias: "serverNode",
        Config:      cfgPath,
    }

    restore := withConfirmYes(t)
    defer restore()

    err := cmd.Run(cli)
    require.NoError(t, err)

    mu.Lock()
    defer mu.Unlock()
    assert.Equal(t, model.SstpRoleInitiator, gotBoot.Role)
    assert.Equal(t, "serverNode", gotBoot.PeerServerAlias)
    assert.Equal(t, "asymmetric multi-hop", gotBoot.Description)
    assert.Equal(t, "a.example.com", gotBoot.Primary.Iss)
    assert.Equal(t, "c.example.com", gotBoot.Inbound.Iss)
    assert.Equal(t, "FORWARD", gotBoot.Primary.Mode)
    assert.Equal(t, "IMPORT", gotBoot.Inbound.Mode)
}

// TestCreateStreamSstp_RejectsFlagsWithConfig proves mixing symmetric flags with
// --config-file is a clear error before any request is made.
func TestCreateStreamSstp_RejectsFlagsWithConfig(t *testing.T) {
    cli := newTestCLI(t)
    sstpTestServers(t, cli, "https://unused.example.com")

    cmd := &CreateStreamSstpCmd{
        ClientAlias: "clientNode",
        ServerAlias: "serverNode",
        Config:      "/tmp/asym.json",
        Iss:         "tx.example.com",
    }

    err := cmd.Run(cli)
    require.Error(t, err)
    assert.Contains(t, err.Error(), "config")
}
