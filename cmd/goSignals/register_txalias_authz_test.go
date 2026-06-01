package main

import (
    "crypto/rand"
    "crypto/rsa"
    "net/http"
    "net/http/httptest"
    "sync/atomic"
    "testing"
    "time"

    jwt "github.com/golang-jwt/jwt/v5"
    "github.com/i2-open/i2goSignals/pkg/authSupport"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// mintClientToken builds a goSignals ClientToken JWT carrying the given roles,
// signed with a throwaway key. The CLI offline precheck decodes claims WITHOUT
// verifying the signature, so the key is irrelevant to the test.
func mintClientToken(t *testing.T, roles ...string) string {
    t.Helper()
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    require.NoError(t, err)
    eat := authSupport.EventAuthToken{
        ProjectId: "proj-A",
        Roles:     roles,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
            Issuer:    "DEFAULT",
        },
    }
    tok := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
    signed, err := tok.SignedString(key)
    require.NoError(t, err)
    return signed
}

// TestRegisterTxAliasServer_FailFastOnStreamScope proves the offline precheck:
// a node credential that decodes to a stream-only ClientToken short-circuits
// BEFORE any network call with an actionable admin-scope error.
func TestRegisterTxAliasServer_FailFastOnStreamScope(t *testing.T) {
    cli := newTestCLI(t)

    var called int32
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&called, 1)
        w.WriteHeader(http.StatusCreated)
    }))
    defer stub.Close()

    stagedTxServer(t, cli, "ssfTx", stub.URL)
    node := cli.Data.Servers["node"]
    node.ClientToken = mintClientToken(t, authSupport.ScopeStreamMgmt)
    cli.Data.Servers["node"] = node
    n, err := cli.Data.GetServer("node")
    require.NoError(t, err)

    err = cli.registerTxAliasServer(n, "ssfTx", "", "")
    require.Error(t, err)
    assert.Contains(t, err.Error(), "admin", "stream-only credential must fail fast with admin-scope guidance")
    assert.Equal(t, int32(0), atomic.LoadInt32(&called), "fail-fast must not make the network call")
}

// TestRegisterTxAliasServer_AdminTokenProceeds proves an admin ClientToken
// passes the offline precheck and the POST /server call is made.
func TestRegisterTxAliasServer_AdminTokenProceeds(t *testing.T) {
    cli := newTestCLI(t)

    var called int32
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&called, 1)
        w.WriteHeader(http.StatusCreated)
        _, _ = w.Write([]byte("{}"))
    }))
    defer stub.Close()

    stagedTxServer(t, cli, "ssfTx", stub.URL)
    node := cli.Data.Servers["node"]
    node.ClientToken = mintClientToken(t, authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt)
    cli.Data.Servers["node"] = node
    n, err := cli.Data.GetServer("node")
    require.NoError(t, err)

    err = cli.registerTxAliasServer(n, "ssfTx", "", "")
    require.NoError(t, err)
    assert.Equal(t, int32(1), atomic.LoadInt32(&called), "admin credential must proceed to the network call")
}

// TestRegisterTxAliasServer_OpaqueTokenProceeds proves graceful degradation:
// an opaque (non-JWT) credential cannot be classified locally, so the call is
// NOT blocked and proceeds to the network.
func TestRegisterTxAliasServer_OpaqueTokenProceeds(t *testing.T) {
    cli := newTestCLI(t)

    var called int32
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&called, 1)
        w.WriteHeader(http.StatusCreated)
    }))
    defer stub.Close()

    stagedTxServer(t, cli, "ssfTx", stub.URL) // ClientToken "node-admin-token" is opaque
    n, err := cli.Data.GetServer("node")
    require.NoError(t, err)

    err = cli.registerTxAliasServer(n, "ssfTx", "", "")
    require.NoError(t, err)
    assert.Equal(t, int32(1), atomic.LoadInt32(&called), "an unclassifiable credential must not be blocked offline")
}

// TestRegisterTxAliasServer_ReactiveTranslates403 proves a 403 from POST /server
// is translated into the SAME actionable admin-scope message rather than leaking
// a raw status/body.
func TestRegisterTxAliasServer_ReactiveTranslates403(t *testing.T) {
    cli := newTestCLI(t)

    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusForbidden)
        _, _ = w.Write([]byte("forbidden"))
    }))
    defer stub.Close()

    stagedTxServer(t, cli, "ssfTx", stub.URL) // opaque token -> precheck proceeds
    n, err := cli.Data.GetServer("node")
    require.NoError(t, err)

    err = cli.registerTxAliasServer(n, "ssfTx", "", "")
    require.Error(t, err)
    assert.Contains(t, err.Error(), "admin", "a 403 must be translated into actionable admin-scope guidance")
}
