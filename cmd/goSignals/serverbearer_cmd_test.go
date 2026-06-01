package main

import (
    "net/http"
    "net/http/httptest"
    "path/filepath"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// seedOAuthSessionCLI builds a CLI wired with a single server + stream and a
// credentials store holding a live IdP session for the server's ActiveIssuer
// but NO ClientToken. This is the OAuth-login user shape of GH #138: a login
// session exists, but no legacy client admin token is stored. The handler URL
// is used for both the server Host and the ConfigurationEndpoint/StatusEndpoint
// so management calls land on the test server.
func seedOAuthSessionCLI(t *testing.T, handlerURL string) *CLI {
    t.Helper()
    dir := t.TempDir()
    g := Globals{ConfigFile: filepath.Join(dir, "config.json")}

    store := &CredentialStore{Path: credentialsPath(&g)}
    store.Set("https://idp.example.com", &Session{
        AccessToken: "session-token",
        Expiry:      time.Now().Add(time.Hour),
        LoggedInAt:  time.Now(),
    })
    require.NoError(t, store.Save())

    server := SsfServer{
        Alias:        "gs1",
        Host:         handlerURL,
        ActiveIssuer: "https://idp.example.com",
        // ClientToken deliberately empty — OAuth-login user.
        Streams: map[string]Stream{
            "s1": {Alias: "s1", Id: "stream-1"},
        },
        ServerConfiguration: &model.TransmitterConfiguration{
            ConfigurationEndpoint: handlerURL + "/stream",
            StatusEndpoint:        handlerURL + "/status",
        },
    }

    cli := &CLI{}
    cli.Globals = g
    cli.Data = ConfigData{
        Selected: "gs1",
        Servers:  map[string]SsfServer{"gs1": server},
    }
    return cli
}

// TestDeleteStreamCmd_UsesSessionBearer guards GH #138: an OAuth-login user
// (session present, ClientToken empty) must authenticate `delete stream` via
// the resolved session bearer, not emit an empty/legacy Authorization header.
func TestDeleteStreamCmd_UsesSessionBearer(t *testing.T) {
    var gotAuth string
    var sawRequest bool
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        sawRequest = true
        gotAuth = r.Header.Get("Authorization")
        w.WriteHeader(http.StatusOK)
    }))
    defer ts.Close()

    cli := seedOAuthSessionCLI(t, ts.URL)
    cmd := &DeleteStreamCmd{Alias: "s1"}
    err := cmd.Run(cli)
    require.NoError(t, err)
    require.True(t, sawRequest, "expected delete request to reach the server")
    assert.Equal(t, "Bearer session-token", gotAuth,
        "delete stream must carry the resolved session bearer (GH #138)")
}

// TestChangeSubjectFilter_UsesSessionBearer guards GH #138 for a subject-filter
// command: the shared add/remove path must authenticate an OAuth-login user via
// the resolved session bearer.
func TestChangeSubjectFilter_UsesSessionBearer(t *testing.T) {
    var gotAuth string
    var sawRequest bool
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        sawRequest = true
        gotAuth = r.Header.Get("Authorization")
        w.WriteHeader(http.StatusOK)
    }))
    defer ts.Close()

    cli := seedOAuthSessionCLI(t, ts.URL)
    err := changeSubjectFilter(cli, "s1", `{"format":"email","email":"a@example.com"}`,
        subjectArgFlags{}, false, "/add-subject", "added")
    require.NoError(t, err)
    require.True(t, sawRequest, "expected add-subject request to reach the server")
    assert.Equal(t, "Bearer session-token", gotAuth,
        "subject-filter change must carry the resolved session bearer (GH #138)")
}
