package main

import (
    "io"
    "net/http"
    "net/http/httptest"
    "net/url"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/require"
)

// fakeServerForSubjectFilter spins up an httptest server that handles the two
// endpoints the subject-filter command group uses: PUT /stream (the existing
// StreamUpdate path) and POST /subject-filter/review. The handlers are
// behavior-driven via the closure args so individual tests can pin the wire
// shape they care about.
func fakeServerForSubjectFilter(t *testing.T,
    onUpdate func(body []byte) (int, []byte),
    onReview func(body []byte) (int, []byte),
) *httptest.Server {
    t.Helper()
    mux := http.NewServeMux()
    mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPut {
            w.WriteHeader(http.StatusMethodNotAllowed)
            return
        }
        body, _ := io.ReadAll(r.Body)
        status, resp := onUpdate(body)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        _, _ = w.Write(resp)
    })
    mux.HandleFunc("/subject-filter/review", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            w.WriteHeader(http.StatusMethodNotAllowed)
            return
        }
        body, _ := io.ReadAll(r.Body)
        status, resp := onReview(body)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        _, _ = w.Write(resp)
    })
    return httptest.NewServer(mux)
}

// makeServerForCli builds a populated SsfServer + Stream so the cli commands
// resolve the alias through the standard ConfigData path.
func makeServerForCli(t *testing.T, tsURL, streamId string) (*CLI, *SsfServer) {
    t.Helper()
    parsed, err := url.Parse(tsURL)
    require.NoError(t, err)
    server := SsfServer{
        Alias:       "test-sf",
        Host:        parsed.String(),
        ClientToken: "admin-token",
        Streams: map[string]Stream{
            "sf-alias": {Alias: "sf-alias", Id: streamId},
        },
        ServerConfiguration: &model.TransmitterConfiguration{
            ConfigurationEndpoint: parsed.String() + "/stream",
        },
    }
    cli := &CLI{}
    cli.Data = ConfigData{
        Servers:  map[string]SsfServer{"test-sf": server},
        Selected: "test-sf",
    }
    return cli, &server
}
