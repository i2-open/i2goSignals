package main

import (
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "net/url"
    "os"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestSetStreamStatusIncludesStreamIdAndContentType locks down the wire-shape
// fix from commit 7ecd00e (issue #194). SSF §8.1.2.2 makes `stream_id`
// REQUIRED in the POST /status request body, and the OpenID conformance suite
// only parses the body as JSON when the `Content-Type: application/json`
// header is set. Without these the suite's status-update modules silently
// reject the request and the receiver test plan times out at ~240s. The CLI's
// `SetStreamStatusCmd.Run` (`cmd/goSignals/commands.go`) MUST send both.
//
// Reverting 7ecd00e (dropping `StreamId: stream.Id` from the UpdateStreamStatus
// literal, or removing the explicit Content-Type header) makes this test fail.
func TestSetStreamStatusIncludesStreamIdAndContentType(t *testing.T) {
    const streamId = "sid-194"

    var (
        recordedMethod      string
        recordedContentType string
        recordedBody        []byte
    )

    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        recordedMethod = r.Method
        recordedContentType = r.Header.Get("Content-Type")
        recordedBody, _ = io.ReadAll(r.Body)
        // Return a minimal valid status response so the command's Run exits
        // cleanly after the request has been recorded.
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte(`{"stream_id":"` + streamId + `","status":"enabled"}`))
    })
    ts := httptest.NewServer(handler)
    defer ts.Close()

    cli := newCliForStatusTest(t, ts.URL, streamId)

    cmd := &SetStreamStatusCmd{
        Alias: "status-alias",
        State: "active",
    }

    // SetStreamStatusCmd.Run prints to stdout on success; suppress to keep
    // test output clean.
    save := os.Stdout
    r, w, _ := os.Pipe()
    os.Stdout = w
    err := cmd.Run(cli)
    _ = w.Close()
    os.Stdout = save
    _, _ = io.ReadAll(r)

    require.NoError(t, err, "SetStreamStatusCmd.Run must succeed against the mock /status endpoint")

    assert.Equal(t, http.MethodPost, recordedMethod, "POST /status is the SSF §8.1.2.2 request shape")
    assert.Equal(t, "application/json", recordedContentType,
        "the request MUST set Content-Type: application/json so spec-conformant receivers (and the OpenID conformance suite) parse the body as JSON")

    var bodyJson map[string]any
    require.NoError(t, json.Unmarshal(recordedBody, &bodyJson),
        "the recorded request body MUST be JSON, got %q", string(recordedBody))
    assert.Equal(t, streamId, bodyJson["stream_id"],
        "SSF §8.1.2.2 makes stream_id REQUIRED in the POST /status request body; commit 7ecd00e added it to model.UpdateStreamStatus")
}

// newCliForStatusTest builds a populated CLI whose `status-alias` resolves
// against `ts` and carries the configured stream id. The fake server's URL is
// used directly as the SSF status_endpoint — the command POSTs to it (plus a
// stream_id query parameter the legacy SUT also accepts).
func newCliForStatusTest(t *testing.T, tsURL, streamId string) *CLI {
    t.Helper()
    parsed, err := url.Parse(tsURL)
    require.NoError(t, err)

    server := SsfServer{
        Alias:       "test-status",
        Host:        parsed.String(),
        ClientToken: "admin-token",
        Streams: map[string]Stream{
            "status-alias": {Alias: "status-alias", Id: streamId},
        },
        ServerConfiguration: &model.TransmitterConfiguration{
            StatusEndpoint: parsed.String() + "/status",
        },
    }
    cli := &CLI{}
    cli.Data = ConfigData{
        Servers:  map[string]SsfServer{"test-status": server},
        Selected: "test-status",
    }
    return cli
}
