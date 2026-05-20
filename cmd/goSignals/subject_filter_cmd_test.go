package main

import (
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "net/url"
    "os"
    "strings"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestSubjectFilterShowCmdParses pins the kong shape of
// `subject-filter show <alias>` (PRD #97 issue #102). The command group lets
// an operator review the four subject-filter knobs (defaultSubjects, mode,
// event source, grace override) in one place.
func TestSubjectFilterShowCmdParses(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"subject-filter", "show", "my-stream"})
    require.NoError(t, err, "subject-filter show <alias> must parse")
    assert.Equal(t, "subject-filter show <alias>", ctx.Command())
    assert.Equal(t, "my-stream", pd.cli.SubjectFilter.Show.Alias)
}

// TestSubjectFilterSetCmdParses pins the kong shape of
// `subject-filter set <alias> [flags]` (PRD #97 issue #102). All four knobs
// are individually optional — a single PATCH-style call may change one or
// many. Empty/zero means "do not change" on the wire, matching the server's
// partial-update semantics in StreamUpdate.
func TestSubjectFilterSetCmdParses(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{
        "subject-filter", "set", "my-stream",
        "--default-subjects", "NONE",
        "--mode", "LOCAL",
        "--event-source", "AUDIENCE",
        "--grace-seconds", "600",
    })
    require.NoError(t, err, "subject-filter set <alias> with all four flags must parse")
    assert.Equal(t, "subject-filter set <alias>", ctx.Command())
    sc := pd.cli.SubjectFilter.Set
    assert.Equal(t, "my-stream", sc.Alias)
    assert.Equal(t, "NONE", sc.DefaultSubjects)
    assert.Equal(t, "LOCAL", sc.Mode)
    assert.Equal(t, "AUDIENCE", sc.EventSource)
    require.NotNil(t, sc.GraceSeconds, "--grace-seconds was supplied")
    assert.Equal(t, 600, *sc.GraceSeconds)
}

// TestSubjectFilterSetCmdRejectsInvalidMode verifies the kong enum rejects an
// unknown subject-filter mode at parse time rather than letting it round-trip
// to the server. The server's #89 validation is the authoritative gate, but
// catching obvious typos in the CLI is friendlier.
func TestSubjectFilterSetCmdRejectsInvalidMode(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{
        "subject-filter", "set", "my-stream", "--mode", "BOGUS",
    })
    assert.Error(t, err, "an unknown --mode value must be rejected at parse time")
}

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

// TestSubjectFilterShowCmdHitsReviewEndpoint verifies `subject-filter show`
// posts a stream_id body to the admin review endpoint and prints the four
// settings from the response. The mock server returns a populated review
// payload; the command must echo each knob.
func TestSubjectFilterShowCmdHitsReviewEndpoint(t *testing.T) {
    var reviewBody []byte
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) {
            t.Fatal("show must not PUT /stream")
            return 500, nil
        },
        func(body []byte) (int, []byte) {
            reviewBody = body
            resp := map[string]any{
                "stream_id":                     "sid-1",
                "mode":                          model.SubjectFilterModeLocal,
                "default_subjects":              model.DefaultSubjectsNone,
                "event_source":                  map[string]any{"type": model.EventSourceAudience},
                "subject_removal_grace_seconds": 600,
            }
            b, _ := json.Marshal(resp)
            return http.StatusOK, b
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SubjectFilterShowCmd{Alias: "sf-alias"}
    require.NoError(t, cmd.Run(cli))

    var req map[string]any
    require.NoError(t, json.Unmarshal(reviewBody, &req), "review body must be JSON: %s", string(reviewBody))
    assert.Equal(t, "sid-1", req["stream_id"], "request must carry stream_id")
    _, hasSubject := req["subject"]
    assert.False(t, hasSubject, "show settings must not request a point lookup")
}

// TestSubjectFilterSetCmdPutsPartialUpdate verifies `subject-filter set`
// translates its flags into the StreamStateRecord partial-update shape (knobs
// at the top level of the body, embedded StreamConfiguration left untouched)
// and posts to PUT /stream — no new server endpoint.
func TestSubjectFilterSetCmdPutsPartialUpdate(t *testing.T) {
    var updateBody []byte
    grace := 600
    ts := fakeServerForSubjectFilter(t,
        func(body []byte) (int, []byte) {
            updateBody = body
            return http.StatusOK, []byte(`{}`)
        },
        func(_ []byte) (int, []byte) {
            // Echo the values back so the post-update display works.
            resp := map[string]any{
                "stream_id":                     "sid-1",
                "mode":                          model.SubjectFilterModeLocal,
                "default_subjects":              model.DefaultSubjectsNone,
                "event_source":                  map[string]any{"type": model.EventSourceAudience},
                "subject_removal_grace_seconds": grace,
            }
            b, _ := json.Marshal(resp)
            return http.StatusOK, b
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SubjectFilterSetCmd{
        Alias:           "sf-alias",
        DefaultSubjects: model.DefaultSubjectsNone,
        Mode:            model.SubjectFilterModeLocal,
        EventSource:     model.EventSourceAudience,
        GraceSeconds:    &grace,
    }
    require.NoError(t, cmd.Run(cli))

    var got map[string]any
    require.NoError(t, json.Unmarshal(updateBody, &got), "update body must be JSON: %s", string(updateBody))
    assert.Equal(t, "sid-1", got["stream_id"], "stream_id must be in the body")
    assert.Equal(t, "sid-1", got["id"], "the embedded StreamConfiguration id must echo stream_id so the auth check resolves")
    assert.Equal(t, model.DefaultSubjectsNone, got["default_subjects"])
    assert.Equal(t, model.SubjectFilterModeLocal, got["subject_filter_mode"])
    require.NotNil(t, got["event_source"])
    es, _ := got["event_source"].(map[string]any)
    assert.Equal(t, model.EventSourceAudience, es["type"])
    assert.EqualValues(t, 600, got["subject_removal_grace_seconds"])
}

// TestSubjectFilterSetCmdOmitsUntouchedKnobs verifies a partial update — only
// --grace-seconds supplied — sends only that one knob, so untouched fields are
// not overwritten on the server side. This matches the server's partial-update
// semantics for the four operator knobs.
func TestSubjectFilterSetCmdOmitsUntouchedKnobs(t *testing.T) {
    var updateBody []byte
    grace := 300
    ts := fakeServerForSubjectFilter(t,
        func(body []byte) (int, []byte) {
            updateBody = body
            return http.StatusOK, []byte(`{}`)
        },
        func(_ []byte) (int, []byte) {
            return http.StatusOK, []byte(`{"stream_id":"sid-1"}`)
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SubjectFilterSetCmd{Alias: "sf-alias", GraceSeconds: &grace}
    require.NoError(t, cmd.Run(cli))

    var got map[string]any
    require.NoError(t, json.Unmarshal(updateBody, &got))
    assert.EqualValues(t, 300, got["subject_removal_grace_seconds"])
    _, hasDefaults := got["default_subjects"]
    _, hasMode := got["subject_filter_mode"]
    _, hasES := got["event_source"]
    assert.False(t, hasDefaults, "untouched defaultSubjects must be omitted")
    assert.False(t, hasMode, "untouched mode must be omitted")
    assert.False(t, hasES, "untouched event_source must be omitted")
}

// TestSubjectFilterSetCmdSurfacesValidationError verifies a server-side
// rejection (e.g. PRD #89's invalid LOCAL/HYBRID combination, or a negative
// grace value from #98) is returned as an error to the caller. The CLI does
// not retry or mutate local state on a validation failure.
func TestSubjectFilterSetCmdSurfacesValidationError(t *testing.T) {
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) {
            return http.StatusBadRequest,
                []byte("invalid subject-filter configuration: HYBRID requires a filtering-capable upstream\n")
        },
        func(_ []byte) (int, []byte) {
            t.Fatal("review must not be called after a validation failure")
            return 500, nil
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SubjectFilterSetCmd{Alias: "sf-alias", Mode: model.SubjectFilterModeHybrid}
    err := cmd.Run(cli)
    require.Error(t, err, "a 400 from the server must propagate to the CLI")
    assert.True(t, strings.Contains(err.Error(), "HYBRID requires a filtering-capable upstream"),
        "the server's validation message must surface to the operator, got %q", err.Error())
}

// TestSubjectFilterSetCmdSurfacesReceiverGraceIgnore verifies that a
// `--grace-seconds` set on a receiver stream is silently dropped server-side
// (per PRD #97 issue #98's WARN-and-ignore), and the post-update settings
// display reflects the persisted value (0) rather than the requested value.
// This is the operator's visibility into the server's WARN behavior.
func TestSubjectFilterSetCmdSurfacesReceiverGraceIgnore(t *testing.T) {
    grace := 600
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) { return http.StatusOK, []byte(`{}`) },
        func(_ []byte) (int, []byte) {
            // Server kept the persisted value at 0 — the ignore in action.
            resp := map[string]any{
                "stream_id":                     "sid-1",
                "subject_removal_grace_seconds": 0,
            }
            b, _ := json.Marshal(resp)
            return http.StatusOK, b
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SubjectFilterSetCmd{Alias: "sf-alias", GraceSeconds: &grace}

    // Capture stdout to inspect what the operator sees printed.
    r, w, _ := os.Pipe()
    save := os.Stdout
    os.Stdout = w
    err := cmd.Run(cli)
    _ = w.Close()
    os.Stdout = save
    require.NoError(t, err)
    out, _ := io.ReadAll(r)

    assert.Contains(t, string(out), "subject_removal_grace_seconds: 0",
        "post-update display must show the persisted value (0) so the server's ignore is visible to the operator")
}
