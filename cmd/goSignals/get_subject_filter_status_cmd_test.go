package main

import (
    "encoding/json"
    "net/http"
    "os"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestGetSubjectFilterStatusCmdParses pins the kong shape of
// `get subject-filter status <alias>` (PRD #106 issue #108). The `status`
// sub-command surfaces runtime-derived filter-table state — counts, the
// pending-removal list, and an optional point lookup — as distinct from the
// `config` sub-command which shows the operator-tunable knobs.
func TestGetSubjectFilterStatusCmdParses(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"get", "subject-filter", "status", "my-stream"})
    require.NoError(t, err, "get subject-filter status <alias> must parse")
    assert.Equal(t, "get subject-filter status <alias>", ctx.Command())
    assert.Equal(t, "my-stream", pd.cli.Get.SubjectFilter.Status.Alias)
}

// TestGetSubjectFilterStatusCmdAliasOptional verifies the alias arg is
// optional — when omitted the command falls back to the selected stream.
func TestGetSubjectFilterStatusCmdAliasOptional(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"get", "subject-filter", "status"})
    require.NoError(t, err, "get subject-filter status (no alias) must parse")
    assert.Equal(t, "get subject-filter status", ctx.Command())
    assert.Empty(t, pd.cli.Get.SubjectFilter.Status.Alias)
}

// TestGetSubjectFilterStatusCmdPositionalSubject verifies the optional second
// positional carries a subject-JSON literal for a point lookup. With two
// positionals kong fills left-to-right, so <alias> must be given explicitly
// whenever a positional subject is supplied.
func TestGetSubjectFilterStatusCmdPositionalSubject(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{
        "get", "subject-filter", "status", "my-stream",
        `{"format":"email","email":"alice@example.com"}`,
    })
    require.NoError(t, err, "get subject-filter status <alias> <subject-json> must parse")
    assert.Equal(t, "get subject-filter status <alias> <subject-json>", ctx.Command())
    assert.Equal(t, "my-stream", pd.cli.Get.SubjectFilter.Status.Alias)
    assert.Equal(t, `{"format":"email","email":"alice@example.com"}`,
        pd.cli.Get.SubjectFilter.Status.SubjectJson)
}

// TestGetSubjectFilterStatusCmdFieldFlags verifies the format field flags
// parse onto the status command — the ergonomic point-lookup path that does
// not require hand-writing JSON.
func TestGetSubjectFilterStatusCmdFieldFlags(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{
        "get", "subject-filter", "status", "my-stream",
        "--email", "bob@example.com",
    })
    require.NoError(t, err, "get subject-filter status with --email must parse")
    assert.Equal(t, "bob@example.com", pd.cli.Get.SubjectFilter.Status.Email)
}

// TestGetSubjectFilterStatusCmdSummary verifies `get subject-filter status`
// with no subject POSTs a settings-only body (stream_id, no subject) to the
// admin /subject-filter/review endpoint and prints the aggregate counts and
// the pending-removal list.
func TestGetSubjectFilterStatusCmdSummary(t *testing.T) {
    var method, path string
    var reviewBody []byte
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) {
            t.Fatal("get subject-filter status must not PUT /stream")
            return 500, nil
        },
        func(body []byte) (int, []byte) {
            reviewBody = body
            resp := map[string]any{
                "stream_id": "sid-1",
                "counts":    map[string]any{"total": 5, "pending": 2},
                "pending": []map[string]any{
                    {"canonical_key": "email:alice@example.com", "kind": "explicit",
                        "enforce_at": "2026-06-01T00:00:00Z"},
                },
            }
            b, _ := json.Marshal(resp)
            return http.StatusOK, b
        })
    base := ts.Config.Handler
    ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        method, path = r.Method, r.URL.Path
        base.ServeHTTP(w, r)
    })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &GetSubjectFilterStatusCmd{Alias: "sf-alias"}
    require.NoError(t, cmd.Run(cli))

    assert.Equal(t, http.MethodPost, method, "status must POST")
    assert.Equal(t, "/subject-filter/review", path, "status must hit the review endpoint")

    var req map[string]any
    require.NoError(t, json.Unmarshal(reviewBody, &req), "review body must be JSON: %s", string(reviewBody))
    assert.Equal(t, "sid-1", req["stream_id"], "request must carry stream_id")
    _, hasSubject := req["subject"]
    assert.False(t, hasSubject, "the summary (no-subject) case must not request a point lookup")
}

// TestGetSubjectFilterStatusCmdPointLookup verifies that a subject (positional
// JSON) is carried in the request body so the response includes a point-lookup
// result.
func TestGetSubjectFilterStatusCmdPointLookup(t *testing.T) {
    var reviewBody []byte
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) { return 500, nil },
        func(body []byte) (int, []byte) {
            reviewBody = body
            resp := map[string]any{
                "stream_id": "sid-1",
                "counts":    map[string]any{"total": 1, "pending": 0},
                "lookup": map[string]any{
                    "subject":  map[string]any{"format": "email", "email": "bob@example.com"},
                    "found":    true,
                    "kind":     "explicit",
                    "delivers": true,
                },
            }
            b, _ := json.Marshal(resp)
            return http.StatusOK, b
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &GetSubjectFilterStatusCmd{
        Alias:       "sf-alias",
        SubjectJson: `{"format":"email","email":"bob@example.com"}`,
    }
    require.NoError(t, cmd.Run(cli))

    var req map[string]any
    require.NoError(t, json.Unmarshal(reviewBody, &req))
    assert.Equal(t, "sid-1", req["stream_id"])
    subject, hasSubject := req["subject"].(map[string]any)
    require.True(t, hasSubject, "a point lookup must carry the subject in the body")
    assert.Equal(t, "email", subject["format"])
    assert.Equal(t, "bob@example.com", subject["email"])
}

// TestGetSubjectFilterStatusCmdPointLookupFieldFlags verifies a point lookup
// can be supplied via the format field flags rather than positional JSON — the
// shared subject-argument parser feeds the same request body.
func TestGetSubjectFilterStatusCmdPointLookupFieldFlags(t *testing.T) {
    var reviewBody []byte
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) { return 500, nil },
        func(body []byte) (int, []byte) {
            reviewBody = body
            return http.StatusOK, []byte(`{"stream_id":"sid-1","lookup":{"found":false,"delivers":false}}`)
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &GetSubjectFilterStatusCmd{Alias: "sf-alias", Email: "carol@example.com"}
    require.NoError(t, cmd.Run(cli))

    var req map[string]any
    require.NoError(t, json.Unmarshal(reviewBody, &req))
    subject, hasSubject := req["subject"].(map[string]any)
    require.True(t, hasSubject, "field flags must produce a subject in the body")
    assert.Equal(t, "email", subject["format"])
    assert.Equal(t, "carol@example.com", subject["email"])
}

// TestGetSubjectFilterStatusCmdDisabledServer verifies a 404 from the review
// endpoint (subject filtering disabled server-wide) surfaces the plain
// disabled message rather than a raw HTTP status.
func TestGetSubjectFilterStatusCmdDisabledServer(t *testing.T) {
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) { return 500, nil },
        func(_ []byte) (int, []byte) {
            return http.StatusNotFound, []byte("not found\n")
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &GetSubjectFilterStatusCmd{Alias: "sf-alias"}
    err := cmd.Run(cli)
    require.Error(t, err, "a 404 must surface as an error")
    assert.Equal(t, "subject filtering is disabled on this server", err.Error(),
        "the 404 must be the plain disabled message, not a raw HTTP status")
}

// TestGetSubjectFilterStatusCmdHonoursOutputFile verifies the status output is
// written to the file named by -o (the CLI's Output field), matching the
// output-writer wiring the rest of the get commands use.
func TestGetSubjectFilterStatusCmdHonoursOutputFile(t *testing.T) {
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) { return 500, nil },
        func(_ []byte) (int, []byte) {
            return http.StatusOK, []byte(`{"stream_id":"sid-1","counts":{"total":3,"pending":1}}`)
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    outPath := filepath.Join(t.TempDir(), "status.txt")
    cli.Output = outPath

    cmd := &GetSubjectFilterStatusCmd{Alias: "sf-alias"}
    require.NoError(t, cmd.Run(cli))

    written, err := os.ReadFile(outPath)
    require.NoError(t, err, "-o must produce a file")
    assert.Contains(t, string(written), "Subject-filter status for [sf-alias]:")
    assert.Contains(t, string(written), "filter-table entries:  3")
}
