package main

import (
    "encoding/json"
    "net/http"
    "strings"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestGetSubjectFilterConfigCmdParses pins the kong shape of
// `get subject-filter config <alias>` (PRD #106 issue #107). The `config`
// sub-command shows the four operator-tunable subject-filter knobs
// (defaultSubjects, mode, event source, removal grace) — as distinct from a
// future `status` sub-command which surfaces runtime-derived filter-table
// state.
func TestGetSubjectFilterConfigCmdParses(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"get", "subject-filter", "config", "my-stream"})
    require.NoError(t, err, "get subject-filter config <alias> must parse")
    assert.Equal(t, "get subject-filter config <alias>", ctx.Command())
    assert.Equal(t, "my-stream", pd.cli.Get.SubjectFilter.Config.Alias)
}

// TestGetSubjectFilterConfigCmdAliasOptional verifies the alias arg is
// optional — when omitted the command falls back to the selected stream.
func TestGetSubjectFilterConfigCmdAliasOptional(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"get", "subject-filter", "config"})
    require.NoError(t, err, "get subject-filter config (no alias) must parse")
    assert.Equal(t, "get subject-filter config", ctx.Command())
    assert.Empty(t, pd.cli.Get.SubjectFilter.Config.Alias)
}

// TestGetSubjectFilterConfigCmdHitsReviewEndpoint verifies `get subject-filter
// config` POSTs a settings-only body (stream_id, no subject) to the admin
// /subject-filter/review endpoint and prints the four operator knobs from the
// response. It reuses the PRD #97 review endpoint unchanged — this is a
// CLI-only restructure.
func TestGetSubjectFilterConfigCmdHitsReviewEndpoint(t *testing.T) {
    var reviewMethod, reviewPath string
    var reviewBody []byte
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) {
            t.Fatal("get subject-filter config must not PUT /stream")
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
    // Capture the exact method/path the command used.
    base := ts.Config.Handler
    ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        reviewMethod, reviewPath = r.Method, r.URL.Path
        base.ServeHTTP(w, r)
    })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &GetSubjectFilterConfigCmd{Alias: "sf-alias"}
    require.NoError(t, cmd.Run(cli))

    assert.Equal(t, http.MethodPost, reviewMethod, "config must POST")
    assert.Equal(t, "/subject-filter/review", reviewPath, "config must hit the review endpoint")

    var req map[string]any
    require.NoError(t, json.Unmarshal(reviewBody, &req), "review body must be JSON: %s", string(reviewBody))
    assert.Equal(t, "sid-1", req["stream_id"], "request must carry stream_id")
    _, hasSubject := req["subject"]
    assert.False(t, hasSubject, "config (settings-only) must not request a point lookup")
}

// TestGetSubjectFilterConfigCmdDisabledServer verifies a 404 from the review
// endpoint (subject filtering disabled server-wide) is surfaced as a plain
// operator-facing message rather than a raw HTTP status.
func TestGetSubjectFilterConfigCmdDisabledServer(t *testing.T) {
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) { return 500, nil },
        func(_ []byte) (int, []byte) {
            return http.StatusNotFound, []byte("not found\n")
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &GetSubjectFilterConfigCmd{Alias: "sf-alias"}
    err := cmd.Run(cli)
    require.Error(t, err, "a 404 must surface as an error")
    assert.Equal(t, "subject filtering is disabled on this server", err.Error(),
        "the 404 must be a plain message, not a raw HTTP status")
}

// TestFormatSubjectFilterSettingsUnsetKnobs verifies the retained PRD #97
// settings formatter renders unset operator knobs as "(unset)" so an operator
// can tell an explicit value from a fall-through to the server-wide default.
func TestFormatSubjectFilterSettingsUnsetKnobs(t *testing.T) {
    out := formatSubjectFilterSettings("sf-alias", &subjectFilterReviewWire{StreamId: "sid-1"})
    assert.Contains(t, out, "stream_id:                     sid-1")
    assert.Contains(t, out, "default_subjects:              (unset)")
    assert.Contains(t, out, "mode:                          (unset)")
    assert.Contains(t, out, "event_source:                  (unset)")
    assert.Contains(t, out, "subject_removal_grace_seconds: 0")
    assert.True(t, strings.HasPrefix(out, "Subject-filter settings for [sf-alias]:"))
}
