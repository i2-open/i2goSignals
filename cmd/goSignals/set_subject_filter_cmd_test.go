package main

import (
    "encoding/json"
    "io"
    "net/http"
    "os"
    "strings"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestSetSubjectFilterConfigCmdParses pins the kong shape of
// `set subject-filter config <alias> [knob flags]` (PRD #106 issue #109). Each
// of the five operator knobs is individually optional — a single call may
// change one knob or many. `--source-stream-ids` accepts a comma-separated
// list and closes the gap that left EXPLICIT event sources unconfigurable
// from the CLI.
func TestSetSubjectFilterConfigCmdParses(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{
        "set", "subject-filter", "config", "my-stream",
        "--default-subjects", "NONE",
        "--mode", "LOCAL",
        "--event-source", "EXPLICIT",
        "--source-stream-ids", "sid-a,sid-b",
        "--grace-seconds", "600",
    })
    require.NoError(t, err, "set subject-filter config <alias> with all knob flags must parse")
    assert.Equal(t, "set subject-filter config <alias>", ctx.Command())
    sc := pd.cli.Set.SubjectFilter.Config
    assert.Equal(t, "my-stream", sc.Alias)
    assert.Equal(t, "NONE", sc.DefaultSubjects)
    assert.Equal(t, "LOCAL", sc.Mode)
    assert.Equal(t, "EXPLICIT", sc.EventSource)
    assert.Equal(t, []string{"sid-a", "sid-b"}, sc.SourceStreamIds)
    require.NotNil(t, sc.GraceSeconds, "--grace-seconds was supplied")
    assert.Equal(t, 600, *sc.GraceSeconds)
}

// TestSetSubjectFilterConfigCmdAliasOptional verifies the alias arg is
// optional — when omitted the command falls back to the selected stream.
func TestSetSubjectFilterConfigCmdAliasOptional(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"set", "subject-filter", "config"})
    require.NoError(t, err, "set subject-filter config (no alias) must parse")
    assert.Equal(t, "set subject-filter config", ctx.Command())
    assert.Empty(t, pd.cli.Set.SubjectFilter.Config.Alias)
}

// TestSetSubjectFilterConfigCmdRepeatedSourceStreamIds verifies
// `--source-stream-ids` accepts repeated flags as well as a comma-separated
// list.
func TestSetSubjectFilterConfigCmdRepeatedSourceStreamIds(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{
        "set", "subject-filter", "config", "my-stream",
        "--source-stream-ids", "sid-a",
        "--source-stream-ids", "sid-b",
    })
    require.NoError(t, err, "repeated --source-stream-ids must parse")
    assert.Equal(t, []string{"sid-a", "sid-b"}, pd.cli.Set.SubjectFilter.Config.SourceStreamIds)
}

// TestSetSubjectFilterConfigCmdRejectsInvalidMode verifies the kong enum
// rejects an unknown subject-filter mode at parse time.
func TestSetSubjectFilterConfigCmdRejectsInvalidMode(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{
        "set", "subject-filter", "config", "my-stream", "--mode", "BOGUS",
    })
    assert.Error(t, err, "an unknown --mode value must be rejected at parse time")
}

// TestSetSubjectFilterConfigCmdPutsPartialUpdate verifies the command
// translates its flags into the StreamStateRecord partial-update shape (knobs
// at the top level of the body) and PUTs to /stream — no new server endpoint
// — then re-reads the persisted settings via POST /subject-filter/review.
func TestSetSubjectFilterConfigCmdPutsPartialUpdate(t *testing.T) {
    var updateBody []byte
    var reviewCalled bool
    grace := 600
    ts := fakeServerForSubjectFilter(t,
        func(body []byte) (int, []byte) {
            updateBody = body
            return http.StatusOK, []byte(`{}`)
        },
        func(_ []byte) (int, []byte) {
            reviewCalled = true
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
    cmd := &SetSubjectFilterConfigCmd{
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
    assert.True(t, reviewCalled, "the command must re-read the persisted settings after the update")
}

// TestSetSubjectFilterConfigCmdOmitsUntouchedKnobs verifies a partial update —
// only --grace-seconds supplied — sends only that one knob, so untouched
// fields are not overwritten server-side.
func TestSetSubjectFilterConfigCmdOmitsUntouchedKnobs(t *testing.T) {
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
    cmd := &SetSubjectFilterConfigCmd{Alias: "sf-alias", GraceSeconds: &grace}
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

// TestSetSubjectFilterConfigCmdExplicitSourceStreamIds verifies
// `--source-stream-ids` with `--event-source EXPLICIT` is sent under the
// event_source's source_stream_ids — closing the gap that left EXPLICIT event
// sources unconfigurable from the CLI.
func TestSetSubjectFilterConfigCmdExplicitSourceStreamIds(t *testing.T) {
    var updateBody []byte
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
    cmd := &SetSubjectFilterConfigCmd{
        Alias:           "sf-alias",
        EventSource:     model.EventSourceExplicit,
        SourceStreamIds: []string{"sid-a", "sid-b"},
    }
    require.NoError(t, cmd.Run(cli))

    var got map[string]any
    require.NoError(t, json.Unmarshal(updateBody, &got), "update body must be JSON: %s", string(updateBody))
    es, ok := got["event_source"].(map[string]any)
    require.True(t, ok, "event_source must be present")
    assert.Equal(t, model.EventSourceExplicit, es["type"])
    ids, ok := es["source_stream_ids"].([]any)
    require.True(t, ok, "source_stream_ids must be present under event_source")
    assert.Equal(t, []any{"sid-a", "sid-b"}, ids)
}

// TestSetSubjectFilterConfigCmdRejectsSourceIdsWithNonExplicit verifies the
// CLI rejects `--source-stream-ids` combined with a non-EXPLICIT event
// source — before any HTTP request is made.
func TestSetSubjectFilterConfigCmdRejectsSourceIdsWithNonExplicit(t *testing.T) {
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) {
            t.Fatal("a validation failure must not PUT /stream")
            return 500, nil
        },
        func(_ []byte) (int, []byte) {
            t.Fatal("a validation failure must not call the review endpoint")
            return 500, nil
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterConfigCmd{
        Alias:           "sf-alias",
        EventSource:     model.EventSourceAudience,
        SourceStreamIds: []string{"sid-a"},
    }
    err := cmd.Run(cli)
    require.Error(t, err, "--source-stream-ids with a non-EXPLICIT event source must be rejected")
    assert.True(t, strings.Contains(err.Error(), "EXPLICIT"),
        "the error must mention EXPLICIT, got %q", err.Error())
}

// TestSetSubjectFilterConfigCmdRejectsExplicitWithoutSourceIds verifies the
// CLI rejects `--event-source EXPLICIT` without `--source-stream-ids` —
// before any HTTP request is made.
func TestSetSubjectFilterConfigCmdRejectsExplicitWithoutSourceIds(t *testing.T) {
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) {
            t.Fatal("a validation failure must not PUT /stream")
            return 500, nil
        },
        func(_ []byte) (int, []byte) {
            t.Fatal("a validation failure must not call the review endpoint")
            return 500, nil
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterConfigCmd{
        Alias:       "sf-alias",
        EventSource: model.EventSourceExplicit,
    }
    err := cmd.Run(cli)
    require.Error(t, err, "--event-source EXPLICIT without --source-stream-ids must be rejected")
    assert.True(t, strings.Contains(err.Error(), "source-stream-ids"),
        "the error must mention source-stream-ids, got %q", err.Error())
}

// TestSetSubjectFilterConfigCmdSurfacesValidationError verifies a server-side
// rejection propagates to the caller; the CLI does not retry or re-read on a
// validation failure.
func TestSetSubjectFilterConfigCmdSurfacesValidationError(t *testing.T) {
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
    cmd := &SetSubjectFilterConfigCmd{Alias: "sf-alias", Mode: model.SubjectFilterModeHybrid}
    err := cmd.Run(cli)
    require.Error(t, err, "a 400 from the server must propagate to the CLI")
    assert.True(t, strings.Contains(err.Error(), "HYBRID requires a filtering-capable upstream"),
        "the server's validation message must surface to the operator, got %q", err.Error())
}

// TestSetSubjectFilterConfigCmdSurfacesReceiverGraceIgnore verifies a
// `--grace-seconds` set on a receiver stream is silently dropped server-side
// (PRD #97 issue #98's WARN-and-ignore), and the post-update settings display
// reflects the persisted value (0) rather than the requested value.
func TestSetSubjectFilterConfigCmdSurfacesReceiverGraceIgnore(t *testing.T) {
    grace := 600
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) { return http.StatusOK, []byte(`{}`) },
        func(_ []byte) (int, []byte) {
            resp := map[string]any{
                "stream_id":                     "sid-1",
                "subject_removal_grace_seconds": 0,
            }
            b, _ := json.Marshal(resp)
            return http.StatusOK, b
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterConfigCmd{Alias: "sf-alias", GraceSeconds: &grace}

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

// TestSetSubjectFilterConfigCmdDisabledServer verifies a 404 from the
// post-update re-read (subject filtering disabled server-wide) is surfaced as
// a plain operator-facing message rather than a raw HTTP status.
func TestSetSubjectFilterConfigCmdDisabledServer(t *testing.T) {
    ts := fakeServerForSubjectFilter(t,
        func(_ []byte) (int, []byte) { return http.StatusOK, []byte(`{}`) },
        func(_ []byte) (int, []byte) {
            return http.StatusNotFound, []byte("not found\n")
        })
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterConfigCmd{Alias: "sf-alias", Mode: model.SubjectFilterModeLocal}
    err := cmd.Run(cli)
    require.Error(t, err, "a 404 must surface as an error")
    assert.Equal(t, "subject filtering is disabled on this server", err.Error(),
        "the 404 must be a plain message, not a raw HTTP status")
}
