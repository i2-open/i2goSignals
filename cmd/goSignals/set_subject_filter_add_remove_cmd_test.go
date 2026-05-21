package main

import (
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestSetSubjectFilterAddCmdParses pins the kong shape of
// `set subject-filter add <alias>` (PRD #106 issue #110). The `add`
// sub-command performs an administrative SSF Add Subject from the CLI.
func TestSetSubjectFilterAddCmdParses(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"set", "subject-filter", "add", "my-stream"})
    require.NoError(t, err, "set subject-filter add <alias> must parse")
    assert.Equal(t, "set subject-filter add <alias>", ctx.Command())
    assert.Equal(t, "my-stream", pd.cli.Set.SubjectFilter.Add.Alias)
}

// TestSetSubjectFilterAddCmdVerifiedFlag pins that `--verified` parses onto the
// `add` sub-command. It sets the SSF Add Subject verified flag and is omitted
// by default.
func TestSetSubjectFilterAddCmdVerifiedFlag(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{
        "set", "subject-filter", "add", "my-stream",
        `{"format":"email","email":"alice@example.com"}`, "--verified",
    })
    require.NoError(t, err, "set subject-filter add <alias> <subject-json> --verified must parse")
    assert.True(t, pd.cli.Set.SubjectFilter.Add.Verified, "--verified must set the Verified field")
}

// TestSetSubjectFilterAddCmdVerifiedDefaultsOff verifies --verified defaults to
// false when not supplied.
func TestSetSubjectFilterAddCmdVerifiedDefaultsOff(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{"set", "subject-filter", "add", "my-stream"})
    require.NoError(t, err)
    assert.False(t, pd.cli.Set.SubjectFilter.Add.Verified, "--verified must default to false")
}

// TestSetSubjectFilterRemoveCmdParses pins the kong shape of
// `set subject-filter remove <alias>` (PRD #106 issue #110). The `remove`
// sub-command performs an administrative SSF Remove Subject from the CLI.
func TestSetSubjectFilterRemoveCmdParses(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"set", "subject-filter", "remove", "my-stream"})
    require.NoError(t, err, "set subject-filter remove <alias> must parse")
    assert.Equal(t, "set subject-filter remove <alias>", ctx.Command())
    assert.Equal(t, "my-stream", pd.cli.Set.SubjectFilter.Remove.Alias)
}

// TestSetSubjectFilterRemoveCmdHasNoVerifiedFlag verifies the `remove`
// sub-command does not accept --verified — verified is meaningful for Add only.
func TestSetSubjectFilterRemoveCmdHasNoVerifiedFlag(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{
        "set", "subject-filter", "remove", "my-stream", "--verified",
    })
    assert.Error(t, err, "remove must reject --verified")
}

// TestSetSubjectFilterAddCmdFieldFlags verifies the format field flags parse
// onto the `add` sub-command — the ergonomic subject-input path.
func TestSetSubjectFilterAddCmdFieldFlags(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{
        "set", "subject-filter", "add", "my-stream", "--email", "bob@example.com",
    })
    require.NoError(t, err, "set subject-filter add with --email must parse")
    assert.Equal(t, "bob@example.com", pd.cli.Set.SubjectFilter.Add.Email)
}

// TestSetSubjectFilterRemoveCmdFieldFlags verifies the format field flags parse
// onto the `remove` sub-command.
func TestSetSubjectFilterRemoveCmdFieldFlags(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    _, err = pd.parser.Parse([]string{
        "set", "subject-filter", "remove", "my-stream", "--email", "bob@example.com",
    })
    require.NoError(t, err, "set subject-filter remove with --email must parse")
    assert.Equal(t, "bob@example.com", pd.cli.Set.SubjectFilter.Remove.Email)
}

// fakeServerForSubjectChange spins up an httptest server handling the SSF
// /add-subject and /remove-subject endpoints. Each handler records the method
// and body it received so wire-shape assertions can be made; add returns 200
// and remove returns 204, matching the server.
func fakeServerForSubjectChange(t *testing.T) (*httptest.Server, *capturedRequest, *capturedRequest) {
    t.Helper()
    addCap := &capturedRequest{}
    removeCap := &capturedRequest{}
    mux := http.NewServeMux()
    mux.HandleFunc("/add-subject", func(w http.ResponseWriter, r *http.Request) {
        addCap.method = r.Method
        addCap.path = r.URL.Path
        addCap.auth = r.Header.Get("Authorization")
        addCap.body, _ = io.ReadAll(r.Body)
        addCap.called = true
        w.WriteHeader(http.StatusOK)
    })
    mux.HandleFunc("/remove-subject", func(w http.ResponseWriter, r *http.Request) {
        removeCap.method = r.Method
        removeCap.path = r.URL.Path
        removeCap.auth = r.Header.Get("Authorization")
        removeCap.body, _ = io.ReadAll(r.Body)
        removeCap.called = true
        w.WriteHeader(http.StatusNoContent)
    })
    return httptest.NewServer(mux), addCap, removeCap
}

// capturedRequest records the wire details a fake endpoint received.
type capturedRequest struct {
    called bool
    method string
    path   string
    auth   string
    body   []byte
}

// TestSetSubjectFilterAddCmdHitsAddSubject verifies `set subject-filter add`
// POSTs a { stream_id, subject, verified } body to /add-subject using the
// operator's admin token.
func TestSetSubjectFilterAddCmdHitsAddSubject(t *testing.T) {
    ts, addCap, _ := fakeServerForSubjectChange(t)
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterAddCmd{
        Alias:       "sf-alias",
        SubjectJson: `{"format":"email","email":"alice@example.com"}`,
        Verified:    true,
    }
    require.NoError(t, cmd.Run(cli))

    require.True(t, addCap.called, "add must hit /add-subject")
    assert.Equal(t, http.MethodPost, addCap.method, "add must POST")
    assert.Equal(t, "/add-subject", addCap.path)
    assert.Equal(t, "Bearer admin-token", addCap.auth, "add must use the operator's admin token")

    var got map[string]any
    require.NoError(t, json.Unmarshal(addCap.body, &got), "body must be JSON: %s", string(addCap.body))
    assert.Equal(t, "sid-1", got["stream_id"], "body must carry stream_id")
    subject, ok := got["subject"].(map[string]any)
    require.True(t, ok, "body must carry the subject")
    assert.Equal(t, "email", subject["format"])
    assert.Equal(t, "alice@example.com", subject["email"])
    assert.Equal(t, true, got["verified"], "--verified must set the verified flag on the wire")
}

// TestSetSubjectFilterAddCmdVerifiedOmittedByDefault verifies the verified flag
// is absent from the wire when --verified is not supplied.
func TestSetSubjectFilterAddCmdVerifiedOmittedByDefault(t *testing.T) {
    ts, addCap, _ := fakeServerForSubjectChange(t)
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterAddCmd{
        Alias:       "sf-alias",
        SubjectJson: `{"format":"email","email":"alice@example.com"}`,
    }
    require.NoError(t, cmd.Run(cli))

    var got map[string]any
    require.NoError(t, json.Unmarshal(addCap.body, &got))
    _, hasVerified := got["verified"]
    assert.False(t, hasVerified, "verified must be omitted from the wire when --verified is not given")
}

// TestSetSubjectFilterRemoveCmdHitsRemoveSubject verifies `set subject-filter
// remove` POSTs a { stream_id, subject } body to /remove-subject using the
// operator's admin token, and does not send a verified flag.
func TestSetSubjectFilterRemoveCmdHitsRemoveSubject(t *testing.T) {
    ts, _, removeCap := fakeServerForSubjectChange(t)
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterRemoveCmd{
        Alias:       "sf-alias",
        SubjectJson: `{"format":"email","email":"alice@example.com"}`,
    }
    require.NoError(t, cmd.Run(cli))

    require.True(t, removeCap.called, "remove must hit /remove-subject")
    assert.Equal(t, http.MethodPost, removeCap.method, "remove must POST")
    assert.Equal(t, "/remove-subject", removeCap.path)
    assert.Equal(t, "Bearer admin-token", removeCap.auth, "remove must use the operator's admin token")

    var got map[string]any
    require.NoError(t, json.Unmarshal(removeCap.body, &got), "body must be JSON: %s", string(removeCap.body))
    assert.Equal(t, "sid-1", got["stream_id"])
    subject, ok := got["subject"].(map[string]any)
    require.True(t, ok, "body must carry the subject")
    assert.Equal(t, "alice@example.com", subject["email"])
    _, hasVerified := got["verified"]
    assert.False(t, hasVerified, "remove must not send a verified flag")
}

// TestSetSubjectFilterAddCmdFieldFlagsReachWire verifies a subject supplied via
// the format field flags reaches the /add-subject body through the shared
// subject-argument parser.
func TestSetSubjectFilterAddCmdFieldFlagsReachWire(t *testing.T) {
    ts, addCap, _ := fakeServerForSubjectChange(t)
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterAddCmd{Alias: "sf-alias", Email: "carol@example.com"}
    require.NoError(t, cmd.Run(cli))

    var got map[string]any
    require.NoError(t, json.Unmarshal(addCap.body, &got))
    subject, ok := got["subject"].(map[string]any)
    require.True(t, ok, "field flags must produce a subject in the body")
    assert.Equal(t, "email", subject["format"])
    assert.Equal(t, "carol@example.com", subject["email"])
}

// TestSetSubjectFilterAddCmdDisabledServer verifies a 404 from /add-subject
// (subject filtering disabled server-wide) surfaces the plain disabled message
// rather than a raw HTTP status.
func TestSetSubjectFilterAddCmdDisabledServer(t *testing.T) {
    mux := http.NewServeMux()
    mux.HandleFunc("/add-subject", func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusNotFound)
    })
    ts := httptest.NewServer(mux)
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterAddCmd{
        Alias:       "sf-alias",
        SubjectJson: `{"format":"email","email":"alice@example.com"}`,
    }
    err := cmd.Run(cli)
    require.Error(t, err, "a 404 must surface as an error")
    assert.Equal(t, "subject filtering is disabled on this server", err.Error(),
        "the 404 must be the plain disabled message, not a raw HTTP status")
}

// TestSetSubjectFilterRemoveCmdDisabledServer verifies a 404 from
// /remove-subject surfaces the plain disabled message.
func TestSetSubjectFilterRemoveCmdDisabledServer(t *testing.T) {
    mux := http.NewServeMux()
    mux.HandleFunc("/remove-subject", func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusNotFound)
    })
    ts := httptest.NewServer(mux)
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterRemoveCmd{
        Alias:       "sf-alias",
        SubjectJson: `{"format":"email","email":"alice@example.com"}`,
    }
    err := cmd.Run(cli)
    require.Error(t, err)
    assert.Equal(t, "subject filtering is disabled on this server", err.Error())
}

// TestSetSubjectFilterAddCmdHonoursOutputFile verifies the add confirmation is
// written to the file named by -o (the CLI's Output field).
func TestSetSubjectFilterAddCmdHonoursOutputFile(t *testing.T) {
    ts, _, _ := fakeServerForSubjectChange(t)
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    outPath := filepath.Join(t.TempDir(), "add.txt")
    cli.Output = outPath

    cmd := &SetSubjectFilterAddCmd{
        Alias:       "sf-alias",
        SubjectJson: `{"format":"email","email":"alice@example.com"}`,
    }
    require.NoError(t, cmd.Run(cli))

    written, err := os.ReadFile(outPath)
    require.NoError(t, err, "-o must produce a file")
    assert.Contains(t, string(written), "added on stream [sf-alias]")
}

// TestSetSubjectFilterAddCmdRequiresSubject verifies the command rejects a call
// with no subject — neither positional JSON nor a format field flag.
func TestSetSubjectFilterAddCmdRequiresSubject(t *testing.T) {
    ts, addCap, _ := fakeServerForSubjectChange(t)
    defer ts.Close()

    cli, _ := makeServerForCli(t, ts.URL, "sid-1")
    cmd := &SetSubjectFilterAddCmd{Alias: "sf-alias"}
    err := cmd.Run(cli)
    require.Error(t, err, "add with no subject must be rejected")
    assert.False(t, addCap.called, "no HTTP request must be made when the subject is missing")
}
