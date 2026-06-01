package main

import (
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. Used to assert on the command's human/JSON output.
func captureStdout(t *testing.T, fn func()) string {
    t.Helper()
    orig := os.Stdout
    r, w, err := os.Pipe()
    require.NoError(t, err)
    os.Stdout = w
    defer func() { os.Stdout = orig }()

    fn()
    _ = w.Close()
    out, _ := io.ReadAll(r)
    return string(out)
}

// fixedTokenRecords returns a deterministic set of token records spanning the
// three lifecycle states (active, revoked, expired) for table-rendering tests.
func fixedTokenRecords() []tokenListEntry {
    iat := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
    return []tokenListEntry{
        {TokenRecord: model.TokenRecord{
            JTI:       "jti-active",
            ClientID:  "client-a",
            Subject:   "alice",
            Type:      model.TokenTypeStream,
            Scopes:    []string{"admin", "ssf"},
            IssuedAt:  iat,
            ExpiresAt: time.Now().Add(time.Hour),
        }},
        {TokenRecord: model.TokenRecord{
            JTI:       "jti-revoked",
            ClientID:  "client-b",
            Type:      model.TokenTypeIAT,
            IssuedAt:  iat,
            ExpiresAt: time.Now().Add(time.Hour),
            RevokedAt: iat.Add(time.Minute),
        }},
        {TokenRecord: model.TokenRecord{
            JTI:       "jti-expired",
            ClientID:  "client-c",
            Type:      model.TokenTypeStream,
            IssuedAt:  iat,
            ExpiresAt: time.Now().Add(-time.Hour),
        }},
    }
}

// TestRenderTokenTable_ColumnsAndStates proves the table renderer emits a
// header row with every operator-facing column and one row per token whose
// derived state reflects revocation/expiry.
func TestRenderTokenTable_ColumnsAndStates(t *testing.T) {
    out := renderTokenTable(fixedTokenRecords())

    for _, col := range []string{"JTI", "CLIENT", "SUBJECT", "TYPE", "SCOPES", "ISSUED", "EXPIRES", "STATE", "USAGE IP"} {
        assert.Contains(t, out, col, "header column %s missing", col)
    }

    assert.Contains(t, out, "jti-active")
    assert.Contains(t, out, "client-a")
    assert.Contains(t, out, "alice")
    assert.Contains(t, out, "admin,ssf")

    lines := strings.Split(strings.TrimSpace(out), "\n")
    assert.Equal(t, 4, len(lines), "expected header + 3 rows, got: %q", out)

    assert.Contains(t, lineFor(t, lines, "jti-active"), "active")
    assert.Contains(t, lineFor(t, lines, "jti-revoked"), "revoked")
    assert.Contains(t, lineFor(t, lines, "jti-expired"), "expired")
}

func lineFor(t *testing.T, lines []string, needle string) string {
    t.Helper()
    for _, l := range lines {
        if strings.Contains(l, needle) {
            return l
        }
    }
    t.Fatalf("no line containing %q", needle)
    return ""
}

// configuredTokenCLI returns a CLI whose default server points at host and is
// authenticated via a logged-in session (exercising the serverBearer path).
func configuredTokenCLI(t *testing.T, host string) *CLI {
    t.Helper()
    dir := t.TempDir()
    g := Globals{ConfigFile: filepath.Join(dir, "config.json")}
    c := &CLI{Globals: g}
    store := &CredentialStore{Path: credentialsPath(&c.Globals)}
    store.Set("https://idp.example.com", &Session{
        AccessToken: "session-token",
        Expiry:      time.Now().Add(time.Hour),
    })
    require.NoError(t, store.Save())
    c.Data.Servers = map[string]SsfServer{
        "gs1": {
            Alias:        "gs1",
            Host:         host,
            ProjectId:    "proj-1",
            ActiveIssuer: "https://idp.example.com",
            ClientToken:  "legacy-client-token",
        },
    }
    c.Data.Selected = "gs1"
    return c
}

// TestTokenListCmd_UsesSessionBearer proves token list authenticates with the
// active session token (serverBearer), not the legacy ClientToken header.
func TestTokenListCmd_UsesSessionBearer(t *testing.T) {
    var gotAuth string
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotAuth = r.Header.Get("Authorization")
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(fixedTokenRecords())
    }))
    defer stub.Close()

    cli := configuredTokenCLI(t, stub.URL)
    cmd := &TokenListCmd{}
    require.NoError(t, cmd.Run(cli))
    assert.Equal(t, "Bearer session-token", gotAuth)
}

// TestTokenListCmd_JSONFlag proves --json emits the raw JSON response array.
func TestTokenListCmd_JSONFlag(t *testing.T) {
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(fixedTokenRecords())
    }))
    defer stub.Close()

    cli := configuredTokenCLI(t, stub.URL)
    out := captureStdout(t, func() {
        require.NoError(t, (&TokenListCmd{Json: true}).Run(cli))
    })
    assert.Contains(t, out, `"jti":"jti-active"`)
}

// TestTokenListCmd_TableByDefault proves token list renders the table (not raw
// JSON) when --json is absent.
func TestTokenListCmd_TableByDefault(t *testing.T) {
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(fixedTokenRecords())
    }))
    defer stub.Close()

    cli := configuredTokenCLI(t, stub.URL)
    out := captureStdout(t, func() {
        require.NoError(t, (&TokenListCmd{}).Run(cli))
    })
    assert.Contains(t, out, "JTI")
    assert.Contains(t, out, "STATE")
    assert.NotContains(t, out, `"jti":`, "default output should be a table, not JSON")
}

// TestTokenIntrospectCmd_UsesSessionBearer proves introspect authenticates via
// the session bearer.
func TestTokenIntrospectCmd_UsesSessionBearer(t *testing.T) {
    var gotAuth string
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotAuth = r.Header.Get("Authorization")
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"active":true,"jti":"jti-active"}`))
    }))
    defer stub.Close()

    cli := configuredTokenCLI(t, stub.URL)
    require.NoError(t, (&TokenIntrospectCmd{Token: "jti-active"}).Run(cli))
    assert.Equal(t, "Bearer session-token", gotAuth)
}

// TestTokenRevokeCmd_UsesSessionBearer proves revoke authenticates via the
// session bearer.
func TestTokenRevokeCmd_UsesSessionBearer(t *testing.T) {
    var gotAuth string
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotAuth = r.Header.Get("Authorization")
        w.WriteHeader(http.StatusNoContent)
    }))
    defer stub.Close()

    cli := configuredTokenCLI(t, stub.URL)
    require.NoError(t, (&TokenRevokeCmd{Jti: "jti-active"}).Run(cli))
    assert.Equal(t, "Bearer session-token", gotAuth)
}
