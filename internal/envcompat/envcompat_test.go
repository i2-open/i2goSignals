package envcompat

import (
    "bytes"
    "encoding/json"
    "strings"
    "sync"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/logger"
)

// captureLogs initializes the global logger to write JSON to a buffer so
// tests can count and inspect WARN records. Returns the buffer.
func captureLogs(t *testing.T) *bytes.Buffer {
    t.Helper()
    var buf bytes.Buffer
    logger.Init(logger.Options{Level: "info", Format: "json", Writer: &buf})
    return &buf
}

// countWarns returns the number of JSON log lines in buf whose level is WARN.
func countWarns(t *testing.T, buf *bytes.Buffer) int {
    t.Helper()
    n := 0
    for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
        if line == "" {
            continue
        }
        var m map[string]any
        if err := json.Unmarshal([]byte(line), &m); err != nil {
            t.Fatalf("log line is not JSON: %q (err: %v)", line, err)
        }
        if lvl, _ := m["level"].(string); lvl == "WARN" {
            n++
        }
    }
    return n
}

func TestLookup_NewNameOnly_ReturnsNewValueNoWarn(t *testing.T) {
    resetWarnOnceForTest()
    buf := captureLogs(t)

    t.Setenv("I2SIG_FOO_NEW", "new-value")
    t.Setenv("FOO_OLD", "")

    got := Lookup("I2SIG_FOO_NEW", "FOO_OLD")
    if got != "new-value" {
        t.Fatalf("Lookup = %q, want %q", got, "new-value")
    }
    if n := countWarns(t, buf); n != 0 {
        t.Fatalf("WARN count = %d, want 0 (output: %s)", n, buf.String())
    }
}

func TestLookup_OldNameOnly_ReturnsOldValueAndWarnsOnce(t *testing.T) {
    resetWarnOnceForTest()
    buf := captureLogs(t)

    t.Setenv("I2SIG_FOO_NEW", "")
    t.Setenv("FOO_OLD", "old-value")

    got := Lookup("I2SIG_FOO_NEW", "FOO_OLD")
    if got != "old-value" {
        t.Fatalf("Lookup = %q, want %q", got, "old-value")
    }
    if n := countWarns(t, buf); n != 1 {
        t.Fatalf("WARN count = %d, want 1 (output: %s)", n, buf.String())
    }
    out := buf.String()
    if !strings.Contains(out, "FOO_OLD") {
        t.Errorf("expected WARN to mention deprecated name FOO_OLD; output: %s", out)
    }
    if !strings.Contains(out, "I2SIG_FOO_NEW") {
        t.Errorf("expected WARN to mention replacement name I2SIG_FOO_NEW; output: %s", out)
    }
}

func TestLookup_BothSet_NewWinsAndWarnsOnce(t *testing.T) {
    resetWarnOnceForTest()
    buf := captureLogs(t)

    t.Setenv("I2SIG_FOO_NEW", "new-wins")
    t.Setenv("FOO_OLD", "old-loses")

    got := Lookup("I2SIG_FOO_NEW", "FOO_OLD")
    if got != "new-wins" {
        t.Fatalf("Lookup = %q, want %q (new should win)", got, "new-wins")
    }
    if n := countWarns(t, buf); n != 1 {
        t.Fatalf("WARN count = %d, want 1 (output: %s)", n, buf.String())
    }
    out := buf.String()
    if !strings.Contains(out, "both") {
        t.Errorf("expected WARN to indicate both vars were set; output: %s", out)
    }
    if !strings.Contains(out, "FOO_OLD") || !strings.Contains(out, "I2SIG_FOO_NEW") {
        t.Errorf("expected WARN to name both old and new env vars; output: %s", out)
    }
}

func TestLookup_ConcurrentSameOldName_WarnsExactlyOnce(t *testing.T) {
    resetWarnOnceForTest()
    buf := captureLogs(t)

    t.Setenv("I2SIG_FOO_NEW", "")
    t.Setenv("FOO_OLD", "old-value")

    const goroutines = 100
    var wg sync.WaitGroup
    wg.Add(goroutines)
    for i := 0; i < goroutines; i++ {
        go func() {
            defer wg.Done()
            if got := Lookup("I2SIG_FOO_NEW", "FOO_OLD"); got != "old-value" {
                t.Errorf("Lookup = %q, want %q", got, "old-value")
            }
        }()
    }
    wg.Wait()

    if n := countWarns(t, buf); n != 1 {
        t.Fatalf("WARN count = %d, want exactly 1 across %d concurrent calls (output: %s)",
            n, goroutines, buf.String())
    }
}

func TestLookup_NeitherSet_ReturnsEmpty(t *testing.T) {
    resetWarnOnceForTest()
    buf := captureLogs(t)

    t.Setenv("I2SIG_FOO_NEW", "")
    t.Setenv("FOO_OLD", "")

    got := Lookup("I2SIG_FOO_NEW", "FOO_OLD")
    if got != "" {
        t.Fatalf("Lookup = %q, want \"\"", got)
    }
    if n := countWarns(t, buf); n != 0 {
        t.Fatalf("WARN count = %d, want 0 (output: %s)", n, buf.String())
    }
}

// pollBehaviorTranslate mirrors the real translator that slice #68 will
// install for POLL_SRV_BEHAVIOR (MODE → "true", ALWAYSON → "false").
func pollBehaviorTranslate(old string) string {
    switch strings.ToUpper(strings.TrimSpace(old)) {
    case "ALWAYSON":
        return "false"
    default:
        return "true"
    }
}

func TestLookupWithTranslate_OldNameSet_AppliesTranslate(t *testing.T) {
    resetWarnOnceForTest()
    buf := captureLogs(t)

    t.Setenv("I2SIG_POLL_RESPECT_STATUS", "")
    t.Setenv("POLL_SRV_BEHAVIOR", "ALWAYSON")

    got := LookupWithTranslate("I2SIG_POLL_RESPECT_STATUS", "POLL_SRV_BEHAVIOR", pollBehaviorTranslate)
    if got != "false" {
        t.Fatalf("LookupWithTranslate = %q, want %q (translate must run on old value)", got, "false")
    }
    if n := countWarns(t, buf); n != 1 {
        t.Fatalf("WARN count = %d, want 1 (output: %s)", n, buf.String())
    }
}

func TestLookupWithTranslate_NewNameSet_DoesNotTranslate(t *testing.T) {
    resetWarnOnceForTest()
    buf := captureLogs(t)

    t.Setenv("I2SIG_POLL_RESPECT_STATUS", "true")
    t.Setenv("POLL_SRV_BEHAVIOR", "")

    translateCalled := false
    spy := func(s string) string {
        translateCalled = true
        return "SHOULD-NOT-APPEAR"
    }

    got := LookupWithTranslate("I2SIG_POLL_RESPECT_STATUS", "POLL_SRV_BEHAVIOR", spy)
    if got != "true" {
        t.Fatalf("LookupWithTranslate = %q, want %q (new value must pass through untouched)", got, "true")
    }
    if translateCalled {
        t.Errorf("translate must not be called when value originated from new name")
    }
    if n := countWarns(t, buf); n != 0 {
        t.Fatalf("WARN count = %d, want 0 (output: %s)", n, buf.String())
    }
}
