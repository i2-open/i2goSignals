package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestSubLoggerLevelUpdate(t *testing.T) {
	// Setup a buffer to capture output
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: globalLevel})
	slog.SetDefault(slog.New(handler))

	// Create a sub-logger (similar to pLog in dynamic_proxy.go)
	subLogger := Sub("TEST")

	// Initially it should be Info level (from init)
	globalLevel.Set(slog.LevelInfo)
	subLogger.Debug("this debug message should be hidden")
	if buf.Len() > 0 {
		t.Errorf("expected no output for debug message at Info level, got: %s", buf.String())
	}
	buf.Reset()

	subLogger.Info("this info message should be shown")
	if !strings.Contains(buf.String(), "this info message should be shown") {
		t.Errorf("expected info message to be shown, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "component=TEST") {
		t.Errorf("expected component=TEST attribute, got: %s", buf.String())
	}
	buf.Reset()

	// Now update to Debug level via Init (simulated). Writer is supplied
	// so the sub-logger keeps writing to the test buffer after Init replaces
	// the global default.
	Init(Options{Level: "debug", Writer: &buf})
	subLogger.Debug("this debug message should now be shown")
	if !strings.Contains(buf.String(), "this debug message should now be shown") {
		t.Errorf("expected debug message to be shown after Init(debug), got: %s", buf.String())
	}
	buf.Reset()
}

func TestInit_JSONFormatIsParseable(t *testing.T) {
    var buf bytes.Buffer
    Init(Options{Level: "info", Format: "json", Writer: &buf})

    slog.Info("hello", "k", "v")

    line := strings.TrimSpace(buf.String())
    if line == "" {
        t.Fatal("expected JSON output, got empty buffer")
    }
    var m map[string]any
    if err := json.Unmarshal([]byte(line), &m); err != nil {
        t.Fatalf("output is not valid JSON: %v\nline: %s", err, line)
    }
    if m["msg"] != "hello" {
        t.Errorf("msg = %v, want %q", m["msg"], "hello")
    }
    if m["level"] != "INFO" {
        t.Errorf("level = %v, want INFO", m["level"])
    }
    if m["k"] != "v" {
        t.Errorf("k = %v, want %q", m["k"], "v")
    }
}

func TestInit_TextFormatRemainsHumanReadable(t *testing.T) {
    var buf bytes.Buffer
    Init(Options{Level: "info", Format: "", Writer: &buf})

    slog.Info("hello", "k", "v")

    out := buf.String()
    // Text handler emits key=value pairs, not JSON braces.
    if strings.HasPrefix(strings.TrimSpace(out), "{") {
        t.Errorf("expected text output, got JSON: %s", out)
    }
    if !strings.Contains(out, "msg=hello") {
        t.Errorf("expected msg=hello in text output, got: %s", out)
    }
    if !strings.Contains(out, "k=v") {
        t.Errorf("expected k=v in text output, got: %s", out)
    }
}

func TestInit_DefaultAttrsAppearInOutput(t *testing.T) {
    var buf bytes.Buffer
    Init(Options{
        Level:  "info",
        Format: "json",
        Writer: &buf,
        Attrs: []slog.Attr{
            slog.String("service", "gosignals"),
            slog.String("version", "v9.9.9"),
            slog.String("node_id", "node-1"),
            slog.String("cluster_name", "dev-local"),
        },
    })

    slog.Info("ping")

    var m map[string]any
    if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &m); err != nil {
        t.Fatalf("not valid JSON: %v", err)
    }
    for k, want := range map[string]string{
        "service":      "gosignals",
        "version":      "v9.9.9",
        "node_id":      "node-1",
        "cluster_name": "dev-local",
    } {
        if m[k] != want {
            t.Errorf("%s = %v, want %q", k, m[k], want)
        }
    }
}

func TestSub_AttachesComponentInJSONMode(t *testing.T) {
    var buf bytes.Buffer
    Init(Options{Level: "info", Format: "json", Writer: &buf})

    Sub("ROUTER").Info("event")

    var m map[string]any
    if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &m); err != nil {
        t.Fatalf("not valid JSON: %v", err)
    }
    if m["component"] != "ROUTER" {
        t.Errorf("component = %v, want ROUTER", m["component"])
    }
}

// A sub-logger captured at package-init time (the pattern used pervasively
// in this codebase as `var fooLog = logger.Sub("FOO")`) must still pick up
// the format and default attrs configured later by Init() in main(). Before
// the dynamicHandler fix, Sub() captured slog.Default() as a one-shot
// snapshot, so package-level loggers stayed on the bootstrap text handler
// and never produced JSON or default attrs.
func TestSub_PicksUpInitCalledAfterSubCreation(t *testing.T) {
    // Simulate package-init scope: create the sub-logger BEFORE Init runs.
    earlyLog := Sub("EARLY")

    var buf bytes.Buffer
    Init(Options{
        Level:  "info",
        Format: "json",
        Writer: &buf,
        Attrs: []slog.Attr{
            slog.String("service", "gosignals"),
            slog.String("node_id", "node-1"),
        },
    })

    earlyLog.Info("event", "k", "v")

    line := strings.TrimSpace(buf.String())
    var m map[string]any
    if err := json.Unmarshal([]byte(line), &m); err != nil {
        t.Fatalf("output is not valid JSON: %v\nline: %s", err, line)
    }
    for k, want := range map[string]string{
        "service":   "gosignals",
        "node_id":   "node-1",
        "component": "EARLY",
        "msg":       "event",
        "k":         "v",
    } {
        if m[k] != want {
            t.Errorf("%s = %v, want %q", k, m[k], want)
        }
    }
}

func TestDefaultAttrs_OmitsEmptyClusterName(t *testing.T) {
    cases := []struct {
        name           string
        clusterName    string
        wantClusterKey bool
    }{
        {"empty cluster_name omitted", "", false},
        {"non-empty cluster_name included", "prod-east", true},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            attrs := DefaultAttrs("gosignals", "v1.2.3", "node-x", tc.clusterName)

            keys := map[string]string{}
            for _, a := range attrs {
                keys[a.Key] = a.Value.String()
            }
            // service, version, node_id are always present
            for _, k := range []string{"service", "version", "node_id"} {
                if _, ok := keys[k]; !ok {
                    t.Errorf("missing required attr %q", k)
                }
            }
            _, got := keys["cluster_name"]
            if got != tc.wantClusterKey {
                t.Errorf("cluster_name present = %v, want %v (attrs=%v)", got, tc.wantClusterKey, attrs)
            }
            if tc.wantClusterKey && keys["cluster_name"] != tc.clusterName {
                t.Errorf("cluster_name = %q, want %q", keys["cluster_name"], tc.clusterName)
            }
        })
    }
}
