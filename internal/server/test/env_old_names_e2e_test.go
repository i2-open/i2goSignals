package test

import (
    "bytes"
    "encoding/json"
    "log/slog"
    "net/http"
    "strings"
    "sync"
    "sync/atomic"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/envcompat"
    "github.com/i2-open/i2goSignals/pkg/logger"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/suite"
)

// syncBuf is a goroutine-safe io.Writer over a bytes.Buffer. The push
// transmitter goroutine that this suite triggers via createPushStream
// continues to log INFO records concurrently with the test reading the
// captured boot log, so a plain bytes.Buffer would race under -race.
type syncBuf struct {
    mu  sync.Mutex
    buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.buf.Write(p)
}

func (s *syncBuf) String() string {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.buf.String()
}

// OldNamesOnlySuite verifies that an operator who upgrades to v0.11.0 with
// only the legacy pre-v0.11.0 env-var names still in their config (no new
// I2SIG_* names) gets a working server: it boots, registers a stream, and
// delivers a SET. The suite also asserts that the deprecation WARN path is
// wired up — at least one old-name read emits a WARN through the project
// logger. If any call site in slices #2–#5 was missed (and now silently
// reads the new name only), the boot path stops finding its value and the
// downstream flow fails — that's the failure mode this suite is designed
// to catch.
type OldNamesOnlySuite struct {
    suite.Suite

    instance *ssfInstance
    mockSrv  *mockReceiver
    streamId string
    received *atomic.Int32
    logBuf   *syncBuf
}

type mockReceiver struct {
    url      string
    teardown func()
}

func TestOldNamesOnlyE2E(t *testing.T) {
    suite.Run(t, new(OldNamesOnlySuite))
}

func (s *OldNamesOnlySuite) SetupSuite() {
    t := s.T()

    // Capture all logs to a buffer so the second test can assert that
    // envcompat WARN-ed for at least one deprecated name during boot.
    s.logBuf = &syncBuf{}
    logger.Init(logger.Options{Level: "info", Format: "json", Writer: s.logBuf})

    // Other tests in this package may already have triggered warn-once for
    // some old names — reset so this suite observes a fresh first read.
    envcompat.ResetWarnedForTest()

    // Set ONLY pre-v0.11.0 names. Every renamed var that has a non-empty
    // effective default in this test path is set to its old name here.
    // New (I2SIG_*) names are explicitly blanked so the lookup falls
    // through to the old name.
    t.Setenv("I2SIG_ISSUER", "old-names-test.example.com")
    t.Setenv("I2SIG_ISSUER_DEFAULT", "")
    t.Setenv("I2SIG_TOKEN_ISSUER", "old-names-token.example.com")
    t.Setenv("I2SIG_ISSUER_TOKEN", "")
    t.Setenv("SSEF_ADMIN_ROLE", "test-admin-role")
    t.Setenv("I2SIG_AUTH_ADMIN_ROLE", "")
    t.Setenv("OAUTH_SERVERS", "")
    t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", "")
    t.Setenv("MIN_VERIFICATION_INTERVAL", "60")
    t.Setenv("I2SIG_STREAM_MIN_VERIFICATION_INTERVAL", "")
    t.Setenv("MAX_INACTIVITY_TIMEOUT", "3600")
    t.Setenv("I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT", "")
    t.Setenv("NODE_ID", "old-names-node-1")
    t.Setenv("I2SIG_CLUSTER_NODE_ID", "")
    t.Setenv("MEM_SAVE_RATE", "30")
    t.Setenv("I2SIG_STORE_MEM_SAVE_RATE", "")

    instance, err := createServer(t, "old_names_only_e2e", true)
    s.Require().NoError(err)
    s.instance = instance

    // Mock receiver: counts pushed events at /events/streamX, reports
    // "enabled" at /status so the push loop runs without falling into
    // recovery.
    count := &atomic.Int32{}
    s.received = count
    events := func(w http.ResponseWriter, _ *http.Request) {
        count.Add(1)
        w.WriteHeader(http.StatusAccepted)
    }
    status := func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
    }
    srv, teardown := startMockReceiver(t, events, status)
    s.mockSrv = &mockReceiver{url: srv.URL, teardown: teardown}

    s.streamId = createPushStream(t, instance, srv.URL+"/events/streamX")
}

func (s *OldNamesOnlySuite) TearDownSuite() {
    if s.instance != nil {
        s.instance.app.Shutdown()
        s.instance.ts.Close()
    }
    if s.mockSrv != nil {
        s.mockSrv.teardown()
    }
    // Restore the default logger so subsequent tests in this package
    // don't write into our dangling buffer.
    logger.Init(logger.Options{Level: "info"})
}

// TestStreamCreateAndEventDeliver is the tracer bullet: with only legacy
// env names set, the full path stream-create → SET creation → push → ack
// must succeed end-to-end. Failure here means a slice #2–#5 call site
// was missed and the boot path is no longer honoring the old name.
func (s *OldNamesOnlySuite) TestStreamCreateAndEventDeliver() {
    t := s.T()

    emitEvent(t, s.instance, s.streamId)

    s.Require().Eventually(func() bool {
        return s.received.Load() >= 1
    }, 5*time.Second, 50*time.Millisecond,
        "expected push receiver to ack at least one event within 5s — a missed call site in slices #2–#5 means the boot path lost its old-name fallback")

    state, err := s.instance.GetStreamState(s.streamId)
    s.Require().NoError(err)
    s.Equal(model.StreamStateEnabled, state.Status,
        "stream should remain enabled across a successful push delivery")
}

// TestDeprecationWarnEmitted asserts that at least one envcompat WARN was
// logged during boot. The point is to prove the deprecation channel is
// wired — without this canary, a regression where envcompat stops warning
// (e.g., a bug in warnOnce or the sub-logger) would silently undo the
// migration UX.
func (s *OldNamesOnlySuite) TestDeprecationWarnEmitted() {
    out := s.logBuf.String()
    foundWarn := false
    for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
        if line == "" {
            continue
        }
        var rec map[string]any
        if err := json.Unmarshal([]byte(line), &rec); err != nil {
            // Non-JSON noise can appear before logger.Init takes effect
            // for very early bootstrap log lines; ignore those.
            continue
        }
        level, _ := rec["level"].(string)
        if !strings.EqualFold(level, slog.LevelWarn.String()) {
            continue
        }
        component, _ := rec["component"].(string)
        if component != "ENVCOMPAT" {
            continue
        }
        msg, _ := rec["msg"].(string)
        if strings.Contains(strings.ToLower(msg), "deprecated") {
            foundWarn = true
            break
        }
    }
    s.True(foundWarn,
        "expected at least one ENVCOMPAT WARN about a deprecated env var during boot; captured log was:\n%s", out)
}
