package eventRouter

import (
    "context"
    "net/http"
    "net/http/httptest"
    "sync/atomic"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/dao/memory"
    "github.com/i2-open/i2goSignals/internal/services"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestSweepDeferredHybridRelays_NoopWhenServicesMissing verifies the SSF §9.3
// sweep wired into the push loop's backfill tick is a safe no-op when its
// dependencies are absent — the router struct may be partially wired in
// tests or during early startup before the relay service exists.
func TestSweepDeferredHybridRelays_NoopWhenServicesMissing(t *testing.T) {
    r := &router{}
    stream := &model.StreamStateRecord{}
    stream.SubjectFilterMode = model.SubjectFilterModeHybrid

    // No panic, no error — the sweep returns silently when subjectFilterService
    // or subjectRelayService is nil. This guards the push loop from a NPE
    // when the relay service has not been injected (e.g. in test harnesses
    // that pre-date issue #100).
    r.sweepDeferredHybridRelays(context.Background(), stream)
}

// TestSweepDeferredHybridRelays_SkipsNonHybridStreams verifies the mode
// guard: only HYBRID streams carry deferred upstream removes; PASSTHRU
// streams relay synchronously and LOCAL streams have no upstream relay.
// Both cases must short-circuit without touching the filter service so the
// per-tick overhead stays bounded.
func TestSweepDeferredHybridRelays_SkipsNonHybridStreams(t *testing.T) {
    r := &router{}
    r.subjectFilterService = services.NewSubjectFilterService(nil)
    r.subjectRelayService = &services.SubjectRelayService{}

    for _, mode := range []string{"", model.SubjectFilterModeLocal, model.SubjectFilterModePassthru} {
        stream := &model.StreamStateRecord{}
        stream.SubjectFilterMode = mode
        // No panic, no DAO call — the mode guard short-circuits.
        r.sweepDeferredHybridRelays(context.Background(), stream)
    }
}

// TestSweepDeferredHybridRelays_FiresUpstreamRemoveAfterEnforceAt is the
// slice #100 end-to-end test for the wire-up: with a HYBRID stream wired to
// a real SubjectFilterService and SubjectRelayService, a Remove during the
// grace window does not relay; once enforceAt elapses the sweep on the
// backfill tick fires the upstream remove.
func TestSweepDeferredHybridRelays_FiresUpstreamRemoveAfterEnforceAt(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    var removes int32
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        if req.URL.Path == "/remove-subject" {
            atomic.AddInt32(&removes, 1)
        }
        w.WriteHeader(http.StatusNoContent)
    }))
    t.Cleanup(upstream.Close)

    upstreamCfg := &model.TransmitterConfiguration{
        AddSubjectEndpoint:    upstream.URL + "/add-subject",
        RemoveSubjectEndpoint: upstream.URL + "/remove-subject",
    }

    // A receiver stream that feeds the HYBRID downstream — a NONE upstream
    // baseline so HYBRID engages its relay.
    remoteID := "remote-stream-99"
    rx := model.StreamStateRecord{DefaultSubjects: model.DefaultSubjectsNone}
    rx.StreamConfiguration.Id = "rx-1"
    rx.StreamConfiguration.Iss = "https://issuer.example"
    rx.StreamConfiguration.RemoteStreamId = &remoteID

    // A HYBRID downstream with a 30s grace.
    downstream := &model.StreamStateRecord{
        DefaultSubjects:            model.DefaultSubjectsNone,
        SubjectFilterMode:          model.SubjectFilterModeHybrid,
        SubjectRemovalGraceSeconds: 30,
        EventSource:                &model.EventSource{Type: model.EventSourceAudience},
    }
    downstream.StreamConfiguration.Id = "tx-1"
    downstream.StreamConfiguration.Iss = "https://issuer.example"

    receivers := []model.StreamStateRecord{rx}
    transmitters := []model.StreamStateRecord{*downstream}

    filterSvc := services.NewSubjectFilterService(memory.NewSubjectFilterDAO())
    clock := &graceClock{t: time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)}
    filterSvc.SetNow(clock.Now)

    relaySvc := services.NewSubjectRelayService(
        func(context.Context) ([]model.StreamStateRecord, error) { return receivers, nil },
        func(context.Context) ([]model.StreamStateRecord, error) { return transmitters, nil },
        func(c context.Context, s *model.StreamStateRecord, sub *goSet.SubjectIdentifier) bool {
            return filterSvc.Selects(c, s, sub)
        },
        func(context.Context, *model.StreamStateRecord) (*services.UpstreamConn, error) {
            return &services.UpstreamConn{Config: upstreamCfg, HttpClient: upstream.Client()}, nil
        },
    )

    r := &router{}
    r.subjectFilterService = filterSvc
    r.subjectRelayService = relaySvc

    subject := makeEmailSubject("alice@example.com")
    if _, err := filterSvc.AddSubject(ctx, downstream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }
    if _, err := filterSvc.RemoveSubject(ctx, downstream, subject); err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }

    // Inside the grace window the sweep must not fire the upstream remove.
    r.sweepDeferredHybridRelays(ctx, downstream)
    if got := atomic.LoadInt32(&removes); got != 0 {
        t.Fatalf("sweep inside the grace window must not relay upstream, got %d removes", got)
    }

    // Past enforceAt the sweep must fire the upstream remove exactly once.
    clock.Advance(31 * time.Second)
    r.sweepDeferredHybridRelays(ctx, downstream)
    if got := atomic.LoadInt32(&removes); got != 1 {
        t.Fatalf("sweep past enforceAt must relay 1 upstream remove, got %d", got)
    }

    // A subsequent sweep must find nothing — the entry has been purged.
    r.sweepDeferredHybridRelays(ctx, downstream)
    if got := atomic.LoadInt32(&removes); got != 1 {
        t.Fatalf("a purged entry must not be relayed twice, got %d removes after second sweep", got)
    }
}

// graceClock is a hand-cranked clock that the SubjectFilterService consults
// for the §9.3 boundary in this test — the same pattern used by the
// services package's grace tests.
type graceClock struct {
    t time.Time
}

func (c *graceClock) Now() time.Time          { return c.t }
func (c *graceClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// makeEmailSubject builds a simple RFC9493 email-format subject identifier.
func makeEmailSubject(addr string) *goSet.SubjectIdentifier {
    s := &goSet.SubjectIdentifier{Format: "email"}
    return s.AddEmail(addr)
}
