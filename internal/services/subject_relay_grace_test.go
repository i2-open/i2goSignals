package services

import (
    "context"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/dao/memory"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Pure unit tests for the HYBRID upstream-relay grace decision (PRD #97 issue
// #100). They mirror the slice #99 subject_grace_pure_test.go style: a fast,
// exhaustive truth-table over the (before, planned-change, add, grace) inputs
// the SubjectFilterService passes into planHybridRelay.
//
// The contract: with a §9.3 grace window active the upstream subscription
// state must track the *enforced* downstream-interest state, not the
// receiver's instantaneous request. A receiver Remove that stamps a pending
// entry defers the upstream remove to the sweep; a receiver Add that revives
// a pending entry is a no-op because the upstream subscription was never
// dropped.

var relayNow = time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

// TestPlanHybridRelay_RemoveWithGraceDefers is the tracer bullet for issue
// #100: a stop-delivery change on a HYBRID downstream with grace > 0 must
// produce RelayDecisionDeferred — the upstream remove is held back so the
// upstream keeps feeding events through the grace window (SSF §9.3).
func TestPlanHybridRelay_RemoveWithGraceDefers(t *testing.T) {
    before := &model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"} // active inclusion
    change := graceChange{upsert: &model.SubjectFilterEntry{
        StreamId:     "s1",
        CanonicalKey: "k1",
        EnforceAt:    relayNow.Add(30 * time.Second),
    }}

    got := planHybridRelay(before, change, false /*add*/, 30)
    if got != RelayDecisionDeferred {
        t.Fatalf("Remove with grace > 0 must defer the upstream relay, got %v", got)
    }
}

// TestPlanHybridRelay_ReAddDuringGraceIsNoop verifies that a re-Add of a
// pending entry produces RelayDecisionNone — the upstream subscription was
// never dropped because the original Remove deferred its relay, so re-firing
// an upstream Add would be wrong (it would duplicate the subscription) and
// also waste a request.
func TestPlanHybridRelay_ReAddDuringGraceIsNoop(t *testing.T) {
    pending := &model.SubjectFilterEntry{
        StreamId:     "s1",
        CanonicalKey: "k1",
        EnforceAt:    relayNow.Add(20 * time.Second),
    }
    // planStart on NONE returns an upsert with EnforceAt cleared (revive).
    change := graceChange{upsert: &model.SubjectFilterEntry{
        StreamId:     "s1",
        CanonicalKey: "k1",
        // EnforceAt zero — revived.
    }}

    got := planHybridRelay(pending, change, true /*add*/, 30)
    if got != RelayDecisionNone {
        t.Fatalf("re-Add of a pending entry must not relay (upstream still subscribed), got %v", got)
    }
}

// TestPlanHybridRelay_FreshAddRelaysImmediate verifies that an Add with no
// prior entry produces RelayDecisionImmediate — a true 0→1 transition the
// upstream needs to know about right now.
func TestPlanHybridRelay_FreshAddRelaysImmediate(t *testing.T) {
    change := graceChange{upsert: &model.SubjectFilterEntry{
        StreamId:     "s1",
        CanonicalKey: "k1",
    }}

    got := planHybridRelay(nil /*before*/, change, true /*add*/, 30)
    if got != RelayDecisionImmediate {
        t.Fatalf("fresh Add must relay immediately (0→1 transition), got %v", got)
    }
}

// TestPlanHybridRelay_IdempotentReStopIsNoop verifies that a re-Remove on
// an already-pending entry — planGraceChange returns no mutation — produces
// RelayDecisionNone. The original Remove already queued the deferred relay.
func TestPlanHybridRelay_IdempotentReStopIsNoop(t *testing.T) {
    pending := &model.SubjectFilterEntry{
        StreamId:     "s1",
        CanonicalKey: "k1",
        EnforceAt:    relayNow.Add(20 * time.Second),
    }
    change := graceChange{} // planStop is idempotent on pending entries.

    got := planHybridRelay(pending, change, false /*add*/, 30)
    if got != RelayDecisionNone {
        t.Fatalf("idempotent re-Stop must not relay, got %v", got)
    }
}

// TestPlanHybridRelay_GraceZeroFallsBackImmediate verifies the no-grace
// fallback path: with grace == 0 every mutation relays immediately — the
// pre-#100 behavior an operator who has not opted into §9.3 expects.
func TestPlanHybridRelay_GraceZeroFallsBackImmediate(t *testing.T) {
    inclusion := &model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}
    change := graceChange{remove: true} // NONE+grace=0+existing inclusion: planStop returns remove.

    got := planHybridRelay(inclusion, change, false /*add*/, 0)
    if got != RelayDecisionImmediate {
        t.Fatalf("grace=0 Remove must relay immediately (pre-#100 behavior), got %v", got)
    }
}

// TestPlanHybridRelay_GraceZeroNoMutationIsNoop verifies the no-grace
// fallback's quiet case: with grace == 0 and no mutation (a Remove on a
// non-existent entry) there is no upstream relay to fire.
func TestPlanHybridRelay_GraceZeroNoMutationIsNoop(t *testing.T) {
    change := graceChange{} // no mutation.

    got := planHybridRelay(nil, change, false, 0)
    if got != RelayDecisionNone {
        t.Fatalf("grace=0 with no mutation must not relay, got %v", got)
    }
}

// TestSubjectFilterService_RemoveWithGraceReturnsDeferred verifies the
// service-level wiring: SubjectFilterService.RemoveSubject on a stream with
// grace > 0 returns RelayDecisionDeferred so the API handler can skip the
// immediate RelayHybrid call (issue #100).
func TestSubjectFilterService_RemoveWithGraceReturnsDeferred(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(relayNow)
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("hybrid-defer-test")
    stream.SubjectRemovalGraceSeconds = 30

    subject := emailSubject("alice@example.com")

    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }

    decision, err := svc.RemoveSubject(ctx, stream, subject)
    if err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }
    if decision != RelayDecisionDeferred {
        t.Fatalf("Remove with grace > 0 must return RelayDecisionDeferred, got %v", decision)
    }
}

// TestSubjectFilterService_AddReturnsImmediateForFreshAdd verifies the
// service-level wiring for the common Add case: a fresh AddSubject (no
// pre-existing entry) returns RelayDecisionImmediate so the API handler
// fires the upstream relay synchronously (the pre-#100 behavior).
func TestSubjectFilterService_AddReturnsImmediateForFreshAdd(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(relayNow)
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("hybrid-add-test")
    stream.SubjectRemovalGraceSeconds = 30

    decision, err := svc.AddSubject(ctx, stream, emailSubject("alice@example.com"), false)
    if err != nil {
        t.Fatalf("AddSubject: %v", err)
    }
    if decision != RelayDecisionImmediate {
        t.Fatalf("fresh Add must return RelayDecisionImmediate, got %v", decision)
    }
}

// TestSubjectFilterService_ReAddDuringGraceReturnsNone verifies the revive
// case: re-Adding a pending entry returns RelayDecisionNone so the API
// handler does not fire a redundant upstream Add (the upstream subscription
// is still active because the original Remove deferred its relay).
func TestSubjectFilterService_ReAddDuringGraceReturnsNone(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(relayNow)
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("hybrid-revive-test")
    stream.SubjectRemovalGraceSeconds = 30

    subject := emailSubject("alice@example.com")

    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject (initial): %v", err)
    }
    if _, err := svc.RemoveSubject(ctx, stream, subject); err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }

    decision, err := svc.AddSubject(ctx, stream, subject, false)
    if err != nil {
        t.Fatalf("AddSubject (revive): %v", err)
    }
    if decision != RelayDecisionNone {
        t.Fatalf("revive Add must return RelayDecisionNone (upstream still subscribed), got %v", decision)
    }
}

// TestSubjectFilterService_SweepDeferredHybridRelaysFiresAfterEnforceAt is
// the slice #100 sweep tracer: after enforceAt elapses, the
// SweepDeferredHybridRelays call enumerates the pending entries for the
// stream, invokes the supplied relay for each subject, and deletes the
// local entry on success. Before enforceAt the sweep finds nothing.
func TestSubjectFilterService_SweepDeferredHybridRelaysFiresAfterEnforceAt(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(relayNow)
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("hybrid-sweep")
    stream.SubjectRemovalGraceSeconds = 30
    subject := emailSubject("alice@example.com")

    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }
    if _, err := svc.RemoveSubject(ctx, stream, subject); err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }

    var relayed []string
    relay := func(_ context.Context, _ *model.StreamStateRecord, e *model.SubjectFilterEntry) error {
        relayed = append(relayed, e.CanonicalKey)
        return nil
    }

    // Inside the grace window the sweep must do nothing.
    n, err := svc.SweepDeferredHybridRelays(ctx, stream, relay)
    if err != nil {
        t.Fatalf("SweepDeferredHybridRelays (in-window): %v", err)
    }
    if n != 0 || len(relayed) != 0 {
        t.Fatalf("sweep inside the grace window must do nothing, got n=%d relayed=%v", n, relayed)
    }

    // Past enforceAt the sweep must fire the relay and remove the local entry.
    clock.Advance(31 * time.Second)
    n, err = svc.SweepDeferredHybridRelays(ctx, stream, relay)
    if err != nil {
        t.Fatalf("SweepDeferredHybridRelays (elapsed): %v", err)
    }
    if n != 1 || len(relayed) != 1 {
        t.Fatalf("sweep past enforceAt must relay 1 subject, got n=%d relayed=%v", n, relayed)
    }
    // A second sweep must find nothing — the entry has been purged.
    relayed = relayed[:0]
    if n, _ := svc.SweepDeferredHybridRelays(ctx, stream, relay); n != 0 || len(relayed) != 0 {
        t.Fatalf("the entry must be purged after a successful relay; second sweep must find nothing, got n=%d relayed=%v", n, relayed)
    }
}

// TestSubjectFilterService_SweepDeferredHybridRelays_RetriesOnRelayFailure
// verifies that a relay failure leaves the local entry in place so the next
// sweep retries — the no-new-scheduler property described in the slice.
func TestSubjectFilterService_SweepDeferredHybridRelays_RetriesOnRelayFailure(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(relayNow)
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("hybrid-sweep-retry")
    stream.SubjectRemovalGraceSeconds = 30
    subject := emailSubject("alice@example.com")

    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }
    if _, err := svc.RemoveSubject(ctx, stream, subject); err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }
    clock.Advance(31 * time.Second)

    fail := func(_ context.Context, _ *model.StreamStateRecord, _ *model.SubjectFilterEntry) error {
        return errSimulatedRelay
    }
    if _, err := svc.SweepDeferredHybridRelays(ctx, stream, fail); err != nil {
        t.Fatalf("SweepDeferredHybridRelays (failing relay): %v", err)
    }

    // The entry must still be present so a future sweep retries.
    succeed := func(_ context.Context, _ *model.StreamStateRecord, _ *model.SubjectFilterEntry) error {
        return nil
    }
    n, err := svc.SweepDeferredHybridRelays(ctx, stream, succeed)
    if err != nil {
        t.Fatalf("SweepDeferredHybridRelays (retry): %v", err)
    }
    if n != 1 {
        t.Fatalf("a failed relay must leave the entry for the next sweep to retry, got n=%d", n)
    }
}

// TestSubjectFilterService_SweepDeferredHybridRelays_ReAddCancelsDeferredRelay
// verifies the §9.3 cancellation rule: a re-Add before enforceAt revives the
// entry (clears EnforceAt) so the sweep no longer finds it — the upstream
// remove is never relayed. This is the acceptance criterion "a re-Add before
// enforceAt cancels the pending upstream remove" from slice #100.
func TestSubjectFilterService_SweepDeferredHybridRelays_ReAddCancelsDeferredRelay(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(relayNow)
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("hybrid-cancel")
    stream.SubjectRemovalGraceSeconds = 30
    subject := emailSubject("alice@example.com")

    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }
    if _, err := svc.RemoveSubject(ctx, stream, subject); err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }
    // Re-Add before enforceAt cancels the deferred upstream remove.
    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("re-AddSubject: %v", err)
    }

    // Past the original enforceAt — but the entry was revived (EnforceAt
    // cleared), so the sweep must find nothing and the upstream relay never
    // fires.
    clock.Advance(31 * time.Second)
    var relayed []string
    relay := func(_ context.Context, _ *model.StreamStateRecord, e *model.SubjectFilterEntry) error {
        relayed = append(relayed, e.CanonicalKey)
        return nil
    }
    n, err := svc.SweepDeferredHybridRelays(ctx, stream, relay)
    if err != nil {
        t.Fatalf("SweepDeferredHybridRelays: %v", err)
    }
    if n != 0 || len(relayed) != 0 {
        t.Fatalf("a re-Add before enforceAt must cancel the deferred upstream relay; got n=%d relayed=%v", n, relayed)
    }
}

var errSimulatedRelay = simulatedError("simulated upstream relay failure")

type simulatedError string

func (e simulatedError) Error() string { return string(e) }
