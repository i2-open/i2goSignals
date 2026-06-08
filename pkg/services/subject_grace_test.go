package services

import (
    "context"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/pkg/dao/memory"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestSubjectFilterService_NoneRemoveKeepsDeliveringDuringGrace is the slice
// #99 tracer bullet for SSF §9.3: a Remove on a LOCAL NONE stream keeps
// delivering the affected subject for the configured grace window, then stops
// once enforceAt elapses. A malicious or coerced receiver cannot instantly
// blind a downstream by removing a victim subject.
func TestSubjectFilterService_NoneRemoveKeepsDeliveringDuringGrace(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC))
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("stream-grace")
    stream.SubjectRemovalGraceSeconds = 5

    subject := emailSubject("alice@example.com")
    event := eventFor(subject)

    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }
    if !svc.Allows(ctx, stream, event) {
        t.Fatal("precondition: a NONE stream must deliver an added subject")
    }

    if _, err := svc.RemoveSubject(ctx, stream, subject); err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }

    if !svc.Allows(ctx, stream, event) {
        t.Fatal("during the grace window the removed subject must keep delivering (§9.3)")
    }

    clock.Advance(4 * time.Second)
    if !svc.Allows(ctx, stream, event) {
        t.Fatal("4s into a 5s grace window the subject must still deliver")
    }

    clock.Advance(2 * time.Second) // total 6s, past enforceAt
    if svc.Allows(ctx, stream, event) {
        t.Fatal("after the grace window elapses the subject must stop delivering")
    }
}

// TestSubjectFilterService_AllRemoveKeepsDeliveringDuringGrace verifies the
// §9.3 grace symmetry on an ALL baseline: a Remove on an ALL stream stamps a
// pending exclusion that does not take effect until enforceAt, so the subject
// keeps delivering during the grace window.
func TestSubjectFilterService_AllRemoveKeepsDeliveringDuringGrace(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC))
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := allStream("stream-grace-all")
    stream.SubjectRemovalGraceSeconds = 5

    subject := emailSubject("alice@example.com")
    event := eventFor(subject)

    if !svc.Allows(ctx, stream, event) {
        t.Fatal("precondition: an ALL stream with an empty filter must deliver every subject")
    }

    if _, err := svc.RemoveSubject(ctx, stream, subject); err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }

    if !svc.Allows(ctx, stream, event) {
        t.Fatal("during the grace window the pending exclusion must not yet drop the subject (§9.3)")
    }

    clock.Advance(6 * time.Second) // past enforceAt
    if svc.Allows(ctx, stream, event) {
        t.Fatal("after the grace window elapses the exclusion must take effect and the subject must stop delivering")
    }
}

// TestSubjectFilterService_ReAddDuringGraceRevives verifies that a re-Add on a
// pending-removal entry cancels the pending stop (no delivery gap, no
// duplicate entry) — the §9.3 revive rule.
func TestSubjectFilterService_ReAddDuringGraceRevives(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC))
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("stream-revive")
    stream.SubjectRemovalGraceSeconds = 5

    subject := emailSubject("alice@example.com")
    event := eventFor(subject)

    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }
    if _, err := svc.RemoveSubject(ctx, stream, subject); err != nil {
        t.Fatalf("RemoveSubject: %v", err)
    }
    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("re-AddSubject (revive): %v", err)
    }

    // Past the original grace window — if revive cleared EnforceAt, delivery
    // must still hold; otherwise the entry would be enforced and drop.
    clock.Advance(10 * time.Second)
    if !svc.Allows(ctx, stream, event) {
        t.Fatal("a re-Add during the grace window must revive the entry (clear EnforceAt)")
    }
}

// TestSubjectFilterService_DefaultSubjectsFlipClearsAndBypassesGrace verifies
// the §9.3 admin-bypass rule: a defaultSubjects flip is a deliberate operator
// action (not the receiver-initiated threat §9.3 protects against), so
// ClearFilter wipes the table immediately and any pending-removal entries are
// discarded with no grace. After a flip the predicate falls back to the new
// baseline as if the filter had always been empty.
func TestSubjectFilterService_DefaultSubjectsFlipClearsAndBypassesGrace(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC))
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("stream-flip")
    stream.SubjectRemovalGraceSeconds = 60

    keep := emailSubject("keep@example.com")
    pending := emailSubject("pending@example.com")

    if _, err := svc.AddSubject(ctx, stream, keep, false); err != nil {
        t.Fatalf("AddSubject keep: %v", err)
    }
    if _, err := svc.AddSubject(ctx, stream, pending, false); err != nil {
        t.Fatalf("AddSubject pending: %v", err)
    }
    if _, err := svc.RemoveSubject(ctx, stream, pending); err != nil {
        t.Fatalf("RemoveSubject pending (sets up pending-removal entry): %v", err)
    }

    // Operator flips the baseline. ClearFilter is the storage-side
    // implementation of the flip.
    if err := svc.ClearFilter(ctx, stream.StreamConfiguration.Id); err != nil {
        t.Fatalf("ClearFilter: %v", err)
    }

    // Reflect the flip on the in-memory stream record so the predicate sees
    // the new baseline (in production the StreamService writes both).
    stream.DefaultSubjects = model.DefaultSubjectsAll

    // After the flip the table is empty: under ALL, every subject delivers
    // immediately — including the one that was mid-grace. Grace did not gate
    // the flip.
    if !svc.Allows(ctx, stream, eventFor(pending)) {
        t.Fatal("after a defaultSubjects flip the pending-removal entry must be discarded — every subject delivers under the new ALL baseline")
    }
    if !svc.Allows(ctx, stream, eventFor(keep)) {
        t.Fatal("after a defaultSubjects flip the active inclusion must also be discarded — every subject delivers under the new ALL baseline")
    }
}

// TestSubjectFilterService_StartDeliveryIsImmediate verifies the §9.3
// asymmetry: a delivery-starting change is never deferred by the grace
// window. Independent of baseline, an Add takes effect immediately.
func TestSubjectFilterService_StartDeliveryIsImmediate(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    clock := newFakeClock(time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC))
    svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
    svc.SetNow(clock.Now)

    stream := noneStream("stream-start")
    stream.SubjectRemovalGraceSeconds = 60

    subject := emailSubject("alice@example.com")
    event := eventFor(subject)

    // NONE: nothing delivers until Add; the Add must take effect immediately
    // even with a long grace configured.
    if _, err := svc.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }
    if !svc.Allows(ctx, stream, event) {
        t.Fatal("a delivery-starting change must take effect immediately, not after the grace window")
    }
}

// fakeClock is a hand-cranked monotonic clock used by grace tests so the §9.3
// boundary can be exercised without sleeping.
type fakeClock struct {
    t time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{t: start} }
func (c *fakeClock) Now() time.Time           { return c.t }
func (c *fakeClock) Advance(d time.Duration)  { c.t = c.t.Add(d) }

// noneStream-and-friends helpers live in subject_filter_service_test.go in the
// same package; reuse them.
var _ = model.DefaultSubjectsNone
