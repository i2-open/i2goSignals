package memory

import (
    "context"
    "errors"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// simpleEntry builds a simple-kind SubjectFilterEntry for the given stream and
// canonical key.
func simpleEntry(streamID, key string) *model.SubjectFilterEntry {
    return &model.SubjectFilterEntry{StreamId: streamID, CanonicalKey: key, Kind: model.SubjectKindSimple}
}

// TestSubjectFilterDAOMemory_RemoveDeletesEntry verifies Remove deletes the
// entry for a (stream, canonical key) so a subsequent Get reports ErrNotFound.
func TestSubjectFilterDAOMemory_RemoveDeletesEntry(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    if err := dao.Add(ctx, simpleEntry("stream-1", "email:alice@example.com")); err != nil {
        t.Fatalf("Add: %v", err)
    }
    if err := dao.Remove(ctx, "stream-1", "email:alice@example.com"); err != nil {
        t.Fatalf("Remove: %v", err)
    }

    _, err := dao.Get(ctx, "stream-1", "email:alice@example.com")
    if !errors.Is(err, interfaces.ErrNotFound) {
        t.Fatalf("after Remove, Get must report ErrNotFound, got %v", err)
    }
}

// TestSubjectFilterDAOMemory_ClearForStreamWipesOnlyThatStream verifies
// ClearForStream removes every entry for the named stream and leaves other
// streams' entries untouched.
func TestSubjectFilterDAOMemory_ClearForStreamWipesOnlyThatStream(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    _ = dao.Add(ctx, simpleEntry("stream-1", "email:alice@example.com"))
    _ = dao.Add(ctx, simpleEntry("stream-1", "email:bob@example.com"))
    _ = dao.Add(ctx, simpleEntry("stream-2", "email:carol@example.com"))

    if err := dao.ClearForStream(ctx, "stream-1"); err != nil {
        t.Fatalf("ClearForStream: %v", err)
    }

    if _, err := dao.Get(ctx, "stream-1", "email:alice@example.com"); !errors.Is(err, interfaces.ErrNotFound) {
        t.Fatalf("stream-1 entry alice must be cleared, got %v", err)
    }
    if _, err := dao.Get(ctx, "stream-1", "email:bob@example.com"); !errors.Is(err, interfaces.ErrNotFound) {
        t.Fatalf("stream-1 entry bob must be cleared, got %v", err)
    }
    if _, err := dao.Get(ctx, "stream-2", "email:carol@example.com"); err != nil {
        t.Fatalf("stream-2 entry must survive ClearForStream(stream-1), got %v", err)
    }
}

// TestSubjectFilterDAOMemory_EnforceAtRoundTrips verifies the SSF §9.3
// EnforceAt field survives Add/Get round-trip on the memory adapter (PRD #97
// issue #99). The field is part of the persisted shape; matching parity on
// the Mongo adapter is verified in its own test.
func TestSubjectFilterDAOMemory_EnforceAtRoundTrips(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    deadline := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
    entry := simpleEntry("stream-1", "email:alice@example.com")
    entry.EnforceAt = deadline

    if err := dao.Add(ctx, entry); err != nil {
        t.Fatalf("Add: %v", err)
    }
    got, err := dao.Get(ctx, "stream-1", "email:alice@example.com")
    if err != nil {
        t.Fatalf("Get: %v", err)
    }
    if !got.EnforceAt.Equal(deadline) {
        t.Fatalf("EnforceAt did not round-trip: want %v, got %v", deadline, got.EnforceAt)
    }
}

// TestSubjectFilterDAOMemory_EnforceAtReviveClearsField verifies that an Add
// with EnforceAt zero overwrites an existing pending-removal entry — the
// revive case from §9.3 — so the stored entry no longer carries a deadline.
func TestSubjectFilterDAOMemory_EnforceAtReviveClearsField(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    deadline := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
    pending := simpleEntry("stream-1", "email:alice@example.com")
    pending.EnforceAt = deadline
    if err := dao.Add(ctx, pending); err != nil {
        t.Fatalf("Add (pending): %v", err)
    }

    revived := simpleEntry("stream-1", "email:alice@example.com")
    // revived.EnforceAt is the zero value (no deadline).
    if err := dao.Add(ctx, revived); err != nil {
        t.Fatalf("Add (revive): %v", err)
    }

    got, err := dao.Get(ctx, "stream-1", "email:alice@example.com")
    if err != nil {
        t.Fatalf("Get: %v", err)
    }
    if !got.EnforceAt.IsZero() {
        t.Fatalf("revive must clear EnforceAt, got %v", got.EnforceAt)
    }
}

// TestSubjectFilterDAOMemory_ListPendingDueReturnsOnlyElapsedForStream verifies
// the SSF §9.3 sweep enumerator (PRD #97 issue #100): ListPendingDue returns
// every entry for the named stream whose EnforceAt is set and has elapsed at
// the supplied now, and never returns active entries (EnforceAt zero) or
// entries belonging to other streams.
func TestSubjectFilterDAOMemory_ListPendingDueReturnsOnlyElapsedForStream(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

    elapsed := simpleEntry("stream-1", "email:elapsed@example.com")
    elapsed.EnforceAt = now.Add(-time.Second)
    _ = dao.Add(ctx, elapsed)

    pending := simpleEntry("stream-1", "email:pending@example.com")
    pending.EnforceAt = now.Add(30 * time.Second)
    _ = dao.Add(ctx, pending)

    active := simpleEntry("stream-1", "email:active@example.com")
    // EnforceAt is zero — fully active, not pending.
    _ = dao.Add(ctx, active)

    otherStream := simpleEntry("stream-2", "email:elapsed-other@example.com")
    otherStream.EnforceAt = now.Add(-time.Second)
    _ = dao.Add(ctx, otherStream)

    got, err := dao.ListPendingDue(ctx, "stream-1", now)
    if err != nil {
        t.Fatalf("ListPendingDue: %v", err)
    }
    if len(got) != 1 {
        t.Fatalf("ListPendingDue must return only the elapsed stream-1 entry, got %d entries", len(got))
    }
    if got[0].CanonicalKey != "email:elapsed@example.com" {
        t.Fatalf("expected the elapsed entry, got canonical_key %q", got[0].CanonicalKey)
    }
}

// TestSubjectFilterDAOMemory_ListPendingDueBoundaryIsInclusive verifies the
// clock-boundary behavior: an entry whose EnforceAt equals now is treated as
// elapsed (consistent with entryDelivers's clock-boundary rule from slice
// #99), so the sweep relays it on the tick that crosses the boundary.
func TestSubjectFilterDAOMemory_ListPendingDueBoundaryIsInclusive(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

    boundary := simpleEntry("stream-1", "email:boundary@example.com")
    boundary.EnforceAt = now
    _ = dao.Add(ctx, boundary)

    got, err := dao.ListPendingDue(ctx, "stream-1", now)
    if err != nil {
        t.Fatalf("ListPendingDue: %v", err)
    }
    if len(got) != 1 {
        t.Fatalf("an entry whose EnforceAt equals now must be elapsed, got %d entries", len(got))
    }
}

// TestSubjectFilterDAOMemory_ListPendingReturnsOnlyInGraceForStream verifies
// the admin-review pending enumerator (PRD #97 issue #101): ListPending
// returns entries with EnforceAt strictly after now (still in §9.3 grace
// window), excludes due-but-not-swept entries (EnforceAt <= now), excludes
// active entries (EnforceAt zero), and ignores other streams.
func TestSubjectFilterDAOMemory_ListPendingReturnsOnlyInGraceForStream(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

    inGrace := simpleEntry("stream-1", "email:in-grace@example.com")
    inGrace.EnforceAt = now.Add(30 * time.Second)
    _ = dao.Add(ctx, inGrace)

    due := simpleEntry("stream-1", "email:due@example.com")
    due.EnforceAt = now.Add(-time.Second)
    _ = dao.Add(ctx, due)

    boundary := simpleEntry("stream-1", "email:boundary@example.com")
    boundary.EnforceAt = now
    _ = dao.Add(ctx, boundary)

    active := simpleEntry("stream-1", "email:active@example.com")
    _ = dao.Add(ctx, active)

    other := simpleEntry("stream-2", "email:in-grace-other@example.com")
    other.EnforceAt = now.Add(30 * time.Second)
    _ = dao.Add(ctx, other)

    got, err := dao.ListPending(ctx, "stream-1", now)
    if err != nil {
        t.Fatalf("ListPending: %v", err)
    }
    if len(got) != 1 {
        t.Fatalf("ListPending must return only the in-grace stream-1 entry, got %d entries", len(got))
    }
    if got[0].CanonicalKey != "email:in-grace@example.com" {
        t.Fatalf("expected the in-grace entry, got canonical_key %q", got[0].CanonicalKey)
    }
}

// TestSubjectFilterDAOMemory_CountReturnsTotalAndPending verifies Count
// reports the total entry count for a stream and the subset currently inside
// the §9.3 grace window (PRD #97 issue #101). Active entries count toward
// total but not pending; due-or-elapsed entries also count toward total but
// not pending (they have already crossed the grace boundary).
func TestSubjectFilterDAOMemory_CountReturnsTotalAndPending(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

    inGrace := simpleEntry("stream-1", "email:in-grace@example.com")
    inGrace.EnforceAt = now.Add(30 * time.Second)
    _ = dao.Add(ctx, inGrace)

    due := simpleEntry("stream-1", "email:due@example.com")
    due.EnforceAt = now.Add(-time.Second)
    _ = dao.Add(ctx, due)

    active := simpleEntry("stream-1", "email:active@example.com")
    _ = dao.Add(ctx, active)

    _ = dao.Add(ctx, simpleEntry("stream-2", "email:other@example.com"))

    total, pending, err := dao.Count(ctx, "stream-1", now)
    if err != nil {
        t.Fatalf("Count: %v", err)
    }
    if total != 3 {
        t.Fatalf("total must count every stream-1 entry (active + due + in-grace), got %d", total)
    }
    if pending != 1 {
        t.Fatalf("pending must count only the in-grace entry, got %d", pending)
    }
}

// TestSubjectFilterDAOMemory_ListComplexReturnsOnlyNonSimpleForStream verifies
// ListComplex returns the complex and aliases entries for one stream and never
// the simple entries (which are reached by indexed Get, per ADR-0003).
func TestSubjectFilterDAOMemory_ListComplexReturnsOnlyNonSimpleForStream(t *testing.T) {
    ctx := context.Background()
    dao := NewSubjectFilterDAO()

    _ = dao.Add(ctx, simpleEntry("stream-1", "email:alice@example.com"))
    _ = dao.Add(ctx, &model.SubjectFilterEntry{StreamId: "stream-1", CanonicalKey: "complex:[user=email:u]", Kind: model.SubjectKindComplex})
    _ = dao.Add(ctx, &model.SubjectFilterEntry{StreamId: "stream-1", CanonicalKey: "aliases:[email:a]", Kind: model.SubjectKindAliases})
    _ = dao.Add(ctx, &model.SubjectFilterEntry{StreamId: "stream-2", CanonicalKey: "complex:[user=email:v]", Kind: model.SubjectKindComplex})

    got, err := dao.ListComplex(ctx, "stream-1")
    if err != nil {
        t.Fatalf("ListComplex: %v", err)
    }
    if len(got) != 2 {
        t.Fatalf("ListComplex(stream-1) must return the 2 non-simple entries, got %d", len(got))
    }
    for _, e := range got {
        if e.Kind == model.SubjectKindSimple {
            t.Fatalf("ListComplex must never return a simple entry, got kind %q", e.Kind)
        }
        if e.StreamId != "stream-1" {
            t.Fatalf("ListComplex(stream-1) must only return stream-1 entries, got %q", e.StreamId)
        }
    }
}
