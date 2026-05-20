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
