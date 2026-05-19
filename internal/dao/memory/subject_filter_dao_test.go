package memory

import (
    "context"
    "errors"
    "testing"

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
