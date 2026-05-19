package services

import (
    "context"
    "testing"

    "github.com/i2-open/i2goSignals/internal/dao/memory"
)

// TestSubjectFilterService_InvalidateCache_ReflectsRemoteNodeChange simulates
// the PRD #89 cluster scenario (issue #94, ADR-0003): an Add Subject processed
// on one node leaves a peer node's match-result cache stale, and InvalidateCache
// on the peer makes its next decision re-read the shared filter.
func TestSubjectFilterService_InvalidateCache_ReflectsRemoteNodeChange(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    // Two SubjectFilterService instances over one shared DAO model two cluster
    // nodes backed by the same subject_filters collection.
    dao := memory.NewSubjectFilterDAO()
    owner := NewSubjectFilterService(dao) // holds the push-transmitter lease
    peer := NewSubjectFilterService(dao)  // receives the Add Subject request

    stream := noneStream("stream-1")
    subject := emailSubject("alice@example.com")
    event := eventFor(subject)

    // The owner caches a "drop" decision (NONE stream, empty filter).
    if owner.Allows(ctx, stream, event) {
        t.Fatal("precondition: NONE stream with an empty filter must not deliver")
    }

    // The Add Subject lands on the peer node; only the peer's cache is cleared.
    if err := peer.AddSubject(ctx, stream, subject, false); err != nil {
        t.Fatalf("AddSubject: %v", err)
    }

    // The owner's cache is now stale: the filter changed but its cached "drop"
    // still suppresses the subject.
    if owner.Allows(ctx, stream, event) {
        t.Fatal("precondition: the owner's cached decision is expected to be stale")
    }

    // The cluster notification reaches the owner.
    owner.InvalidateCache("stream-1")

    if !owner.Allows(ctx, stream, event) {
        t.Fatal("after InvalidateCache the owner must re-read the filter and deliver")
    }
}
