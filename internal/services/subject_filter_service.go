package services

import (
    "context"
    "errors"
    "time"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/i2-open/i2goSignals/pkg/subjectid"
)

// SubjectFilterService owns a transmitter stream's SSF §8.1.3 subject filter:
// the non-default set of subjects, the ALL/NONE delivery decision, and the
// delivery-time Allows predicate built on the §8.1.3.1 matching module
// (pkg/subjectid). It is the "fat service" of PRD #89 — the thin persistence
// sits behind interfaces.SubjectFilterDAO.
type SubjectFilterService struct {
    dao   interfaces.SubjectFilterDAO
    cache *matchCache
    now   func() time.Time
}

// NewSubjectFilterService constructs a SubjectFilterService over the given DAO.
func NewSubjectFilterService(dao interfaces.SubjectFilterDAO) *SubjectFilterService {
    return &SubjectFilterService{
        dao:   dao,
        cache: newMatchCache(defaultMatchCacheTTL, defaultMatchCacheMaxKeys),
        now:   time.Now,
    }
}

// SetNow overrides the clock used for SSF §9.3 grace evaluation. The default is
// time.Now; tests inject a fake clock to exercise the EnforceAt boundary
// without sleeping (PRD #97 issue #99).
func (s *SubjectFilterService) SetNow(now func() time.Time) {
    if now == nil {
        s.now = time.Now
        return
    }
    s.now = now
}

// AddSubject opts subject into delivery on stream. The filter stores only the
// non-default set, so the effect depends on the stream's baseline: on a NONE
// stream an inclusion entry is written; on an ALL stream any exclusion entry is
// dropped. A re-Add during the SSF §9.3 grace window revives a pending-removal
// entry (clears EnforceAt) so there is no delivery gap (PRD #97 issue #99).
// verified is stored for audit only and has no effect on filtering.
//
// The returned RelayDecision tells a HYBRID caller what to do with the
// upstream relay (PRD #97 issue #100): RelayDecisionImmediate for a fresh Add
// that crosses 0→1, RelayDecisionNone for a revive of a pending entry or an
// idempotent re-Add (upstream already subscribed). LOCAL callers ignore it.
// Returns an error when the subject cannot be canonicalized (missing or
// unrecognized RFC9493 format).
func (s *SubjectFilterService) AddSubject(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier, verified bool) (RelayDecision, error) {
    return s.applySubjectChange(ctx, stream, subject, verified, true)
}

// RemoveSubject opts subject out of delivery on stream. With a non-zero SSF
// §9.3 grace window the entry is upserted with EnforceAt = now + grace and
// delivery continues until EnforceAt; with grace 0 the change is immediate
// (NONE drops the inclusion, ALL inserts an active exclusion). A re-Remove on
// an already-pending entry does not extend the grace window.
//
// The returned RelayDecision tells a HYBRID caller what to do with the
// upstream relay (PRD #97 issue #100): RelayDecisionDeferred when a pending
// entry was stamped (the push-transmitter lease owner's sweep will fire the
// upstream remove at enforceAt), RelayDecisionImmediate for the grace-zero
// fallback that mutated state, RelayDecisionNone for an idempotent re-Remove.
// LOCAL callers ignore it. Returns an error when the subject cannot be
// canonicalized.
func (s *SubjectFilterService) RemoveSubject(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier) (RelayDecision, error) {
    return s.applySubjectChange(ctx, stream, subject, false, false)
}

// applySubjectChange writes or removes a filter entry for subject. add reports
// whether the receiver wants the subject delivered. The mutation is planned by
// planGraceChange — pure on (baseline, existing entry, add, grace, now) — so
// the §9.3 entry lifecycle (upsert / stamp / lazy-purge) is in one place and
// the start-vs-stop "gate the effect, not the verb" rule holds independent of
// baseline (PRD #97 issue #99). The upstream-relay decision is the pure
// planHybridRelay over the same inputs (issue #100).
func (s *SubjectFilterService) applySubjectChange(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier, verified, add bool) (RelayDecision, error) {
    streamID := stream.StreamConfiguration.Id
    key, err := subjectid.CanonicalKey(subject)
    if err != nil {
        return RelayDecisionNone, err
    }

    existing, err := s.dao.Get(ctx, streamID, key)
    if err != nil && !errors.Is(err, interfaces.ErrNotFound) {
        return RelayDecisionNone, err
    }
    if errors.Is(err, interfaces.ErrNotFound) {
        existing = nil
    }

    template := model.SubjectFilterEntry{
        StreamId:     streamID,
        CanonicalKey: key,
        Kind:         kindString(subjectid.Kind(subject)),
        Subject:      subject,
        Verified:     verified,
    }
    grace := s.resolveGrace(stream)
    change := planGraceChange(stream.DefaultSubjects, existing, template, add, grace, s.now())
    decision := planHybridRelay(existing, change, add, grace)

    switch {
    case change.upsert != nil:
        if err := s.dao.Add(ctx, change.upsert); err != nil {
            return RelayDecisionNone, err
        }
    case change.remove:
        if err := s.dao.Remove(ctx, streamID, key); err != nil {
            return RelayDecisionNone, err
        }
    }
    s.cache.invalidateStream(streamID)
    return decision, nil
}

// resolveGrace picks the SSF §9.3 grace seconds for stream: a non-zero
// per-transmitter-stream override wins; otherwise the server-wide default from
// I2SIG_SUBJECT_REMOVAL_GRACE. Returns 0 (immediate enforcement) when neither
// is set or when stream is nil. The grace is honored only on transmitter
// streams; the receiver-stream WARN-and-drop is enforced in StreamService
// CreateStream/UpdateStream (PRD #97 issue #98).
func (s *SubjectFilterService) resolveGrace(stream *model.StreamStateRecord) int {
    if stream == nil {
        return 0
    }
    if stream.SubjectRemovalGraceSeconds > 0 {
        return stream.SubjectRemovalGraceSeconds
    }
    return SubjectRemovalGraceDefaultSeconds()
}

// ClearFilter drops every subject filter entry for streamID, restoring the
// stream's baseline delivery policy. It is invoked when a stream's
// defaultSubjects baseline changes, so stale entries never carry the opposite
// meaning under the new baseline.
func (s *SubjectFilterService) ClearFilter(ctx context.Context, streamID string) error {
    err := s.dao.ClearForStream(ctx, streamID)
    if err == nil {
        s.cache.invalidateStream(streamID)
    }
    return err
}

// DeferredHybridRelayFn is the per-entry callback the SSF §9.3 sweep invokes
// for each elapsed pending entry on a HYBRID stream (PRD #97 issue #100). It
// is typically a closure that calls SubjectRelayService.RelayHybrid with
// add=false; returning a non-nil error leaves the local entry in place so
// the next sweep retries.
type DeferredHybridRelayFn func(ctx context.Context, stream *model.StreamStateRecord, entry *model.SubjectFilterEntry) error

// SweepDeferredHybridRelays enumerates every pending-removal entry for
// stream whose EnforceAt has elapsed at the service clock, invokes relay for
// each, and removes the local entry on success (PRD #97 issue #100). It is
// called from the push-transmitter lease owner's existing backfill ticker,
// so no new scheduler is introduced. Returns the number of entries whose
// relay succeeded.
//
// A relay-callback error is not propagated to the caller — failures are
// per-entry and the unsuccessful entries are left in place so the next
// sweep retries.
func (s *SubjectFilterService) SweepDeferredHybridRelays(ctx context.Context, stream *model.StreamStateRecord, relay DeferredHybridRelayFn) (int, error) {
    if stream == nil || relay == nil {
        return 0, nil
    }
    streamID := stream.StreamConfiguration.Id
    entries, err := s.dao.ListPendingDue(ctx, streamID, s.now())
    if err != nil {
        return 0, err
    }
    relayed := 0
    for _, entry := range entries {
        if err := relay(ctx, stream, entry); err != nil {
            // Leave the entry; the next sweep retries.
            continue
        }
        if err := s.dao.Remove(ctx, entry.StreamId, entry.CanonicalKey); err != nil {
            // The entry will be picked up again next sweep and the relay
            // re-fired — the upstream Remove Subject is idempotent.
            continue
        }
        relayed++
    }
    if relayed > 0 {
        s.cache.invalidateStream(streamID)
    }
    return relayed, nil
}

// InvalidateCache drops every cached match decision for streamID on this node.
// It is the cluster reload signal of PRD #89 (ADR-0003): when an Add/Remove
// Subject is processed on a peer node, that node notifies this stream's
// push-transmitter lease owner, which calls InvalidateCache so its next
// delivery-time decision re-reads the updated filter.
func (s *SubjectFilterService) InvalidateCache(streamID string) {
    s.cache.invalidateStream(streamID)
}

// Allows reports whether event should be delivered to stream under its subject
// filter. Operational events and a server-wide disabled feature always pass;
// otherwise the decision is delegated to Selects.
func (s *SubjectFilterService) Allows(ctx context.Context, stream *model.StreamStateRecord, event *model.AgEventRecord) bool {
    if !SubjectFilteringEnabled() || event == nil || event.Operational {
        return true
    }
    return s.Selects(ctx, stream, event.Event.SubjectId)
}

// Selects reports whether stream's subject filter currently delivers subject.
// The decision is delegated to entryDelivers, which gates the §9.3 effect on
// the entry's EnforceAt: a pending-removal entry keeps delivering until
// EnforceAt, after which it is treated as if it were absent (NONE) or active
// (ALL). It is Allows without the event/operational wrapper and is the HYBRID
// interested-set membership test (issue #96).
func (s *SubjectFilterService) Selects(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier) bool {
    entry := s.lookupEntry(ctx, stream.StreamConfiguration.Id, subject)
    return entryDelivers(stream.DefaultSubjects, entry, s.now())
}

// lookupEntry returns the filter entry for subject on streamID, or nil when no
// entry exists or canonicalization fails. The match-result cache stores the
// EnforceAt alongside the matched flag so the §9.3 predicate can re-evaluate
// the clock boundary on every call without re-reading storage.
func (s *SubjectFilterService) lookupEntry(ctx context.Context, streamID string, subject *goSet.SubjectIdentifier) *model.SubjectFilterEntry {
    key, err := subjectid.CanonicalKey(subject)
    if err != nil {
        return nil
    }
    if cached, hit := s.cache.get(streamID, key); hit {
        if !cached.matched {
            return nil
        }
        return &model.SubjectFilterEntry{StreamId: streamID, CanonicalKey: key, EnforceAt: cached.enforceAt}
    }
    entry := s.computeMatchEntry(ctx, streamID, key, subject)
    if entry == nil {
        s.cache.put(streamID, key, false, time.Time{})
        return nil
    }
    s.cache.put(streamID, key, true, entry.EnforceAt)
    return entry
}

// computeMatchEntry evaluates subject against the stream's filter on a cache
// miss. It takes the two ADR-0003 paths: an indexed canonical-key Get for
// simple-subject membership (O(1), the path that scales to millions of
// entries), then a field-wise scan of the small complex/aliases list, which
// lets a broad subscription match a narrower, more-specific event per SSF
// §8.1.3.1. Returns the matched entry (with its EnforceAt) or nil.
func (s *SubjectFilterService) computeMatchEntry(ctx context.Context, streamID, key string, subject *goSet.SubjectIdentifier) *model.SubjectFilterEntry {
    if entry, err := s.dao.Get(ctx, streamID, key); err == nil {
        return entry
    }
    complexEntries, err := s.dao.ListComplex(ctx, streamID)
    if err != nil {
        return nil
    }
    for _, entry := range complexEntries {
        if subjectid.Match(entry.Subject, subject) {
            return entry
        }
    }
    return nil
}

// kindString maps a subjectid.SubjectKind to its stored string form.
func kindString(k subjectid.SubjectKind) string {
    switch k {
    case subjectid.KindComplex:
        return model.SubjectKindComplex
    case subjectid.KindAliases:
        return model.SubjectKindAliases
    default:
        return model.SubjectKindSimple
    }
}
