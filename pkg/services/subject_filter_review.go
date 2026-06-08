package services

import (
    "context"
    "errors"
    "time"

    "github.com/i2-open/i2goSignals/pkg/goSet"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/i2-open/i2goSignals/pkg/subjectid"
)

// SubjectFilterReview is the read-only operator view of a stream's locally
// managed SSF §8.1.3 subject filter, returned by SubjectFilterService.Review
// (PRD #97 issue #101). It is shaped for the admin endpoint and the
// cmd/goSignals CLI: a single summary object — never a paginated stream of
// entries (ADR-0003 keeps the review a point-lookup + counts).
type SubjectFilterReview struct {
    // Stream identifies the stream the review describes.
    Stream *model.StreamStateRecord
    // NoLocalFilter is true for a PASSTHRU stream — goSignals keeps no local
    // filter table for it; the upstream transmitter's filter is authoritative.
    NoLocalFilter bool
    // Counts is the aggregate shape of the local filter table for the stream.
    // nil for PASSTHRU.
    Counts *SubjectFilterCounts
    // Pending lists the entries currently inside their SSF §9.3 grace window
    // (EnforceAt in the future at the service clock). Empty when no entry is
    // mid-removal. nil for PASSTHRU.
    Pending []*model.SubjectFilterEntry
    // Lookup is the point-lookup result; non-nil only when the caller supplied
    // a subject to query. Found=false means no entry was matched.
    Lookup *SubjectFilterLookup
}

// SubjectFilterCounts is the aggregate count pair for a stream's local filter
// table. Pending is the subset of Total currently inside their §9.3 grace
// window.
type SubjectFilterCounts struct {
    Total   int64
    Pending int64
}

// SubjectFilterLookup is the point-lookup result for one subject against a
// stream's local filter. Delivers is the §9.3-aware delivery-time predicate at
// the service clock — true when the stream would currently deliver an event
// for this subject given its baseline and the matched entry's state.
type SubjectFilterLookup struct {
    Subject      *goSet.SubjectIdentifier
    Found        bool
    Kind         string
    CanonicalKey string
    EnforceAt    time.Time
    Pending      bool
    Delivers     bool
}

// Review assembles the read-only admin view of stream's locally managed subject
// filter (PRD #97 issue #101). lookupSubject is optional: when non-nil it adds
// a point-lookup result; when nil the response carries only counts + pending
// list. A PASSTHRU stream returns NoLocalFilter=true and no counts/pending —
// goSignals does not keep a local filter table for it (per #89 / ADR-0003).
//
// Review never enumerates the full filter — the bounded outputs are aggregate
// counts and the (small by construction) pending-removal list. Reads run
// against the DAO directly, bypassing the match-result cache, so the operator
// view reflects persisted state, not a per-node cached decision.
func (s *SubjectFilterService) Review(ctx context.Context, stream *model.StreamStateRecord, lookupSubject *goSet.SubjectIdentifier) (*SubjectFilterReview, error) {
    if stream == nil {
        return nil, errors.New("nil stream")
    }
    review := &SubjectFilterReview{Stream: stream}

    if stream.SubjectFilterMode == model.SubjectFilterModePassthru {
        review.NoLocalFilter = true
        if lookupSubject != nil {
            review.Lookup = &SubjectFilterLookup{Subject: lookupSubject}
        }
        return review, nil
    }

    streamID := stream.StreamConfiguration.Id
    now := s.now()

    total, pending, err := s.dao.Count(ctx, streamID, now)
    if err != nil {
        return nil, err
    }
    review.Counts = &SubjectFilterCounts{Total: total, Pending: pending}

    pendingDue, err := s.dao.ListPending(ctx, streamID, now)
    if err != nil {
        return nil, err
    }
    review.Pending = pendingDue

    if lookupSubject != nil {
        review.Lookup = s.lookupForReview(ctx, stream, lookupSubject, now)
    }
    return review, nil
}

// lookupForReview is the read-only point lookup used by Review. It reuses
// computeMatchEntry — ADR-0003's indexed Get followed by a complex/aliases
// scan — so the storage path is one tested function. The match-result cache
// is bypassed because the admin view must reflect persisted state, not a
// per-node cached decision.
func (s *SubjectFilterService) lookupForReview(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier, now time.Time) *SubjectFilterLookup {
    out := &SubjectFilterLookup{Subject: subject}
    key, err := subjectid.CanonicalKey(subject)
    if err != nil {
        // An uncanonicalizable subject cannot match any entry; delivery is
        // the baseline default at now.
        out.Delivers = entryDelivers(stream.DefaultSubjects, nil, now)
        return out
    }
    out.CanonicalKey = key
    entry := s.computeMatchEntry(ctx, stream.StreamConfiguration.Id, key, subject)
    if entry == nil {
        out.Delivers = entryDelivers(stream.DefaultSubjects, nil, now)
        return out
    }
    out.Found = true
    out.Kind = entry.Kind
    out.CanonicalKey = entry.CanonicalKey
    out.EnforceAt = entry.EnforceAt
    out.Pending = entryPending(entry, now)
    out.Delivers = entryDelivers(stream.DefaultSubjects, entry, now)
    return out
}
