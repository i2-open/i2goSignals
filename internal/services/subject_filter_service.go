package services

import (
    "context"

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
}

// NewSubjectFilterService constructs a SubjectFilterService over the given DAO.
func NewSubjectFilterService(dao interfaces.SubjectFilterDAO) *SubjectFilterService {
    return &SubjectFilterService{
        dao:   dao,
        cache: newMatchCache(defaultMatchCacheTTL, defaultMatchCacheMaxKeys),
    }
}

// AddSubject opts subject into delivery on stream. The filter stores only the
// non-default set, so the effect depends on the stream's baseline: on a NONE
// stream an inclusion entry is written; on an ALL stream any exclusion entry is
// dropped. verified is stored for audit only and has no effect on filtering. It
// returns an error when the subject cannot be canonicalized (missing or
// unrecognized RFC9493 format).
func (s *SubjectFilterService) AddSubject(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier, verified bool) error {
    return s.applySubjectChange(ctx, stream, subject, verified, true)
}

// RemoveSubject opts subject out of delivery on stream. On a NONE stream any
// inclusion entry is dropped; on an ALL stream an exclusion entry is written.
// It returns an error when the subject cannot be canonicalized.
func (s *SubjectFilterService) RemoveSubject(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier) error {
    return s.applySubjectChange(ctx, stream, subject, false, false)
}

// applySubjectChange writes or removes a filter entry for subject. add reports
// whether the receiver wants the subject delivered; combined with the stream's
// baseline it decides whether a non-default-set entry is inserted or deleted.
func (s *SubjectFilterService) applySubjectChange(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier, verified, add bool) error {
    streamID := stream.StreamConfiguration.Id
    key, err := subjectid.CanonicalKey(subject)
    if err != nil {
        return err
    }
    // An entry always means "the opposite of the baseline". A NONE stream
    // stores inclusions, so Add inserts; an ALL stream stores exclusions, so
    // Remove inserts. The other two combinations drop the entry.
    insert := (stream.DefaultSubjects == model.DefaultSubjectsNone) == add
    if insert {
        err = s.dao.Add(ctx, &model.SubjectFilterEntry{
            StreamId:     streamID,
            CanonicalKey: key,
            Kind:         kindString(subjectid.Kind(subject)),
            Subject:      subject,
            Verified:     verified,
        })
    } else {
        err = s.dao.Remove(ctx, streamID, key)
    }
    if err == nil {
        s.cache.invalidateStream(streamID)
    }
    return err
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

// InvalidateCache drops every cached match decision for streamID on this node.
// It is the cluster reload signal of PRD #89 (ADR-0003): when an Add/Remove
// Subject is processed on a peer node, that node notifies this stream's
// push-transmitter lease owner, which calls InvalidateCache so its next
// delivery-time decision re-reads the updated filter.
func (s *SubjectFilterService) InvalidateCache(streamID string) {
    s.cache.invalidateStream(streamID)
}

// Allows reports whether event should be delivered to stream under its subject
// filter. Operational events and a server-wide disabled feature always pass.
// On a NONE stream an event delivers only when its subject is in the filter; on
// an ALL stream it delivers unless its subject is in the filter.
func (s *SubjectFilterService) Allows(ctx context.Context, stream *model.StreamStateRecord, event *model.AgEventRecord) bool {
    if !SubjectFilteringEnabled() || event == nil || event.Operational {
        return true
    }
    matched := s.matches(ctx, stream.StreamConfiguration.Id, event.Event.SubjectId)
    if stream.DefaultSubjects == model.DefaultSubjectsNone {
        return matched
    }
    return !matched
}

// matches reports whether subject is present in the stream's filter. A live
// match-result cache hit is returned directly; a miss is computed and cached.
func (s *SubjectFilterService) matches(ctx context.Context, streamID string, subject *goSet.SubjectIdentifier) bool {
    key, err := subjectid.CanonicalKey(subject)
    if err != nil {
        return false
    }
    if cached, hit := s.cache.get(streamID, key); hit {
        return cached
    }
    result := s.computeMatch(ctx, streamID, key, subject)
    s.cache.put(streamID, key, result)
    return result
}

// computeMatch evaluates subject against the stream's filter on a cache miss.
// It takes the two ADR-0003 paths: an indexed canonical-key Get for
// simple-subject membership (O(1), the path that scales to millions of
// entries), then a field-wise scan of the small complex/aliases list, which
// lets a broad subscription match a narrower, more-specific event per SSF
// §8.1.3.1.
func (s *SubjectFilterService) computeMatch(ctx context.Context, streamID, key string, subject *goSet.SubjectIdentifier) bool {
    if _, err := s.dao.Get(ctx, streamID, key); err == nil {
        return true
    }
    complexEntries, err := s.dao.ListComplex(ctx, streamID)
    if err != nil {
        return false
    }
    for _, entry := range complexEntries {
        if subjectid.Match(entry.Subject, subject) {
            return true
        }
    }
    return false
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
