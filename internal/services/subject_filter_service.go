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
    dao interfaces.SubjectFilterDAO
}

// NewSubjectFilterService constructs a SubjectFilterService over the given DAO.
func NewSubjectFilterService(dao interfaces.SubjectFilterDAO) *SubjectFilterService {
    return &SubjectFilterService{dao: dao}
}

// AddSubject records subject in the stream's filter. On a NONE stream this opts
// the subject into delivery. verified is stored for audit only and has no
// effect on filtering. It returns an error when the subject cannot be
// canonicalized (missing/unrecognized RFC9493 format).
func (s *SubjectFilterService) AddSubject(ctx context.Context, streamID string, subject *goSet.SubjectIdentifier, verified bool) error {
    key, err := subjectid.CanonicalKey(subject)
    if err != nil {
        return err
    }
    return s.dao.Add(ctx, &model.SubjectFilterEntry{
        StreamId:     streamID,
        CanonicalKey: key,
        Kind:         kindString(subjectid.Kind(subject)),
        Subject:      subject,
        Verified:     verified,
    })
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

// matches reports whether subject is present in the stream's filter.
func (s *SubjectFilterService) matches(ctx context.Context, streamID string, subject *goSet.SubjectIdentifier) bool {
    key, err := subjectid.CanonicalKey(subject)
    if err != nil {
        return false
    }
    _, err = s.dao.Get(ctx, streamID, key)
    return err == nil
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
