package memory

import (
    "context"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SubjectFilterDAOMemory is the file-backed in-memory SubjectFilterDAO. Entries
// are keyed by (stream_id, canonical_key); see ADR-0003.
type SubjectFilterDAOMemory struct {
    store *StateManager[string, model.SubjectFilterEntry]
}

// NewSubjectFilterDAO constructs an in-memory SubjectFilterDAO.
func NewSubjectFilterDAO() interfaces.SubjectFilterDAO {
    return &SubjectFilterDAOMemory{
        store: NewStateManager[string, model.SubjectFilterEntry](copySubjectFilterEntry),
    }
}

// sfKey is the composite store key for a (stream, canonical key) pair. The NUL
// separator cannot occur in either component.
func sfKey(streamID, canonicalKey string) string {
    return streamID + "\x00" + canonicalKey
}

func copySubjectFilterEntry(e *model.SubjectFilterEntry) *model.SubjectFilterEntry {
    cp := *e
    return &cp
}

func (d *SubjectFilterDAOMemory) Add(_ context.Context, entry *model.SubjectFilterEntry) error {
    d.store.Set(sfKey(entry.StreamId, entry.CanonicalKey), entry)
    return nil
}

func (d *SubjectFilterDAOMemory) Get(_ context.Context, streamID, canonicalKey string) (*model.SubjectFilterEntry, error) {
    if e, ok := d.store.Get(sfKey(streamID, canonicalKey)); ok {
        return e, nil
    }
    return nil, interfaces.ErrNotFound
}
