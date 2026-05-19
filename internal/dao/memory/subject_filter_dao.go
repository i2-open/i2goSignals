package memory

import (
    "context"
    "sync"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SubjectFilterDAOMemory is the file-backed in-memory SubjectFilterDAO. Entries
// are keyed by (stream_id, canonical_key); see ADR-0003.
//
// Per ADR-0003 the filter splits by subject kind: simple-subject membership is
// an O(1) indexed Get, and the complex/aliases subset is a small linear scan.
// A secondary nonSimple index records which entries are complex or aliases so
// ListComplex visits only that small subset — never a full-store scan, which
// would make every delivery-time filter decision O(total filter size).
type SubjectFilterDAOMemory struct {
    store *StateManager[string, model.SubjectFilterEntry]

    // nonSimple maps stream_id -> set of canonical keys whose entry is complex
    // or aliases. Guarded by mu; kept in lock-step with store by Add/Remove/
    // ClearForStream.
    mu        sync.Mutex
    nonSimple map[string]map[string]struct{}
}

// NewSubjectFilterDAO constructs an in-memory SubjectFilterDAO.
func NewSubjectFilterDAO() interfaces.SubjectFilterDAO {
    return &SubjectFilterDAOMemory{
        store:     NewStateManager[string, model.SubjectFilterEntry](copySubjectFilterEntry),
        nonSimple: make(map[string]map[string]struct{}),
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

    // Add is an upsert: keep the nonSimple index consistent in both directions
    // so a kind change on re-Add never leaves a stale entry.
    d.mu.Lock()
    if entry.Kind != model.SubjectKindSimple {
        set := d.nonSimple[entry.StreamId]
        if set == nil {
            set = make(map[string]struct{})
            d.nonSimple[entry.StreamId] = set
        }
        set[entry.CanonicalKey] = struct{}{}
    } else if set := d.nonSimple[entry.StreamId]; set != nil {
        delete(set, entry.CanonicalKey)
    }
    d.mu.Unlock()
    return nil
}

func (d *SubjectFilterDAOMemory) Get(_ context.Context, streamID, canonicalKey string) (*model.SubjectFilterEntry, error) {
    if e, ok := d.store.Get(sfKey(streamID, canonicalKey)); ok {
        return e, nil
    }
    return nil, interfaces.ErrNotFound
}

func (d *SubjectFilterDAOMemory) Remove(_ context.Context, streamID, canonicalKey string) error {
    d.store.Delete(sfKey(streamID, canonicalKey))

    d.mu.Lock()
    if set := d.nonSimple[streamID]; set != nil {
        delete(set, canonicalKey)
        if len(set) == 0 {
            delete(d.nonSimple, streamID)
        }
    }
    d.mu.Unlock()
    return nil
}

func (d *SubjectFilterDAOMemory) ClearForStream(_ context.Context, streamID string) error {
    for _, e := range d.store.FindAll(func(e *model.SubjectFilterEntry) bool {
        return e.StreamId == streamID
    }) {
        d.store.Delete(sfKey(e.StreamId, e.CanonicalKey))
    }

    d.mu.Lock()
    delete(d.nonSimple, streamID)
    d.mu.Unlock()
    return nil
}

// ListComplex returns the complex and aliases entries for streamID. It visits
// only the stream's nonSimple index, so the cost is O(non-simple count) for the
// stream — never O(total filter size) — keeping delivery-time filtering O(1)
// for a simple event subject (ADR-0003).
func (d *SubjectFilterDAOMemory) ListComplex(_ context.Context, streamID string) ([]*model.SubjectFilterEntry, error) {
    d.mu.Lock()
    keys := make([]string, 0, len(d.nonSimple[streamID]))
    for k := range d.nonSimple[streamID] {
        keys = append(keys, k)
    }
    d.mu.Unlock()

    results := make([]*model.SubjectFilterEntry, 0, len(keys))
    for _, canonicalKey := range keys {
        if e, ok := d.store.Get(sfKey(streamID, canonicalKey)); ok {
            results = append(results, e)
        }
    }
    return results, nil
}
