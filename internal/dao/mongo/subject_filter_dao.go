package mongo

import (
    "context"
    "errors"
    "time"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    "github.com/i2-open/i2goSignals/pkg/logger"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "go.mongodb.org/mongo-driver/v2/bson"
    "go.mongodb.org/mongo-driver/v2/mongo"
    "go.mongodb.org/mongo-driver/v2/mongo/options"
)

var sfLog = logger.Sub("SUBJECT_FILTER_DAO")

var errSubjectFilterNotInit = errors.New("mongo collection not initialized")

// SubjectFilterDAOMongo is the MongoDB-backed SubjectFilterDAO. Entries live in
// the subject_filters collection, one document per (stream_id, canonical_key);
// a compound index on that pair makes simple-subject membership an indexed
// point lookup rather than a collection scan (ADR-0003).
type SubjectFilterDAOMongo struct {
    ref collectionRef
}

// NewSubjectFilterDAO constructs a MongoDB SubjectFilterDAO over collection and
// ensures the (stream_id, canonical_key) index exists.
func NewSubjectFilterDAO(collection *mongo.Collection) interfaces.SubjectFilterDAO {
    d := &SubjectFilterDAOMongo{}
    d.ref.set(collection)
    d.ensureIndex(collection)
    return d
}

func (d *SubjectFilterDAOMongo) SetCollection(c *mongo.Collection) {
    d.ref.set(c)
    d.ensureIndex(c)
}

// ensureIndex creates the subject_filters indexes. It is idempotent and
// best-effort: a failure is logged, not fatal.
//
//   - (stream_id, canonical_key) unique — simple-subject membership is an
//     indexed point lookup.
//   - (stream_id, kind) — ListComplex selects only the small complex/aliases
//     subset without scanning the stream's (potentially millions of) simple
//     entries (ADR-0003).
//   - (stream_id, enforce_at) PARTIAL on enforce_at $exists — the SSF §9.3
//     pending-removal index (PRD #97 issue #99). Only pending entries carry
//     enforce_at, so the partial index stays tiny even when the full filter
//     holds millions of rows; future admin-review queries enumerate
//     pending removals without scanning the table.
func (d *SubjectFilterDAOMongo) ensureIndex(c *mongo.Collection) {
    if c == nil {
        return
    }
    _, err := c.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
        {
            Keys:    bson.D{{Key: "stream_id", Value: 1}, {Key: "canonical_key", Value: 1}},
            Options: options.Index().SetUnique(true),
        },
        {
            Keys: bson.D{{Key: "stream_id", Value: 1}, {Key: "kind", Value: 1}},
        },
        {
            Keys: bson.D{{Key: "stream_id", Value: 1}, {Key: "enforce_at", Value: 1}},
            Options: options.Index().SetPartialFilterExpression(
                bson.M{"enforce_at": bson.M{"$exists": true}},
            ),
        },
    })
    if err != nil {
        sfLog.Warn("Error creating subject_filters index", "error", err)
    }
}

func (d *SubjectFilterDAOMongo) col() (*mongo.Collection, error) {
    c := d.ref.load()
    if c == nil {
        return nil, errSubjectFilterNotInit
    }
    return c, nil
}

func (d *SubjectFilterDAOMongo) Add(ctx context.Context, entry *model.SubjectFilterEntry) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    filter := bson.M{"stream_id": entry.StreamId, "canonical_key": entry.CanonicalKey}
    _, err = c.ReplaceOne(ctx, filter, entry, options.Replace().SetUpsert(true))
    if err != nil {
        sfLog.Error("Error adding subject filter entry", "sid", entry.StreamId, "error", err)
    }
    return err
}

func (d *SubjectFilterDAOMongo) Get(ctx context.Context, streamID, canonicalKey string) (*model.SubjectFilterEntry, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"stream_id": streamID, "canonical_key": canonicalKey}
    var entry model.SubjectFilterEntry
    err = c.FindOne(ctx, filter).Decode(&entry)
    if err != nil {
        err = HandleFindError(err, interfaces.ErrNotFound)
        if !errors.Is(err, interfaces.ErrNotFound) {
            sfLog.Error("Error finding subject filter entry", "sid", streamID, "error", err)
        }
        return nil, err
    }
    return &entry, nil
}

func (d *SubjectFilterDAOMongo) Remove(ctx context.Context, streamID, canonicalKey string) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    filter := bson.M{"stream_id": streamID, "canonical_key": canonicalKey}
    if _, err = c.DeleteOne(ctx, filter); err != nil {
        sfLog.Error("Error removing subject filter entry", "sid", streamID, "error", err)
        return err
    }
    return nil
}

func (d *SubjectFilterDAOMongo) ClearForStream(ctx context.Context, streamID string) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    if _, err = c.DeleteMany(ctx, bson.M{"stream_id": streamID}); err != nil {
        sfLog.Error("Error clearing subject filter for stream", "sid", streamID, "error", err)
        return err
    }
    return nil
}

// ListPendingDue returns every entry for streamID whose enforce_at is set and
// has elapsed at now (PRD #97 issue #100). The (stream_id, enforce_at)
// sparse partial index already covers only the pending-removal entries, so
// the query stays cheap even when the full filter table holds millions of
// active rows. The boundary is inclusive — enforce_at == now is elapsed,
// matching the slice #99 entryDelivers clock-boundary rule.
func (d *SubjectFilterDAOMongo) ListPendingDue(ctx context.Context, streamID string, now time.Time) ([]*model.SubjectFilterEntry, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{
        "stream_id":  streamID,
        "enforce_at": bson.M{"$lte": now},
    }
    cursor, err := c.Find(ctx, filter)
    if err != nil {
        sfLog.Error("Error listing pending-due subject filter entries", "sid", streamID, "error", err)
        return nil, err
    }
    var entries []*model.SubjectFilterEntry
    if err = cursor.All(ctx, &entries); err != nil {
        sfLog.Error("Error decoding pending-due subject filter entries", "sid", streamID, "error", err)
        return nil, err
    }
    return entries, nil
}

// ListPending returns every entry for streamID currently inside its SSF §9.3
// grace window — enforce_at strictly after now (PRD #97 issue #101). The
// (stream_id, enforce_at) sparse partial index covers only pending entries,
// so the range query stays cheap even when the filter table holds millions of
// active rows. The boundary is exclusive, the complement of ListPendingDue:
// an entry whose enforce_at == now has elapsed and is sweep-eligible, not
// pending.
func (d *SubjectFilterDAOMongo) ListPending(ctx context.Context, streamID string, now time.Time) ([]*model.SubjectFilterEntry, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{
        "stream_id":  streamID,
        "enforce_at": bson.M{"$gt": now},
    }
    cursor, err := c.Find(ctx, filter)
    if err != nil {
        sfLog.Error("Error listing pending subject filter entries", "sid", streamID, "error", err)
        return nil, err
    }
    var entries []*model.SubjectFilterEntry
    if err = cursor.All(ctx, &entries); err != nil {
        sfLog.Error("Error decoding pending subject filter entries", "sid", streamID, "error", err)
        return nil, err
    }
    return entries, nil
}

// Count returns total entries for streamID and the subset currently inside
// their §9.3 grace window (PRD #97 issue #101). Two CountDocuments calls; the
// pending count rides the (stream_id, enforce_at) partial index.
func (d *SubjectFilterDAOMongo) Count(ctx context.Context, streamID string, now time.Time) (int64, int64, error) {
    c, err := d.col()
    if err != nil {
        return 0, 0, err
    }
    total, err := c.CountDocuments(ctx, bson.M{"stream_id": streamID})
    if err != nil {
        sfLog.Error("Error counting subject filter entries", "sid", streamID, "error", err)
        return 0, 0, err
    }
    pending, err := c.CountDocuments(ctx, bson.M{
        "stream_id":  streamID,
        "enforce_at": bson.M{"$gt": now},
    })
    if err != nil {
        sfLog.Error("Error counting pending subject filter entries", "sid", streamID, "error", err)
        return 0, 0, err
    }
    return total, pending, nil
}

// ListComplex returns the complex and aliases entries for streamID. The
// kind: $in predicate rides the (stream_id, kind) index, so it selects only the
// small non-simple subset and never scans the stream's simple entries (ADR-0003).
func (d *SubjectFilterDAOMongo) ListComplex(ctx context.Context, streamID string) ([]*model.SubjectFilterEntry, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"stream_id": streamID, "kind": bson.M{"$in": bson.A{model.SubjectKindComplex, model.SubjectKindAliases}}}
    cursor, err := c.Find(ctx, filter)
    if err != nil {
        sfLog.Error("Error listing complex subject filter entries", "sid", streamID, "error", err)
        return nil, err
    }
    var entries []*model.SubjectFilterEntry
    if err = cursor.All(ctx, &entries); err != nil {
        sfLog.Error("Error decoding complex subject filter entries", "sid", streamID, "error", err)
        return nil, err
    }
    return entries, nil
}
