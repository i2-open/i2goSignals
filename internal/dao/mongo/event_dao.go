package mongo

import (
    "context"
    "errors"
    "time"

    interfaces "github.com/i2-open/i2goSignals/pkg/dao"
    "github.com/i2-open/i2goSignals/pkg/logger"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "go.mongodb.org/mongo-driver/v2/bson"
    "go.mongodb.org/mongo-driver/v2/mongo"
    "go.mongodb.org/mongo-driver/v2/mongo/options"
)

var eLog = logger.Sub("EVENT_DAO")

// pendingDoc is the on-disk shape of a DeliverableEvent inside Mongo. It keeps
// `sid` as bson.ObjectID for backward compatibility with existing data; the
// public DAO interface exposes only string IDs and converts at the boundary.
type pendingDoc struct {
    Jti string        `bson:"jti"`
    Sid bson.ObjectID `bson:"sid"`
}

// deliveredDoc is the on-disk shape of a DeliveredEvent.
type deliveredDoc struct {
    pendingDoc `bson:",inline"`
    AckDate    time.Time `bson:"ackDate"`
}

var errEventNotInit = errors.New("mongo collection not initialized")

type EventDAOMongo struct {
    events    collectionRef
    pending   collectionRef
    delivered collectionRef
}

func NewEventDAO(eventCol, pendingCol, deliveredCol *mongo.Collection) interfaces.EventDAO {
    d := &EventDAOMongo{}
    d.events.set(eventCol)
    d.pending.set(pendingCol)
    d.delivered.set(deliveredCol)
    return d
}

// SetCollections rebinds all three collections used by EventDAOMongo. The
// rebind is atomic per-collection; in-flight callers see consistent values
// for the collection they originally loaded.
func (d *EventDAOMongo) SetCollections(eventCol, pendingCol, deliveredCol *mongo.Collection) {
    d.events.set(eventCol)
    d.pending.set(pendingCol)
    d.delivered.set(deliveredCol)
}

func (d *EventDAOMongo) eventColLoad() (*mongo.Collection, error) {
    c := d.events.load()
    if c == nil {
        return nil, errEventNotInit
    }
    return c, nil
}

func (d *EventDAOMongo) pendingColLoad() (*mongo.Collection, error) {
    c := d.pending.load()
    if c == nil {
        return nil, errEventNotInit
    }
    return c, nil
}

func (d *EventDAOMongo) deliveredColLoad() (*mongo.Collection, error) {
    c := d.delivered.load()
    if c == nil {
        return nil, errEventNotInit
    }
    return c, nil
}

func (d *EventDAOMongo) Insert(ctx context.Context, record *model.AgEventRecord) error {
    c, err := d.eventColLoad()
    if err != nil {
        return err
    }
    _, err = c.InsertOne(ctx, record)
    if err != nil {
        // JTI is the persistence-layer dedup key (RFC 8417 §2.2). The
        // sparse-unique eventJtiUnique index installed by createIndexes is
        // the authoritative race breaker; translate Mongo's duplicate-key
        // error to the shared interfaces.ErrDuplicateJTI sentinel so the
        // service layer can fetch the original via FindByJTI and the router
        // can short-circuit. Precedent: cluster_coordinator.go uses the same
        // mongo.IsDuplicateKeyError translation pattern.
        if mongo.IsDuplicateKeyError(err) {
            return interfaces.ErrDuplicateJTI
        }
        eLog.Error("Error inserting event", "error", err)
    }
    return err
}

func (d *EventDAOMongo) FindByJTI(ctx context.Context, jti string) (*model.AgEventRecord, error) {
    c, err := d.eventColLoad()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"jti": jti}
    var res model.AgEventRecord
    cursor := c.FindOne(ctx, filter)
    err = cursor.Decode(&res)
    if err != nil {
        if errors.Is(err, mongo.ErrNoDocuments) {
            return nil, nil
        }
        eLog.Error("Error decoding event record", "error", err)
        return nil, err
    }
    return &res, nil
}

func (d *EventDAOMongo) FindByJTIs(ctx context.Context, jtis []string) ([]*model.AgEventRecord, error) {
    c, err := d.eventColLoad()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"jti": bson.M{"$in": jtis}}
    cursor, err := c.Find(ctx, filter)
    if err != nil {
        eLog.Error("Error finding events", "error", err)
        return nil, err
    }

    var records []*model.AgEventRecord
    err = cursor.All(ctx, &records)
    if err != nil {
        eLog.Error("Error parsing event records", "error", err)
        return nil, err
    }
    return records, nil
}

func (d *EventDAOMongo) FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.AgEventRecord) bool) ([]*model.AgEventRecord, error) {
    c, err := d.eventColLoad()
    if err != nil {
        return nil, err
    }
    var queryFilter bson.D
    if to != nil {
        queryFilter = bson.D{
            bson.E{Key: "sortTime", Value: bson.D{
                bson.E{Key: "$gte", Value: from},
                bson.E{Key: "$lte", Value: to},
            }},
        }
    } else {
        queryFilter = bson.D{
            bson.E{Key: "sortTime", Value: bson.D{bson.E{Key: "$gte", Value: from}}},
        }
    }

    opts := options.Find().SetSort(bson.D{bson.E{Key: "jti", Value: 1}})
    cursor, err := c.Find(ctx, queryFilter, opts)
    if err != nil {
        eLog.Error("Error finding events by time range", "error", err)
        return nil, err
    }

    var allRecords []*model.AgEventRecord
    err = cursor.All(ctx, &allRecords)
    if err != nil {
        eLog.Error("Error parsing events", "error", err)
        return nil, err
    }

    if filter == nil {
        return allRecords, nil
    }

    // Apply custom filter
    var filtered []*model.AgEventRecord
    for _, rec := range allRecords {
        if filter(rec) {
            filtered = append(filtered, rec)
        }
    }
    return filtered, nil
}

func (d *EventDAOMongo) AddPending(ctx context.Context, jti string, streamID string) error {
    c, err := d.pendingColLoad()
    if err != nil {
        return err
    }
    sid, err := ParseObjectID(streamID)
    if err != nil {
        return err
    }
    doc := pendingDoc{Jti: jti, Sid: sid}
    _, err = c.InsertOne(ctx, &doc)
    return err
}

func (d *EventDAOMongo) GetPendingForStream(ctx context.Context, streamID string, limit int32) (jtis []string, total int64, err error) {
    c, err := d.pendingColLoad()
    if err != nil {
        return nil, 0, err
    }
    sid, err := ParseObjectID(streamID)
    if err != nil {
        return nil, 0, err
    }

    filter := bson.M{"sid": sid}

    totalCount, err := c.CountDocuments(ctx, filter, options.Count())
    if err != nil {
        eLog.Error("Error counting pending events", "error", err)
        return nil, 0, err
    }

    if totalCount == 0 {
        return []string{}, 0, nil
    }

    opts := options.Find()
    if limit > 0 {
        opts.SetLimit(int64(limit))
    }

    var docs []pendingDoc
    cursor, err := c.Find(ctx, filter, opts)
    if err != nil {
        eLog.Error("Error getting event batch", "error", err)
        return nil, 0, err
    }

    err = cursor.All(ctx, &docs)
    if err != nil {
        eLog.Error("Error parsing pending events", "error", err)
        return nil, 0, err
    }

    ids := make([]string, len(docs))
    for i, v := range docs {
        ids[i] = v.Jti
    }

    return ids, totalCount, nil
}

func (d *EventDAOMongo) RemovePending(ctx context.Context, jti string, streamID string) (*interfaces.DeliverableEvent, error) {
    c, err := d.pendingColLoad()
    if err != nil {
        return nil, err
    }
    sid, err := ParseObjectID(streamID)
    if err != nil {
        return nil, err
    }

    filter := bson.M{
        "jti": jti,
        "sid": sid,
    }

    res := c.FindOne(ctx, filter)
    if res.Err() != nil {
        if errors.Is(res.Err(), mongo.ErrNoDocuments) {
            return nil, nil
        }
        return nil, res.Err()
    }

    var doc pendingDoc
    err = res.Decode(&doc)
    if err != nil {
        eLog.Error("Error decoding deliverable event", "error", err)
        return nil, err
    }

    _, err = c.DeleteOne(ctx, filter)
    if err != nil {
        eLog.Error("Error deleting pending event", "error", err)
        return nil, err
    }

    return &interfaces.DeliverableEvent{Jti: doc.Jti, StreamId: doc.Sid.Hex()}, nil
}

func (d *EventDAOMongo) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
    c, err := d.pendingColLoad()
    if err != nil {
        return 0, err
    }
    sid, err := ParseObjectID(streamID)
    if err != nil {
        return 0, err
    }

    filter := bson.D{bson.E{Key: "sid", Value: sid}}
    many, err := c.DeleteMany(ctx, filter)
    if err != nil {
        eLog.Error("Error clearing pending events", "error", err)
        return 0, err
    }
    return many.DeletedCount, nil
}

func (d *EventDAOMongo) MarkDelivered(ctx context.Context, event *interfaces.DeliverableEvent, ackDate time.Time) error {
    c, err := d.deliveredColLoad()
    if err != nil {
        return err
    }
    sid, err := ParseObjectID(event.StreamId)
    if err != nil {
        return err
    }
    doc := deliveredDoc{
        pendingDoc: pendingDoc{Jti: event.Jti, Sid: sid},
        AckDate:    ackDate,
    }
    _, err = c.InsertOne(ctx, &doc)
    return err
}

func (d *EventDAOMongo) WatchPending(ctx context.Context, callback func(jti string, streamID string)) error {
    c, err := d.pendingColLoad()
    if err != nil {
        return err
    }
    matchInserts := bson.D{
        bson.E{
            Key: "$match", Value: bson.D{
                bson.E{Key: "operationType", Value: "insert"}},
        },
    }

    opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
    eventStream, err := c.Watch(ctx, mongo.Pipeline{matchInserts}, opts)
    if err != nil {
        eLog.Error("Unable to initialize background event stream", "error", err)
        return err
    }
    defer func(eventStream *mongo.ChangeStream, ctx context.Context) {
        err := eventStream.Close(ctx)
        if err != nil {
            eLog.Error("Error closing background event stream", "error", err)
        }
    }(eventStream, ctx)

    eLog.Info("Background pending event watcher started")

    for eventStream.Next(ctx) {
        var change bson.M
        if err := eventStream.Decode(&change); err != nil {
            eLog.Error("Error decoding change event", "error", err)
            continue
        }

        fullDoc, ok := change["fullDocument"].(bson.M)
        if !ok {
            continue
        }

        jti, _ := fullDoc["jti"].(string)
        sid, _ := fullDoc["sid"].(bson.ObjectID)

        if jti != "" && !sid.IsZero() {
            callback(jti, sid.Hex())
        }
    }

    if err := eventStream.Err(); err != nil {
        eLog.Error("Background event stream stopped with error", "error", err)
        return err
    }

    eLog.Info("Background event stream stopped")
    return nil
}
