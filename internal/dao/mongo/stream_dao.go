package mongo

import (
    "context"
    "errors"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    "github.com/i2-open/i2goSignals/pkg/logger"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "go.mongodb.org/mongo-driver/v2/bson"
    "go.mongodb.org/mongo-driver/v2/mongo"
)

var sLog = logger.Sub("STREAM_DAO")

// errStreamNotInit is the canonical "the DAO has no collection bound yet"
// error. Returned during the brief window between provider construction and
// the first successful Mongo connect, and after a disconnect that has not
// yet reconnected.
var errStreamNotInit = errors.New("mongo collection not initialized")

type StreamDAOMongo struct {
    ref collectionRef
}

func NewStreamDAO(collection *mongo.Collection) interfaces.StreamDAO {
    d := &StreamDAOMongo{}
    d.ref.set(collection)
    return d
}

// SetCollection rebinds the underlying *mongo.Collection. Used by
// MongoProvider's reconnect path so DAOs can be reused across connections
// without reconstructing services.
func (d *StreamDAOMongo) SetCollection(c *mongo.Collection) {
    d.ref.set(c)
}

func (d *StreamDAOMongo) col() (*mongo.Collection, error) {
    c := d.ref.load()
    if c == nil {
        return nil, errStreamNotInit
    }
    return c, nil
}

func (d *StreamDAOMongo) Create(ctx context.Context, state *model.StreamStateRecord) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    _, err = c.InsertOne(ctx, state)
    if err != nil {
        sLog.Error("Error inserting stream", "error", err)
    }
    return err
}

func (d *StreamDAOMongo) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    docId, err := ParseObjectID(id)
    if err != nil {
        return nil, err
    }

    filter := bson.M{"_id": docId}
    res := c.FindOne(ctx, filter)

    if err := HandleFindError(res.Err(), errors.New("not found")); err != nil {
        return nil, err
    }

    var rec model.StreamStateRecord
    err = res.Decode(&rec)
    if err != nil {
        sLog.Error("Error parsing StreamStateRecord", "error", err)
        return nil, err
    }
    return &rec, nil
}

func (d *StreamDAOMongo) Update(ctx context.Context, state *model.StreamStateRecord) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    filter := bson.M{"_id": state.Id}
    res, err := c.ReplaceOne(ctx, filter, state)
    if err != nil {
        return errors.New("stream update error: " + err.Error())
    }
    return HandleUpdateResult(res, errors.New("not found"))
}

func (d *StreamDAOMongo) Delete(ctx context.Context, id string) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    docId, err := ParseObjectID(id)
    if err != nil {
        return err
    }

    filter := bson.M{"_id": docId}
    resp, err := c.DeleteOne(ctx, filter)
    if err != nil {
        return err
    }
    return HandleDeleteResult(resp, errors.New("not found"))
}

func (d *StreamDAOMongo) List(ctx context.Context) ([]model.StreamStateRecord, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    cursor, err := c.Find(ctx, bson.D{})
    if err != nil {
        sLog.Error("Error listing Stream Configs", "error", err)
        return nil, err
    }

    var recs []model.StreamStateRecord
    err = cursor.All(ctx, &recs)
    if err != nil {
        sLog.Error("Error parsing Stream Configs", "error", err)
        return nil, err
    }
    return recs, nil
}

func (d *StreamDAOMongo) FindByProjectID(ctx context.Context, projectID string) ([]model.StreamStateRecord, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"project_id": projectID}
    cursor, err := c.Find(ctx, filter)
    if err != nil {
        sLog.Error("Error finding streams by project", "projectID", projectID, "error", err)
        return nil, err
    }

    var recs []model.StreamStateRecord
    err = cursor.All(ctx, &recs)
    if err != nil {
        sLog.Error("Error parsing Stream Configs", "error", err)
        return nil, err
    }
    return recs, nil
}

// FindByInboundSID returns the SSTP pair record whose receive-side SID
// (sstp_inbound.id) equals sid. Backed by the sparse-unique index on
// sstp_inbound.id, so non-SSTP records (which lack the field) pay no cost.
func (d *StreamDAOMongo) FindByInboundSID(ctx context.Context, sid string) (*model.StreamStateRecord, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"sstp_inbound.id": sid}
    res := c.FindOne(ctx, filter)
    if err := HandleFindError(res.Err(), interfaces.ErrNotFound); err != nil {
        return nil, err
    }
    var rec model.StreamStateRecord
    if err := res.Decode(&rec); err != nil {
        sLog.Error("Error parsing StreamStateRecord", "error", err)
        return nil, err
    }
    return &rec, nil
}

// FindByPairId returns the record whose pair_id equals pairId. Backed by the
// sparse-unique index on pair_id.
func (d *StreamDAOMongo) FindByPairId(ctx context.Context, pairId string) (*model.StreamStateRecord, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"pair_id": pairId}
    res := c.FindOne(ctx, filter)
    if err := HandleFindError(res.Err(), interfaces.ErrNotFound); err != nil {
        return nil, err
    }
    var rec model.StreamStateRecord
    if err := res.Decode(&rec); err != nil {
        sLog.Error("Error parsing StreamStateRecord", "error", err)
        return nil, err
    }
    return &rec, nil
}

func (d *StreamDAOMongo) UpdateStatus(ctx context.Context, id string, status string, errorMsg string) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    docId, err := ParseObjectID(id)
    if err != nil {
        return err
    }

    filter := bson.M{"_id": docId}
    update := bson.M{
        "$set": bson.M{
            "status":    status,
            "error_msg": errorMsg,
        },
    }

    res, err := c.UpdateOne(ctx, filter, update)
    if err != nil {
        sLog.Error("Error updating stream status", "error", err)
        return err
    }
    return HandleUpdateResult(res, errors.New("not found"))
}

func (d *StreamDAOMongo) UpdateRemoteAddress(ctx context.Context, id string, addr *model.RemoteIP) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    docId, err := ParseObjectID(id)
    if err != nil {
        return err
    }

    filter := bson.M{"_id": docId}
    update := bson.M{
        "$set": bson.M{
            "remote_address": addr,
        },
    }

    res, err := c.UpdateOne(ctx, filter, update)
    if err != nil {
        sLog.Error("Error updating stream remote address", "error", err)
        return err
    }
    return HandleUpdateResult(res, errors.New("not found"))
}
