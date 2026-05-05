package mongo

import (
	"context"
	"errors"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var eLog = logger.Sub("EVENT_DAO")

type EventDAOMongo struct {
	eventCol     *mongo.Collection
	pendingCol   *mongo.Collection
	deliveredCol *mongo.Collection
}

func NewEventDAO(eventCol, pendingCol, deliveredCol *mongo.Collection) interfaces.EventDAO {
	return &EventDAOMongo{
		eventCol:     eventCol,
		pendingCol:   pendingCol,
		deliveredCol: deliveredCol,
	}
}

func (d *EventDAOMongo) Insert(ctx context.Context, record *model.AgEventRecord) error {
	if d.eventCol == nil {
		return errors.New("mongo collection not initialized")
	}
	_, err := d.eventCol.InsertOne(ctx, record)
	if err != nil {
		eLog.Error("Error inserting event", "error", err)
	}
	return err
}

func (d *EventDAOMongo) FindByJTI(ctx context.Context, jti string) (*model.AgEventRecord, error) {
	if d.eventCol == nil {
		return nil, errors.New("mongo collection not initialized")
	}
	filter := bson.M{"jti": jti}
	var res model.AgEventRecord
	cursor := d.eventCol.FindOne(ctx, filter)
	err := cursor.Decode(&res)
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
	if d.eventCol == nil {
		return nil, errors.New("mongo collection not initialized")
	}
	filter := bson.M{"jti": bson.M{"$in": jtis}}
	cursor, err := d.eventCol.Find(ctx, filter)
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
	if d.eventCol == nil {
		return nil, errors.New("mongo collection not initialized")
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
	cursor, err := d.eventCol.Find(ctx, queryFilter, opts)
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

func (d *EventDAOMongo) AddPending(ctx context.Context, jti string, streamID bson.ObjectID) error {
	if d.pendingCol == nil {
		return errors.New("mongo collection not initialized")
	}
	deliverable := interfaces.DeliverableEvent{
		Jti:      jti,
		StreamId: streamID,
	}
	_, err := d.pendingCol.InsertOne(ctx, &deliverable)
	return err
}

func (d *EventDAOMongo) GetPendingForStream(ctx context.Context, streamID string, limit int32) (jtis []string, total int64, err error) {
	if d.pendingCol == nil {
		return nil, 0, errors.New("mongo collection not initialized")
	}
	sid, err := bson.ObjectIDFromHex(streamID)
	if err != nil {
		return nil, 0, err
	}

	filter := bson.M{"sid": sid}

	totalCount, err := d.pendingCol.CountDocuments(ctx, filter, options.Count())
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

	var events []interfaces.DeliverableEvent
	cursor, err := d.pendingCol.Find(ctx, filter, opts)
	if err != nil {
		eLog.Error("Error getting event batch", "error", err)
		return nil, 0, err
	}

	err = cursor.All(ctx, &events)
	if err != nil {
		eLog.Error("Error parsing pending events", "error", err)
		return nil, 0, err
	}

	ids := make([]string, len(events))
	for i, v := range events {
		ids[i] = v.Jti
	}

	return ids, totalCount, nil
}

func (d *EventDAOMongo) RemovePending(ctx context.Context, jti string, streamID string) (*interfaces.DeliverableEvent, error) {
	if d.pendingCol == nil {
		return nil, errors.New("mongo collection not initialized")
	}
	sid, err := bson.ObjectIDFromHex(streamID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"jti": jti,
		"sid": sid,
	}

	res := d.pendingCol.FindOne(ctx, filter)
	if res.Err() != nil {
		if errors.Is(res.Err(), mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, res.Err()
	}

	var event interfaces.DeliverableEvent
	err = res.Decode(&event)
	if err != nil {
		eLog.Error("Error decoding deliverable event", "error", err)
		return nil, err
	}

	_, err = d.pendingCol.DeleteOne(ctx, filter)
	if err != nil {
		eLog.Error("Error deleting pending event", "error", err)
		return nil, err
	}

	return &event, nil
}

func (d *EventDAOMongo) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	if d.pendingCol == nil {
		return 0, errors.New("mongo collection not initialized")
	}
	sid, err := bson.ObjectIDFromHex(streamID)
	if err != nil {
		return 0, err
	}

	filter := bson.D{bson.E{Key: "sid", Value: sid}}
	many, err := d.pendingCol.DeleteMany(ctx, filter)
	if err != nil {
		eLog.Error("Error clearing pending events", "error", err)
		return 0, err
	}
	return many.DeletedCount, nil
}

func (d *EventDAOMongo) MarkDelivered(ctx context.Context, event *interfaces.DeliverableEvent, ackDate time.Time) error {
	if d.deliveredCol == nil {
		return errors.New("mongo collection not initialized")
	}
	acked := interfaces.DeliveredEvent{
		DeliverableEvent: *event,
		AckDate:          ackDate,
	}
	_, err := d.deliveredCol.InsertOne(ctx, &acked)
	return err
}

func (d *EventDAOMongo) WatchPending(ctx context.Context, callback func(jti string, streamID bson.ObjectID)) error {
	if d.pendingCol == nil {
		return errors.New("mongo collection not initialized")
	}
	matchInserts := bson.D{
		bson.E{
			Key: "$match", Value: bson.D{
				bson.E{Key: "operationType", Value: "insert"}},
		},
	}

	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	eventStream, err := d.pendingCol.Watch(ctx, mongo.Pipeline{matchInserts}, opts)
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
			callback(jti, sid)
		}
	}

	if err := eventStream.Err(); err != nil {
		eLog.Error("Background event stream stopped with error", "error", err)
		return err
	}

	eLog.Info("Background event stream stopped")
	return nil
}
