package mongo

import (
	"context"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

func (d *EventDAOMongo) Insert(ctx context.Context, record *model.EventRecord) error {
	_, err := d.eventCol.InsertOne(ctx, record)
	if err != nil {
		eLog.Error("Error inserting event", "error", err)
	}
	return err
}

func (d *EventDAOMongo) FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error) {
	filter := bson.M{"jti": jti}
	var res model.EventRecord
	cursor := d.eventCol.FindOne(ctx, filter)
	err := cursor.Decode(&res)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		eLog.Error("Error decoding event record", "error", err)
		return nil, err
	}
	return &res, nil
}

func (d *EventDAOMongo) FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error) {
	filter := bson.M{"jti": bson.M{"$in": jtis}}
	cursor, err := d.eventCol.Find(ctx, filter)
	if err != nil {
		eLog.Error("Error finding events", "error", err)
		return nil, err
	}

	var records []*model.EventRecord
	err = cursor.All(ctx, &records)
	if err != nil {
		eLog.Error("Error parsing event records", "error", err)
		return nil, err
	}
	return records, nil
}

func (d *EventDAOMongo) FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.EventRecord) bool) ([]*model.EventRecord, error) {
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

	var allRecords []*model.EventRecord
	err = cursor.All(ctx, &allRecords)
	if err != nil {
		eLog.Error("Error parsing events", "error", err)
		return nil, err
	}

	if filter == nil {
		return allRecords, nil
	}

	// Apply custom filter
	var filtered []*model.EventRecord
	for _, rec := range allRecords {
		if filter(rec) {
			filtered = append(filtered, rec)
		}
	}
	return filtered, nil
}

func (d *EventDAOMongo) AddPending(ctx context.Context, jti string, streamID primitive.ObjectID) error {
	deliverable := interfaces.DeliverableEvent{
		Jti:      jti,
		StreamId: streamID,
	}
	_, err := d.pendingCol.InsertOne(ctx, &deliverable)
	return err
}

func (d *EventDAOMongo) GetPendingForStream(ctx context.Context, streamID string, limit int32) (jtis []string, total int64, err error) {
	sid, err := primitive.ObjectIDFromHex(streamID)
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
	sid, err := primitive.ObjectIDFromHex(streamID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"jti": jti,
		"sid": sid,
	}

	res := d.pendingCol.FindOne(ctx, filter)
	if res.Err() != nil {
		if res.Err() == mongo.ErrNoDocuments {
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
	sid, err := primitive.ObjectIDFromHex(streamID)
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
	acked := interfaces.DeliveredEvent{
		DeliverableEvent: *event,
		AckDate:          ackDate,
	}
	_, err := d.deliveredCol.InsertOne(ctx, &acked)
	return err
}

func (d *EventDAOMongo) WatchPending(ctx context.Context, callback func(jti string, streamID primitive.ObjectID)) error {
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
	defer eventStream.Close(ctx)

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
		sid, _ := fullDoc["sid"].(primitive.ObjectID)

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
