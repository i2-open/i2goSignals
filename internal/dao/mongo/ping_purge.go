package mongo

import (
	"context"
	"errors"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// EventsPingReceivedAtIndexName names the events index the ping purge reads
// (ADR 0048).
const EventsPingReceivedAtIndexName = "eventPingReceivedAt"

// pingPurgeBatch bounds one body read-check-delete round of PurgePingWindow.
const pingPurgeBatch = 1000

// EventsPingReceivedAtIndexModel is {receivedAt} partial on
// types = VerificationEventUri: the ping purge's window read and
// OldestPingStoredAt. Data events are not in it.
func EventsPingReceivedAtIndexModel() mongo.IndexModel {
	return mongo.IndexModel{
		Keys: bson.D{{Key: "receivedAt", Value: 1}},
		Options: options.Index().SetName(EventsPingReceivedAtIndexName).
			SetPartialFilterExpression(bson.D{{Key: "types", Value: events.VerificationEventUri}}),
	}
}

// pingWindowFilter selects the ping bodies stored in [from, to).
func pingWindowFilter(from, to time.Time) bson.D {
	return bson.D{
		{Key: "types", Value: events.VerificationEventUri},
		{Key: "receivedAt", Value: bson.D{{Key: "$gte", Value: from}, {Key: "$lt", Value: to}}},
	}
}

// PurgePingWindow deletes delivered ping-marked rows with createdAt < to (one
// deleteMany on the ping partial index), then reads the ping bodies stored in
// [from, to) in batches and deletes each one whose reference key (originalJti
// when set, else jti) has no pending deliveries row (ADR 0048, ADR 0055
// A5.22). Bodies without receivedAt and unmarked rows are not matched.
func (d *EventDAOMongo) PurgePingWindow(ctx context.Context, from, to time.Time) (interfaces.PingPurgeResult, error) {
	var result interfaces.PingPurgeResult
	dc, err := d.deliveriesColLoad()
	if err != nil {
		return result, err
	}
	ec, err := d.eventColLoad()
	if err != nil {
		return result, err
	}

	res, err := dc.DeleteMany(ctx, bson.D{
		{Key: "ping", Value: true},
		{Key: "state", Value: interfaces.DeliveryStateDelivered},
		{Key: "createdAt", Value: bson.D{{Key: "$lt", Value: to}}},
	})
	if err != nil {
		// WARN, not ERROR: the next purge check retries (CONTEXT.md log-level policy).
		eLog.Warn("Error deleting delivered ping references", "error", err)
		return result, err
	}
	result.Deliveries = res.DeletedCount

	cursor, err := ec.Find(ctx, pingWindowFilter(from, to), options.Find().
		SetProjection(bson.D{{Key: "jti", Value: 1}, {Key: "originalJti", Value: 1}}).
		SetBatchSize(pingPurgeBatch))
	if err != nil {
		eLog.Warn("Error reading ping bodies for purge", "error", err)
		return result, err
	}
	defer func() { _ = cursor.Close(ctx) }()

	batch := make([]sweepBody, 0, pingPurgeBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := deleteUnpendingBodies(ctx, ec, dc, batch)
		result.Bodies += n
		batch = batch[:0]
		return err
	}
	for cursor.Next(ctx) {
		var b sweepBody
		if err = cursor.Decode(&b); err != nil {
			return result, err
		}
		batch = append(batch, b)
		if len(batch) == pingPurgeBatch {
			if err = flush(); err != nil {
				return result, err
			}
		}
	}
	if err = cursor.Err(); err != nil {
		eLog.Warn("Error reading ping bodies for purge", "error", err)
		return result, err
	}
	return result, flush()
}

// deleteUnpendingBodies deletes the bodies of batch that no pending row
// references and returns the count deleted.
func deleteUnpendingBodies(ctx context.Context, ec, dc *mongo.Collection, batch []sweepBody) (int64, error) {
	keyOf := func(b sweepBody) string {
		if b.OriginalJti != "" {
			return b.OriginalJti
		}
		return b.Jti
	}
	keys := make([]string, len(batch))
	for i, b := range batch {
		keys[i] = keyOf(b)
	}
	var pending []string
	if err := dc.Distinct(ctx, "jti", bson.D{
		{Key: "jti", Value: bson.D{{Key: "$in", Value: keys}}},
		{Key: "state", Value: interfaces.DeliveryStatePending},
	}).Decode(&pending); err != nil {
		eLog.Warn("Error reading pending references for ping purge", "error", err)
		return 0, err
	}
	held := make(map[string]struct{}, len(pending))
	for _, j := range pending {
		held[j] = struct{}{}
	}
	var doomed []string
	for _, b := range batch {
		if _, ok := held[keyOf(b)]; !ok {
			doomed = append(doomed, b.Jti)
		}
	}
	if len(doomed) == 0 {
		return 0, nil
	}
	// Re-assert the ping type so the delete can never reach a data body.
	del, err := ec.DeleteMany(ctx, bson.D{
		{Key: "jti", Value: bson.D{{Key: "$in", Value: doomed}}},
		{Key: "types", Value: events.VerificationEventUri},
	})
	if err != nil {
		eLog.Warn("Error deleting purged ping bodies", "error", err)
		return 0, err
	}
	return del.DeletedCount, nil
}

// OldestPingStoredAt returns the smallest receivedAt among ping bodies (one
// indexed read).
func (d *EventDAOMongo) OldestPingStoredAt(ctx context.Context) (time.Time, bool, error) {
	ec, err := d.eventColLoad()
	if err != nil {
		return time.Time{}, false, err
	}
	var body struct {
		ReceivedAt time.Time `bson:"receivedAt"`
	}
	err = ec.FindOne(ctx, bson.D{
		{Key: "types", Value: events.VerificationEventUri},
		{Key: "receivedAt", Value: bson.D{{Key: "$exists", Value: true}}},
	}, options.FindOne().
		SetSort(bson.D{{Key: "receivedAt", Value: 1}}).
		SetProjection(bson.D{{Key: "receivedAt", Value: 1}})).Decode(&body)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return time.Time{}, false, nil
	}
	if err != nil {
		eLog.Warn("Error reading oldest ping body", "error", err)
		return time.Time{}, false, err
	}
	return body.ReceivedAt, true, nil
}
