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

// legacyPingFilter selects the ping bodies stored before receivedAt existed
// (pre-upgrade data). The events ping partial index holds them under a null
// key, so the read is index-backed and empty once they are drained.
func legacyPingFilter() bson.D {
	return bson.D{
		{Key: "types", Value: events.VerificationEventUri},
		{Key: "receivedAt", Value: bson.D{{Key: "$exists", Value: false}}},
	}
}

// legacyPingWindowFilter selects the ping bodies without receivedAt whose
// ObjectId _id time is in [from, to). An ObjectId built from a time sorts
// before every _id of that second, so consecutive windows neither overlap nor
// leave a gap. The planner serves it from the _id index (an _id range) or the
// events ping partial index (the null receivedAt key), whichever it rates
// cheaper; never a collection scan.
func legacyPingWindowFilter(from, to time.Time) bson.D {
	return append(legacyPingFilter(), bson.E{Key: "_id", Value: bson.D{
		{Key: "$gte", Value: bson.NewObjectIDFromTimestamp(from)},
		{Key: "$lt", Value: bson.NewObjectIDFromTimestamp(to)},
	}})
}

// PurgePingWindow deletes delivered ping-marked rows with createdAt < to (one
// deleteMany on the ping partial index), then reads the ping bodies stored in
// [from, to) in batches — by receivedAt, then, while any pre-upgrade ping body
// is left, by its ObjectId _id time — and deletes each one whose reference key
// (originalJti when set, else jti) has no pending deliveries row (ADR 0048,
// ADR 0055 A5.22). Unmarked rows are not matched until MigratePingMarkers
// marks them, and the pre-upgrade pass waits for its done flag: the backfill
// finds a row through its body, so a body purged first would strand the row.
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

	n, err := purgePingBodies(ctx, ec, dc, pingWindowFilter(from, to))
	result.Bodies += n
	if err != nil {
		return result, err
	}
	// The pre-upgrade pass runs only once the marker backfill is done, and
	// only while a body without receivedAt is left (one indexed probe), so a
	// drained store pays nothing for it.
	if err = d.migrationsCol(dc).FindOne(ctx, bson.D{{Key: "_id", Value: pingMarkerMigration}}).Err(); errors.Is(err, mongo.ErrNoDocuments) {
		return result, nil
	} else if err != nil {
		eLog.Warn("Error reading the ping marker done flag for purge", "error", err)
		return result, err
	}
	if err = ec.FindOne(ctx, legacyPingFilter(), options.FindOne().
		SetProjection(bson.D{{Key: "_id", Value: 1}})).Err(); errors.Is(err, mongo.ErrNoDocuments) {
		return result, nil
	} else if err != nil {
		eLog.Warn("Error reading pre-upgrade ping bodies for purge", "error", err)
		return result, err
	}
	n, err = purgePingBodies(ctx, ec, dc, legacyPingWindowFilter(from, to))
	result.Bodies += n
	return result, err
}

// purgePingBodies reads the ping bodies filter selects in batches and deletes
// the unpending ones; it returns the count deleted.
func purgePingBodies(ctx context.Context, ec, dc *mongo.Collection, filter bson.D) (int64, error) {
	var deleted int64
	cursor, err := ec.Find(ctx, filter, options.Find().
		SetProjection(bson.D{{Key: "jti", Value: 1}, {Key: "originalJti", Value: 1}}).
		SetBatchSize(pingPurgeBatch))
	if err != nil {
		eLog.Warn("Error reading ping bodies for purge", "error", err)
		return 0, err
	}
	defer func() { _ = cursor.Close(ctx) }()

	batch := make([]sweepBody, 0, pingPurgeBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := deleteUnpendingBodies(ctx, ec, dc, batch)
		deleted += n
		batch = batch[:0]
		return err
	}
	for cursor.Next(ctx) {
		var b sweepBody
		if err = cursor.Decode(&b); err != nil {
			return deleted, err
		}
		batch = append(batch, b)
		if len(batch) == pingPurgeBatch {
			if err = flush(); err != nil {
				return deleted, err
			}
		}
	}
	if err = cursor.Err(); err != nil {
		eLog.Warn("Error reading ping bodies for purge", "error", err)
		return deleted, err
	}
	return deleted, flush()
}

// deleteUnpendingBodies deletes the bodies of batch that no pending row
// references and returns the count deleted.
func deleteUnpendingBodies(ctx context.Context, ec, dc *mongo.Collection, batch []sweepBody) (int64, error) {
	keys := make([]string, len(batch))
	for i, b := range batch {
		keys[i] = b.refKey()
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
		if _, ok := held[b.refKey()]; !ok {
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

// OldestPingStoredAt returns the oldest stored-at time among ping bodies: the
// smallest receivedAt (one indexed read) or, when earlier, the smallest _id
// time of a pre-upgrade ping body (an indexed read of the null receivedAt key,
// empty once they are drained).
func (d *EventDAOMongo) OldestPingStoredAt(ctx context.Context) (time.Time, bool, error) {
	ec, err := d.eventColLoad()
	if err != nil {
		return time.Time{}, false, err
	}
	var body struct {
		ReceivedAt time.Time `bson:"receivedAt"`
	}
	var oldest time.Time
	found := false
	err = ec.FindOne(ctx, bson.D{
		{Key: "types", Value: events.VerificationEventUri},
		{Key: "receivedAt", Value: bson.D{{Key: "$exists", Value: true}}},
	}, options.FindOne().
		SetSort(bson.D{{Key: "receivedAt", Value: 1}}).
		SetProjection(bson.D{{Key: "receivedAt", Value: 1}})).Decode(&body)
	switch {
	case errors.Is(err, mongo.ErrNoDocuments):
	case err != nil:
		eLog.Warn("Error reading oldest ping body", "error", err)
		return time.Time{}, false, err
	default:
		oldest, found = body.ReceivedAt, true
	}

	var legacy struct {
		ID bson.RawValue `bson:"_id"`
	}
	err = ec.FindOne(ctx, legacyPingFilter(), options.FindOne().
		SetSort(bson.D{{Key: "_id", Value: 1}}).
		SetProjection(bson.D{{Key: "_id", Value: 1}})).Decode(&legacy)
	switch {
	case errors.Is(err, mongo.ErrNoDocuments):
	case err != nil:
		eLog.Warn("Error reading oldest pre-upgrade ping body", "error", err)
		return time.Time{}, false, err
	default:
		if oid, ok := legacy.ID.ObjectIDOK(); ok {
			if at := oid.Timestamp().UTC(); !found || at.Before(oldest) {
				oldest, found = at, true
			}
		}
	}
	return oldest, found, nil
}
