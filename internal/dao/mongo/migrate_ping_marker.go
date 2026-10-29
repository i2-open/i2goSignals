package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// migrationsCollection holds one done-flag document per one-shot store
// migration, keyed by name.
const migrationsCollection = "migrations"

// pingMarkerMigration is the done-flag key of MigratePingMarkers.
const pingMarkerMigration = "ping-marker"

// migrationsCol returns the done-flag collection, in the deliveries
// collection's database.
func (d *EventDAOMongo) migrationsCol(dc *mongo.Collection) *mongo.Collection {
	name := migrationsCollection
	if d.migrations != "" {
		name = d.migrations
	}
	return dc.Database().Collection(name)
}

// MigratePingMarkers backfills the ping marker on delivery rows written before
// it existed (ADR 0048). Every write path of this build marks its rows, so only
// rows referencing a pre-upgrade body (no receivedAt) can lack the marker: it
// reads those ping bodies in batches (the null receivedAt key of the events
// ping partial index) and, per batch, sets ping: true on every unmarked deliveries
// row whose jti is the batch's reference keys (originalJti, else jti; one
// updateMany on the jti index). It then records the done flag, so a later call
// reads only the flag. An interrupted pass leaves no flag; the rerun marks
// what is left and the same rows end up marked.
func (d *EventDAOMongo) MigratePingMarkers(ctx context.Context) (interfaces.PingMarkerResult, error) {
	var res interfaces.PingMarkerResult
	dc, err := d.deliveriesColLoad()
	if err != nil {
		return res, fmt.Errorf("%w: %v", interfaces.ErrStoreNotReady, err)
	}
	ec, err := d.eventColLoad()
	if err != nil {
		return res, fmt.Errorf("%w: %v", interfaces.ErrStoreNotReady, err)
	}
	mc := d.migrationsCol(dc)
	err = mc.FindOne(ctx, bson.D{{Key: "_id", Value: pingMarkerMigration}}).Err()
	if err == nil {
		res.AlreadyDone = true
		return res, nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return res, fmt.Errorf("read ping marker done flag: %w", err)
	}

	cursor, err := ec.Find(ctx, legacyPingFilter(), options.Find().
		SetProjection(bson.D{{Key: "jti", Value: 1}, {Key: "originalJti", Value: 1}}).
		SetBatchSize(migrateBatch))
	if err != nil {
		return res, fmt.Errorf("read ping bodies: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	keys := make([]string, 0, migrateBatch)
	flush := func() error {
		if len(keys) == 0 {
			return nil
		}
		u, err := dc.UpdateMany(ctx, bson.D{
			{Key: "jti", Value: bson.D{{Key: "$in", Value: keys}}},
			{Key: "ping", Value: bson.D{{Key: "$ne", Value: true}}},
		}, bson.D{{Key: "$set", Value: bson.D{{Key: "ping", Value: true}}}})
		if err != nil {
			return fmt.Errorf("mark ping delivery rows: %w", err)
		}
		res.Marked += u.ModifiedCount
		keys = keys[:0]
		return nil
	}
	for cursor.Next(ctx) {
		var b sweepBody
		if err = cursor.Decode(&b); err != nil {
			return res, err
		}
		keys = append(keys, b.refKey())
		if len(keys) == migrateBatch {
			if err = flush(); err != nil {
				return res, err
			}
		}
	}
	if err = cursor.Err(); err != nil {
		return res, fmt.Errorf("read ping bodies: %w", err)
	}
	if err = flush(); err != nil {
		return res, err
	}
	if _, err = mc.UpdateOne(ctx, bson.D{{Key: "_id", Value: pingMarkerMigration}},
		bson.D{{Key: "$setOnInsert", Value: bson.D{{Key: "doneAt", Value: time.Now().UTC()}}}},
		options.UpdateOne().SetUpsert(true)); err != nil {
		return res, fmt.Errorf("record ping marker done flag: %w", err)
	}
	if res.Marked > 0 {
		eLog.Info("Backfilled the ping marker on delivery rows", "marked", res.Marked)
	}
	return res, nil
}
