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

// The pre-#359 delivery-reference collections. MigrateLegacyDeliveries carries
// their rows into deliveries and drops them; nothing else names them.
const (
	legacyPendingCollection   = "pendingEvents"
	legacyDeliveredCollection = "deliveredEvents"
)

// migrateBatch bounds one read-and-write round of the migration.
const migrateBatch = 1000

// legacyDoc is the on-disk shape of a pendingEvents / deliveredEvents row:
// {_id, sid, jti} plus ackDate on a delivered row. _id is kept raw because
// only an ObjectID carries a timestamp.
type legacyDoc struct {
	ID      bson.RawValue `bson:"_id"`
	Sid     bson.ObjectID `bson:"sid"`
	Jti     string        `bson:"jti"`
	AckDate time.Time     `bson:"ackDate"`
}

// createdAt is the old document's ObjectID timestamp (one-second resolution),
// or ok=false when _id is not an ObjectID.
func (doc *legacyDoc) createdAt() (time.Time, bool) {
	oid, ok := doc.ID.ObjectIDOK()
	if !ok {
		return time.Time{}, false
	}
	return oid.Timestamp().UTC(), true
}

// legacyNames returns the legacy collection names in the deliveries
// collection's database. Tests that share a database override them.
func (d *EventDAOMongo) legacyNames() (pending, delivered string) {
	pending, delivered = legacyPendingCollection, legacyDeliveredCollection
	if d.legacyPending != "" {
		pending = d.legacyPending
	}
	if d.legacyDelivered != "" {
		delivered = d.legacyDelivered
	}
	return pending, delivered
}

// MigrateLegacyDeliveries carries pendingEvents / deliveredEvents rows into
// deliveries once and drops both old collections (#361, seam S2). Order:
// ensure the deliveries indexes; copy delivered rows (unordered insert,
// duplicate key ignored); copy pending rows as an upsert forcing state pending
// (pending wins, at-least-once); drop both. Every row gets ackJti = jti and
// createdAt from its ObjectID. It is a no-op when neither old collection
// exists, and a rerun after an interruption yields the same documents.
func (d *EventDAOMongo) MigrateLegacyDeliveries(ctx context.Context, expireAt func(streamID string, ackDate time.Time) *time.Time) (interfaces.MigrationResult, error) {
	var res interfaces.MigrationResult
	dc, err := d.deliveriesColLoad()
	if err != nil {
		return res, fmt.Errorf("%w: %v", interfaces.ErrStoreNotReady, err)
	}
	db := dc.Database()
	pendingName, deliveredName := d.legacyNames()
	present, err := legacyPresent(ctx, db, pendingName, deliveredName)
	if err != nil {
		return res, fmt.Errorf("list legacy delivery collections: %w", err)
	}
	if len(present) == 0 {
		res.Dropped = true
		return res, nil
	}
	if _, err = dc.Indexes().CreateMany(ctx, DeliveriesIndexModels()); err != nil {
		return res, fmt.Errorf("ensure deliveries indexes: %w", err)
	}
	now := time.Now().UTC()
	if present[deliveredName] {
		if res.Delivered, err = copyLegacy(ctx, db, deliveredName, pendingName, func(batch []legacyDoc) (int64, error) {
			return insertDelivered(ctx, dc, batch, expireAt, now)
		}); err != nil {
			return res, fmt.Errorf("migrate %s: %w", deliveredName, err)
		}
	}
	if present[pendingName] {
		if res.Pending, err = copyLegacy(ctx, db, pendingName, deliveredName, func(batch []legacyDoc) (int64, error) {
			return upsertPending(ctx, dc, batch, now)
		}); err != nil {
			return res, fmt.Errorf("migrate %s: %w", pendingName, err)
		}
	}
	for _, name := range []string{deliveredName, pendingName} {
		// Drop ignores a namespace that is already gone.
		if err = db.Collection(name).Drop(ctx); err != nil {
			return res, fmt.Errorf("drop %s: %w", name, err)
		}
	}
	res.Dropped = true
	eLog.Info("Migrated legacy delivery references into deliveries", "pending", res.Pending, "delivered", res.Delivered)
	return res, nil
}

// legacyPresent reports which of the named collections exist in db.
func legacyPresent(ctx context.Context, db *mongo.Database, names ...string) (map[string]bool, error) {
	got, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: bson.D{{Key: "$in", Value: names}}}})
	if err != nil {
		return nil, err
	}
	present := make(map[string]bool, len(got))
	for _, n := range got {
		present[n] = true
	}
	return present, nil
}

// copyLegacy streams collection name in batches through write and returns the
// rows written. A read error on a collection that no longer exists on
// re-check is success (another pass dropped it).
func copyLegacy(ctx context.Context, db *mongo.Database, name, other string, write func([]legacyDoc) (int64, error)) (int64, error) {
	var total int64
	readErr := func(err error) (int64, error) {
		if present, lerr := legacyPresent(ctx, db, name, other); lerr == nil && !present[name] {
			return total, nil
		}
		return total, err
	}
	cur, err := db.Collection(name).Find(ctx, bson.D{}, options.Find().SetBatchSize(migrateBatch))
	if err != nil {
		return readErr(err)
	}
	defer func() { _ = cur.Close(ctx) }()
	batch := make([]legacyDoc, 0, migrateBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := write(batch)
		total += n
		batch = batch[:0]
		return err
	}
	for cur.Next(ctx) {
		var doc legacyDoc
		if err = cur.Decode(&doc); err != nil {
			return total, err
		}
		if doc.Jti == "" {
			continue
		}
		batch = append(batch, doc)
		if len(batch) == migrateBatch {
			if err = flush(); err != nil {
				return total, err
			}
		}
	}
	if err = cur.Err(); err != nil {
		return readErr(err)
	}
	return total, flush()
}

// insertDelivered inserts batch as delivered references, ignoring a row that
// already exists (a rerun, or a pending row carried earlier).
func insertDelivered(ctx context.Context, dc *mongo.Collection, batch []legacyDoc, expireAt func(string, time.Time) *time.Time, now time.Time) (int64, error) {
	docs := make([]any, len(batch))
	for i := range batch {
		old := &batch[i]
		created, ok := old.createdAt()
		if !ok {
			created = now
		}
		ackDate := old.AckDate
		doc := &deliveryDoc{Sid: old.Sid, Jti: old.Jti, AckJti: old.Jti, State: interfaces.DeliveryStateDelivered, CreatedAt: created, AckDate: &ackDate}
		if expireAt != nil {
			doc.ExpireAt = expireAt(old.Sid.Hex(), ackDate)
		}
		docs[i] = doc
	}
	_, err := dc.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
	if err == nil {
		return int64(len(docs)), nil
	}
	var bwe mongo.BulkWriteException
	if errors.As(err, &bwe) && bwe.WriteConcernError == nil && allDuplicateKey(bwe.WriteErrors) {
		return int64(len(docs) - len(bwe.WriteErrors)), nil
	}
	return 0, err
}

// upsertPending forces each row of batch to state pending with ackJti = jti,
// removing ackDate / expireAt. createdAt is the ObjectID timestamp; when _id
// is not an ObjectID the migration time is written on insert only, so a rerun
// does not move it.
func upsertPending(ctx context.Context, dc *mongo.Collection, batch []legacyDoc, now time.Time) (int64, error) {
	models := make([]mongo.WriteModel, len(batch))
	for i := range batch {
		old := &batch[i]
		set := bson.D{{Key: "ackJti", Value: old.Jti}, {Key: "state", Value: interfaces.DeliveryStatePending}}
		var onInsert bson.D
		if created, ok := old.createdAt(); ok {
			set = append(set, bson.E{Key: "createdAt", Value: created})
		} else {
			onInsert = bson.D{{Key: "createdAt", Value: now}}
		}
		update := bson.D{
			{Key: "$set", Value: set},
			{Key: "$unset", Value: bson.D{{Key: "ackDate", Value: ""}, {Key: "expireAt", Value: ""}}},
		}
		if onInsert != nil {
			update = append(update, bson.E{Key: "$setOnInsert", Value: onInsert})
		}
		models[i] = mongo.NewUpdateOneModel().
			SetFilter(pendingUpsertFilter(old.Sid, old.Jti)).
			SetUpdate(update).
			SetUpsert(true)
	}
	r, err := dc.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	if err != nil {
		return 0, err
	}
	return r.MatchedCount + r.UpsertedCount, nil
}
