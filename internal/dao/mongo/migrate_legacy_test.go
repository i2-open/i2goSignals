package mongo

import (
	"context"
	"sort"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// migrationFixture is a deliveries collection plus the two legacy collections
// on suffixed names in one test database (#361).
type migrationFixture struct {
	dao                        *EventDAOMongo
	db                         *mongo.Database
	deliveries                 *mongo.Collection
	pending, delivered         *mongo.Collection
	pendingName, deliveredName string
}

func (s *EventDAOMongoSuite) migrationFixture(t *testing.T) *migrationFixture {
	db := s.client.Database("test_event_dao_migrate")
	suffix := bson.NewObjectID().Hex()
	f := &migrationFixture{
		db:            db,
		deliveries:    db.Collection("deliveries_" + suffix),
		pendingName:   "pendingEvents_" + suffix,
		deliveredName: "deliveredEvents_" + suffix,
	}
	f.pending, f.delivered = db.Collection(f.pendingName), db.Collection(f.deliveredName)
	f.dao = NewEventDAO(db.Collection("events_"+suffix), f.deliveries).(*EventDAOMongo)
	f.dao.legacyPending, f.dao.legacyDelivered = f.pendingName, f.deliveredName
	t.Cleanup(func() {
		ctx := context.Background()
		for _, c := range []*mongo.Collection{f.deliveries, f.pending, f.delivered, db.Collection("events_" + suffix)} {
			_ = c.Drop(ctx)
		}
	})
	return f
}

// snapshot returns every deliveries document without _id, sorted by (sid, jti).
func (f *migrationFixture) snapshot(t *testing.T) []deliveryDoc {
	t.Helper()
	cur, err := f.deliveries.Find(context.Background(), bson.D{})
	if err != nil {
		t.Fatalf("find deliveries: %v", err)
	}
	var docs []deliveryDoc
	if err = cur.All(context.Background(), &docs); err != nil {
		t.Fatalf("decode deliveries: %v", err)
	}
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Sid != docs[j].Sid {
			return docs[i].Sid.Hex() < docs[j].Sid.Hex()
		}
		return docs[i].Jti < docs[j].Jti
	})
	return docs
}

func (f *migrationFixture) exists(t *testing.T, name string) bool {
	t.Helper()
	names, err := f.db.ListCollectionNames(context.Background(), bson.D{{Key: "name", Value: name}})
	if err != nil {
		t.Fatalf("list collections: %v", err)
	}
	return len(names) == 1
}

// oidAt is an ObjectID whose timestamp is at (one-second resolution).
func oidAt(at time.Time) bson.ObjectID {
	return bson.NewObjectIDFromTimestamp(at)
}

// seed writes the legacy rows used by the migration tests: two pending, two
// delivered, one JTI in both (on the same stream), and one pending row whose
// _id is not an ObjectID.
func (f *migrationFixture) seed(t *testing.T, sid bson.ObjectID, base time.Time) {
	t.Helper()
	ctx := context.Background()
	_, err := f.pending.InsertMany(ctx, []any{
		bson.D{{Key: "_id", Value: oidAt(base)}, {Key: "jti", Value: "p1"}, {Key: "sid", Value: sid}},
		bson.D{{Key: "_id", Value: oidAt(base.Add(time.Second))}, {Key: "jti", Value: "p2"}, {Key: "sid", Value: sid}},
		bson.D{{Key: "_id", Value: oidAt(base.Add(2 * time.Second))}, {Key: "jti", Value: "both"}, {Key: "sid", Value: sid}},
		bson.D{{Key: "_id", Value: "not-an-oid"}, {Key: "jti", Value: "p-str"}, {Key: "sid", Value: sid}},
	})
	if err != nil {
		t.Fatalf("seed pending: %v", err)
	}
	ack := base.Add(time.Hour).UTC().Truncate(time.Millisecond)
	_, err = f.delivered.InsertMany(ctx, []any{
		bson.D{{Key: "_id", Value: oidAt(base.Add(-time.Minute))}, {Key: "jti", Value: "d1"}, {Key: "sid", Value: sid}, {Key: "ackDate", Value: ack}},
		bson.D{{Key: "_id", Value: oidAt(base.Add(-2 * time.Minute))}, {Key: "jti", Value: "d2"}, {Key: "sid", Value: sid}, {Key: "ackDate", Value: ack}},
		bson.D{{Key: "_id", Value: oidAt(base.Add(-3 * time.Minute))}, {Key: "jti", Value: "both"}, {Key: "sid", Value: sid}, {Key: "ackDate", Value: ack}},
	})
	if err != nil {
		t.Fatalf("seed delivered: %v", err)
	}
}

// TestMigrateLegacyDeliveries checks the migrated documents: ackJti = jti on
// every row, createdAt from the ObjectID (migration time otherwise), ackDate
// and the computed expireAt on delivered rows, pending winning for a JTI in
// both collections, and both old collections dropped.
func (s *EventDAOMongoSuite) TestMigrateLegacyDeliveries() {
	t := s.T()
	ctx := context.Background()
	f := s.migrationFixture(t)
	sid := bson.NewObjectID()
	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	f.seed(t, sid, base)
	ack := base.Add(time.Hour)
	window := 7 * 24 * time.Hour
	var asked []string
	expireAt := func(streamID string, ackDate time.Time) *time.Time {
		asked = append(asked, streamID)
		e := ackDate.Add(window)
		return &e
	}

	before := time.Now().UTC().Add(-time.Second)
	res, err := f.dao.MigrateLegacyDeliveries(ctx, expireAt)
	s.Require().NoError(err)
	s.Equal(interfaces.MigrationResult{Pending: 4, Delivered: 3, Dropped: true}, res)
	s.False(f.exists(t, f.pendingName), "pendingEvents left behind")
	s.False(f.exists(t, f.deliveredName), "deliveredEvents left behind")
	for _, a := range asked {
		s.Equal(sid.Hex(), a)
	}

	docs := f.snapshot(t)
	s.Require().Len(docs, 6)
	byJti := map[string]deliveryDoc{}
	for _, d := range docs {
		s.Equal(sid, d.Sid)
		s.Equal(d.Jti, d.AckJti, "ackJti must equal jti for %s", d.Jti)
		byJti[d.Jti] = d
	}
	for jti, at := range map[string]time.Time{"p1": base, "p2": base.Add(time.Second), "both": base.Add(2 * time.Second)} {
		d := byJti[jti]
		s.Equal(interfaces.DeliveryStatePending, d.State, jti)
		s.True(d.CreatedAt.Equal(at), "%s createdAt %v want %v", jti, d.CreatedAt, at)
		s.Nil(d.AckDate, jti)
		s.Nil(d.ExpireAt, jti)
	}
	str := byJti["p-str"]
	s.Equal(interfaces.DeliveryStatePending, str.State)
	s.False(str.CreatedAt.Before(before), "non-ObjectID row createdAt %v should be the migration time", str.CreatedAt)
	for jti, at := range map[string]time.Time{"d1": base.Add(-time.Minute), "d2": base.Add(-2 * time.Minute)} {
		d := byJti[jti]
		s.Equal(interfaces.DeliveryStateDelivered, d.State, jti)
		s.True(d.CreatedAt.Equal(at), "%s createdAt %v want %v", jti, d.CreatedAt, at)
		s.Require().NotNil(d.AckDate, jti)
		s.True(d.AckDate.Equal(ack), "%s ackDate %v want %v", jti, d.AckDate, ack)
		s.Require().NotNil(d.ExpireAt, jti)
		s.True(d.ExpireAt.Equal(ack.Add(window)), "%s expireAt %v", jti, d.ExpireAt)
	}

	// A pass with nothing left to migrate is a no-op.
	res, err = f.dao.MigrateLegacyDeliveries(ctx, expireAt)
	s.Require().NoError(err)
	s.Equal(interfaces.MigrationResult{Dropped: true}, res)
	s.Equal(docs, f.snapshot(t))
}

// TestMigrateLegacyDeliveries_NilExpireAt keeps delivered rows forever when
// no expireAt function is given.
func (s *EventDAOMongoSuite) TestMigrateLegacyDeliveries_NilExpireAt() {
	t := s.T()
	f := s.migrationFixture(t)
	f.seed(t, bson.NewObjectID(), time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC))
	_, err := f.dao.MigrateLegacyDeliveries(context.Background(), nil)
	s.Require().NoError(err)
	for _, d := range f.snapshot(t) {
		s.Nil(d.ExpireAt, d.Jti)
	}
}

// TestMigrateLegacyDeliveries_RerunAfterInterruption simulates a pass that
// stopped after copying the delivered rows and part of the pending rows
// (before the drop): the rerun yields the same documents as a clean pass.
func (s *EventDAOMongoSuite) TestMigrateLegacyDeliveries_RerunAfterInterruption() {
	t := s.T()
	ctx := context.Background()
	sid := bson.NewObjectID()
	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	expireAt := func(_ string, ackDate time.Time) *time.Time {
		e := ackDate.Add(24 * time.Hour)
		return &e
	}

	clean := s.migrationFixture(t)
	clean.seed(t, sid, base)
	_, err := clean.dao.MigrateLegacyDeliveries(ctx, expireAt)
	s.Require().NoError(err)
	want := clean.snapshot(t)

	f := s.migrationFixture(t)
	f.seed(t, sid, base)
	// The interrupted pass: indexes, every delivered row, the first pending
	// batch of one row; no drop.
	_, err = f.deliveries.Indexes().CreateMany(ctx, DeliveriesIndexModels())
	s.Require().NoError(err)
	var del []legacyDoc
	cur, err := f.delivered.Find(ctx, bson.D{})
	s.Require().NoError(err)
	s.Require().NoError(cur.All(ctx, &del))
	_, err = insertDelivered(ctx, f.deliveries, del, expireAt, time.Now().UTC())
	s.Require().NoError(err)
	var pend []legacyDoc
	cur, err = f.pending.Find(ctx, bson.D{{Key: "jti", Value: "both"}})
	s.Require().NoError(err)
	s.Require().NoError(cur.All(ctx, &pend))
	_, err = upsertPending(ctx, f.deliveries, pend, time.Now().UTC())
	s.Require().NoError(err)

	res, err := f.dao.MigrateLegacyDeliveries(ctx, expireAt)
	s.Require().NoError(err)
	s.True(res.Dropped)
	got := f.snapshot(t)
	s.Require().Len(got, len(want))
	for i := range want {
		w, g := want[i], got[i]
		if w.Jti == "p-str" {
			// createdAt is the migration time for a non-ObjectID _id.
			w.CreatedAt, g.CreatedAt = time.Time{}, time.Time{}
		}
		s.Equal(w, g, "document %s", w.Jti)
	}
	s.False(f.exists(t, f.pendingName))
	s.False(f.exists(t, f.deliveredName))

	// A rerun of the copy over the finished state changes nothing either.
	f.seed(t, sid, base)
	_, err = f.dao.MigrateLegacyDeliveries(ctx, expireAt)
	s.Require().NoError(err)
	s.Equal(got, f.snapshot(t))
}

// TestMigrateLegacyDeliveries_NoLegacyCollections is a no-op that reports
// Dropped and creates nothing.
func (s *EventDAOMongoSuite) TestMigrateLegacyDeliveries_NoLegacyCollections() {
	t := s.T()
	f := s.migrationFixture(t)
	res, err := f.dao.MigrateLegacyDeliveries(context.Background(), nil)
	s.Require().NoError(err)
	s.Equal(interfaces.MigrationResult{Dropped: true}, res)
	s.Empty(f.snapshot(t))
	s.False(f.exists(t, f.pendingName))
	s.False(f.exists(t, f.deliveredName))
}
