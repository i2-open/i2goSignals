package mongo

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// SeedPreUpgradeBody implements daotest.PreUpgradeSeeder (#389): it stores rec
// as a release before ADR 0048 did, with no receivedAt, under an ObjectId
// `_id` whose timestamp is storedAt (the adapter's stored-at fallback).
func (d *EventDAOMongo) SeedPreUpgradeBody(t *testing.T, rec *model.EventRecord, storedAt time.Time) {
	t.Helper()
	raw, err := bson.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal %s: %v", rec.Jti, err)
	}
	var doc bson.M
	if err := bson.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", rec.Jti, err)
	}
	delete(doc, "receivedAt")
	doc["_id"] = objectIDAt(storedAt)
	c, err := d.eventColLoad()
	if err != nil {
		t.Fatalf("events collection: %v", err)
	}
	if _, err := c.InsertOne(context.Background(), doc); err != nil {
		t.Fatalf("seed %s: %v", rec.Jti, err)
	}
}

// objectIDAt is a fresh ObjectId carrying at as its timestamp, unique even
// for bodies sharing one second (NewObjectIDFromTimestamp zeroes the rest).
func objectIDAt(at time.Time) bson.ObjectID {
	id := bson.NewObjectID()
	binary.BigEndian.PutUint32(id[0:4], uint32(at.Unix()))
	return id
}
