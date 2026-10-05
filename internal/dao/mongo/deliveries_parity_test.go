package mongo

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/daotest"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestDeliveriesParity runs the shared deliveries parity suite (#359) against
// the Mongo adapter on both ack/ingest strategies: the one-trip client
// bulkWrite (MongoDB >= 8.0) and the two-write fallback. Each case gets fresh
// collections carrying the production deliveries indexes.
func (s *EventDAOMongoSuite) TestDeliveriesParity() {
	for _, oneTrip := range []bool{true, false} {
		name := "fallback"
		if oneTrip {
			name = "oneTrip"
		}
		s.T().Run(name, func(t *testing.T) {
			daotest.Deliveries(t, func(t *testing.T) interfaces.EventDAO {
				return s.freshDAO(t, oneTrip)
			})
		})
	}
}

// freshDAO returns an EventDAOMongo over a new, indexed pair of collections
// that is dropped when t ends.
func (s *EventDAOMongoSuite) freshDAO(t *testing.T, oneTrip bool) interfaces.EventDAO {
	ctx := context.Background()
	db := s.client.Database("test_event_dao_parity")
	suffix := bson.NewObjectID().Hex()
	ev, dc := db.Collection("events_"+suffix), db.Collection("deliveries_"+suffix)
	_, err := ev.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "jti", Value: 1}},
		Options: options.Index().SetUnique(true).SetSparse(true),
	})
	if err != nil {
		t.Fatalf("events index: %v", err)
	}
	if _, err = ev.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "sortTime", Value: 1}}}); err != nil {
		t.Fatalf("events sortTime index: %v", err)
	}
	if _, err = dc.Indexes().CreateMany(ctx, testDeliveriesIndexes()); err != nil {
		t.Fatalf("deliveries indexes: %v", err)
	}
	t.Cleanup(func() {
		_ = ev.Drop(context.Background())
		_ = dc.Drop(context.Background())
	})
	d := NewEventDAO(ev, dc).(*EventDAOMongo)
	d.SetOneTripIngest(oneTrip)
	return d
}
