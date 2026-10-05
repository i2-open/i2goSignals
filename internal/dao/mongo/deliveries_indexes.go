package mongo

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Index names on the deliveries collection (#359). Named explicitly so they
// can be asserted on.
const (
	DeliveriesSidJtiIndexName           = "deliveriesSidJti"
	DeliveriesSidAckJtiIndexName        = "deliveriesSidAckJti"
	DeliveriesSidStateJtiIndexName      = "deliveriesSidStateJti"
	DeliveriesExpireAtIndexName         = "deliveriesExpireAt"
	DeliveriesJtiIndexName              = "deliveriesJti"
	DeliveriesPendingCreatedAtIndexName = "deliveriesPendingCreatedAt"
)

// DeliveriesIndexModels are the access-path indexes of the deliveries
// collection:
//
//   - unique {sid, jti} — one reference per (stream, inbound JTI); the ingest
//     duplicate guard the old pendingSidJti index gave, and the AddPending /
//     EnsurePending upsert key.
//   - {sid, ackJti} — the Ack filter {sid, ackJti:{$in}, state:"pending"}.
//   - {sid, state, jti} — the pending read (sorted by jti), its count, and the
//     state-scoped deletes and counts.
//   - {expireAt} with expireAfterSeconds 0 — Mongo's TTL monitor removes a
//     delivered reference once its expireAt passes; rows without expireAt
//     are kept forever.
//   - {jti} — DeleteBodyIfUnreferenced counts references by jti alone.
//   - {sid, createdAt} partial on state pending — the OldestBeyond read.
func DeliveriesIndexModels() []mongo.IndexModel {
	return []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "sid", Value: 1}, {Key: "jti", Value: 1}},
			Options: options.Index().SetName(DeliveriesSidJtiIndexName).SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "sid", Value: 1}, {Key: "ackJti", Value: 1}},
			Options: options.Index().SetName(DeliveriesSidAckJtiIndexName),
		},
		{
			Keys:    bson.D{{Key: "sid", Value: 1}, {Key: "state", Value: 1}, {Key: "jti", Value: 1}},
			Options: options.Index().SetName(DeliveriesSidStateJtiIndexName),
		},
		{
			Keys:    bson.D{{Key: "expireAt", Value: 1}},
			Options: options.Index().SetName(DeliveriesExpireAtIndexName).SetExpireAfterSeconds(0),
		},
		{
			Keys:    bson.D{{Key: "jti", Value: 1}},
			Options: options.Index().SetName(DeliveriesJtiIndexName),
		},
		{
			Keys: bson.D{{Key: "sid", Value: 1}, {Key: "createdAt", Value: 1}},
			Options: options.Index().SetName(DeliveriesPendingCreatedAtIndexName).
				SetPartialFilterExpression(bson.D{{Key: "state", Value: "pending"}}),
		},
	}
}
