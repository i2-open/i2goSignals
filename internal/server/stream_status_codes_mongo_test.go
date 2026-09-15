package server

import (
	"context"
	"net/http"
	"testing"

	mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// statusCodesMongoUrl is the replica set the docker-compose test stack runs, as
// the Mongo DAO suites use it.
const statusCodesMongoUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

// TestStreamHandlers_UnknownSidIs404OnMongo (#305): on the Mongo store a SID
// that is not an ObjectID used to fail parsing and answer 500. Every handler
// answers 404 for it, and for a well-formed ObjectID with no document. It skips
// when no Mongo is reachable, like the Mongo DAO suites.
func TestStreamHandlers_UnknownSidIs404OnMongo(t *testing.T) {
	ctx := context.Background()
	client, err := mongo.Connect(options.Client().ApplyURI(statusCodesMongoUrl))
	if err != nil {
		t.Skip("Mongo connection error: " + err.Error())
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	if err = client.Ping(ctx, nil); err != nil {
		t.Skip("Mongo ping error: " + err.Error())
	}
	collection := client.Database("test_db").Collection("streams_status_codes")
	t.Cleanup(func() { _ = collection.Drop(context.Background()) })

	app := newStatusRefreshApp(t)
	app.withStreamDAO(mongodao.NewStreamDAO(collection))

	for _, sid := range []string{unknownSid, model.NewRecordId().Hex()} {
		t.Run(sid, func(t *testing.T) {
			assertStreamHandlerCodes(t, app, sid, http.StatusNotFound)
		})
	}
}
