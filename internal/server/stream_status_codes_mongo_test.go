package server

import (
	"context"
	"net/http"
	"testing"

	mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// statusCodesMongoUrl is the replica set the docker-compose test stack runs, as
// the Mongo DAO suites use it.
const statusCodesMongoUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

// StreamStatusCodesMongoSuite runs the #305 status-code checks against the Mongo
// stream store. It skips when no Mongo is reachable, like the Mongo DAO suites.
type StreamStatusCodesMongoSuite struct {
	suite.Suite
	client     *mongo.Client
	collection *mongo.Collection
}

func TestStreamStatusCodesMongoSuite(t *testing.T) {
	suite.Run(t, new(StreamStatusCodesMongoSuite))
}

func (suite *StreamStatusCodesMongoSuite) SetupSuite() {
	client, err := mongo.Connect(options.Client().ApplyURI(statusCodesMongoUrl))
	if err != nil {
		suite.T().Skip("Mongo connection error: " + err.Error())
		return
	}
	suite.client = client
	if err = client.Ping(context.Background(), nil); err != nil {
		suite.T().Skip("Mongo ping error: " + err.Error())
		return
	}
	suite.collection = client.Database("test_db").Collection("streams_status_codes")
}

func (suite *StreamStatusCodesMongoSuite) TearDownSuite() {
	if suite.collection != nil {
		_ = suite.collection.Drop(context.Background())
	}
	if suite.client != nil {
		_ = suite.client.Disconnect(context.Background())
	}
}

// TestUnknownSidIs404 (#305): on the Mongo store a SID that is not an ObjectID
// used to fail parsing and answer 500. Every handler answers 404 for it, and for
// a well-formed ObjectID with no document.
func (suite *StreamStatusCodesMongoSuite) TestUnknownSidIs404() {
	app := newStatusRefreshApp(suite.T())
	app.withStreamDAO(mongodao.NewStreamDAO(suite.collection))

	for _, sid := range []string{unknownSid, model.NewRecordId().Hex()} {
		suite.Run(sid, func() {
			assertStreamHandlerCodes(suite.T(), app, sid, http.StatusNotFound)
		})
	}
}
