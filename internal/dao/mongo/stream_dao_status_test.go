package mongo

import (
	"context"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// StreamDAOMongoStatusSuite exercises the status writes against a live Mongo.
// It skips when no Mongo is reachable, mirroring the other mongo DAO suites.
type StreamDAOMongoStatusSuite struct {
	suite.Suite
	client     *mongo.Client
	collection *mongo.Collection
	dao        interfaces.StreamDAO
}

func (suite *StreamDAOMongoStatusSuite) SetupSuite() {
	client, err := mongo.Connect(options.Client().ApplyURI(TestDbUrl))
	if err != nil {
		suite.T().Skip("Mongo connection error: " + err.Error())
		return
	}
	if err = client.Ping(context.Background(), nil); err != nil {
		suite.T().Skip("Mongo ping error: " + err.Error())
		return
	}
	suite.client = client
	suite.collection = client.Database("test_db").Collection("streams_status")
	suite.dao = NewStreamDAO(suite.collection)
}

func (suite *StreamDAOMongoStatusSuite) TearDownSuite() {
	if suite.collection != nil {
		_ = suite.collection.Drop(context.Background())
	}
	if suite.client != nil {
		_ = suite.client.Disconnect(context.Background())
	}
}

func TestStreamDAOMongoStatusSuite(t *testing.T) {
	suite.Run(t, new(StreamDAOMongoStatusSuite))
}

// TestTransmitterCausedRoundTrip (#310): the transmitter-caused write stores the
// flag with the status and reason, a whole-record Update carries it, and an
// ordinary UpdateStatus removes it from the stored document.
func (suite *StreamDAOMongoStatusSuite) TestTransmitterCausedRoundTrip() {
	ctx := context.Background()
	mid := model.NewRecordId()
	sid := mid.Hex()
	suite.Require().NoError(suite.dao.Create(ctx, &model.StreamStateRecord{
		Id:                  mid,
		StreamConfiguration: model.StreamConfiguration{Id: sid},
		Status:              model.StreamStateEnabled,
	}))

	suite.Require().NoError(suite.dao.UpdateTransmitterCausedStatus(ctx, sid, model.StreamStatePause, "Transmitter stream is paused: x"))
	got, err := suite.dao.FindByID(ctx, sid)
	suite.Require().NoError(err)
	suite.Equal(model.StreamStatePause, got.Status)
	suite.Equal("Transmitter stream is paused: x", got.ErrorMsg)
	suite.True(got.TransmitterCaused, "the flag must be stored")

	suite.Require().NoError(suite.dao.Update(ctx, got))
	got, err = suite.dao.FindByID(ctx, sid)
	suite.Require().NoError(err)
	suite.True(got.TransmitterCaused, "a whole-record update must carry the flag")

	suite.Require().NoError(suite.dao.UpdateStatus(ctx, sid, model.StreamStatePause, "operator"))
	got, err = suite.dao.FindByID(ctx, sid)
	suite.Require().NoError(err)
	suite.False(got.TransmitterCaused, "UpdateStatus must clear the flag")

	var raw bson.M
	suite.Require().NoError(suite.collection.FindOne(ctx, bson.M{"_id": mid}).Decode(&raw))
	suite.NotContains(raw, "transmitter_caused", "a cleared flag is omitted from the stored document")

	suite.Error(suite.dao.UpdateTransmitterCausedStatus(ctx, model.NewRecordId().Hex(), model.StreamStateDisable, "x"),
		"an unknown stream is an error")
}
