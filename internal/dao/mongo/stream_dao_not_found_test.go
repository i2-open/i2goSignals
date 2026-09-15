package mongo

import (
	"context"
	"errors"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// StreamDAOMongoNotFoundSuite pins #305 against a live Mongo: a stream id that
// names no stream reports interfaces.ErrNotFound, whether it is a well-formed
// ObjectID with no document or a value that is not an ObjectID at all. It skips
// when no Mongo is reachable, mirroring the other mongo DAO suites.
type StreamDAOMongoNotFoundSuite struct {
	suite.Suite
	client     *mongo.Client
	collection *mongo.Collection
	dao        interfaces.StreamDAO
}

func (suite *StreamDAOMongoNotFoundSuite) SetupSuite() {
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
	suite.collection = client.Database("test_db").Collection("streams_not_found")
	suite.dao = NewStreamDAO(suite.collection)
}

func (suite *StreamDAOMongoNotFoundSuite) TearDownSuite() {
	if suite.collection != nil {
		_ = suite.collection.Drop(context.Background())
	}
	if suite.client != nil {
		_ = suite.client.Disconnect(context.Background())
	}
}

func TestStreamDAOMongoNotFoundSuite(t *testing.T) {
	suite.Run(t, new(StreamDAOMongoNotFoundSuite))
}

func (suite *StreamDAOMongoNotFoundSuite) TestUnknownStreamIsErrNotFound() {
	ctx := context.Background()
	for _, sid := range []string{"not-an-object-id", model.NewRecordId().Hex()} {
		suite.Run(sid, func() {
			_, err := suite.dao.FindByID(ctx, sid)
			suite.notFound("FindByID", err)
			suite.notFound("Delete", suite.dao.Delete(ctx, sid))
			suite.notFound("UpdateStatus", suite.dao.UpdateStatus(ctx, sid, model.StreamStatePause, ""))
			suite.notFound("UpdateTransmitterCausedStatus", suite.dao.UpdateTransmitterCausedStatus(ctx, sid, model.StreamStatePause, ""))
			suite.notFound("UpdateKeyUnavailablePause", suite.dao.UpdateKeyUnavailablePause(ctx, sid, "", time.Now()))
			suite.notFound("UpdateRemoteAddress", suite.dao.UpdateRemoteAddress(ctx, sid, &model.RemoteIP{}))
		})
	}

	// Update keys on the record's ObjectID, so only the no-document case applies.
	missing := &model.StreamStateRecord{Id: model.NewRecordId()}
	missing.StreamConfiguration.Id = missing.Id.Hex()
	suite.notFound("Update", suite.dao.Update(ctx, missing))
}

func (suite *StreamDAOMongoNotFoundSuite) notFound(op string, err error) {
	suite.True(errors.Is(err, interfaces.ErrNotFound), "%s on an unknown stream: expected ErrNotFound, got %v", op, err)
}
