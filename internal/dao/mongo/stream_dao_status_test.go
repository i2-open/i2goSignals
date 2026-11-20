package mongo

import (
	"context"
	"testing"
	"time"

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

// TestKeyUnavailablePauseRoundTrip (#312): the key-unavailable pause stores
// paused, the reason and the marker; a repeat pause keeps the first failure's
// time; a whole-record Update carries the marker; every other status write
// removes it from the stored document.
func (suite *StreamDAOMongoStatusSuite) TestKeyUnavailablePauseRoundTrip() {
	ctx := context.Background()
	mid := model.NewRecordId()
	sid := mid.Hex()
	suite.Require().NoError(suite.dao.Create(ctx, &model.StreamStateRecord{
		Id:                  mid,
		StreamConfiguration: model.StreamConfiguration{Id: sid},
		Status:              model.StreamStateEnabled,
	}))
	first := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	suite.Require().NoError(suite.dao.UpdateKeyUnavailablePause(ctx, sid, "POLL-SRV: no key", first))
	got, err := suite.dao.FindByID(ctx, sid)
	suite.Require().NoError(err)
	suite.Equal(model.StreamStatePause, got.Status)
	suite.Equal("POLL-SRV: no key", got.ErrorMsg)
	suite.Require().NotNil(got.KeyUnavailableSince, "the marker must be stored")
	suite.True(got.KeyUnavailableSince.Equal(first))

	suite.Require().NoError(suite.dao.UpdateKeyUnavailablePause(ctx, sid, "POLL-SRV: no key", first.Add(time.Minute)))
	got, err = suite.dao.FindByID(ctx, sid)
	suite.Require().NoError(err)
	suite.True(got.KeyUnavailableSince.Equal(first), "a repeat failure must not move the marker")

	suite.Require().NoError(suite.dao.Update(ctx, got))
	got, err = suite.dao.FindByID(ctx, sid)
	suite.Require().NoError(err)
	suite.NotNil(got.KeyUnavailableSince, "a whole-record update must carry the marker")

	suite.Require().NoError(suite.dao.UpdateStatus(ctx, sid, model.StreamStateEnabled, ""))
	var raw bson.M
	suite.Require().NoError(suite.collection.FindOne(ctx, bson.M{"_id": mid}).Decode(&raw))
	suite.NotContains(raw, "key_unavailable_since", "UpdateStatus must remove the marker")

	suite.Require().NoError(suite.dao.UpdateKeyUnavailablePause(ctx, sid, "POLL-SRV: no key", first))
	suite.Require().NoError(suite.dao.UpdateTransmitterCausedStatus(ctx, sid, model.StreamStatePause, "x"))
	raw = bson.M{}
	suite.Require().NoError(suite.collection.FindOne(ctx, bson.M{"_id": mid}).Decode(&raw))
	suite.NotContains(raw, "key_unavailable_since", "UpdateTransmitterCausedStatus must remove the marker")

	suite.Error(suite.dao.UpdateKeyUnavailablePause(ctx, model.NewRecordId().Hex(), "x", first),
		"an unknown stream is an error")
}

// TestUpdateIfStatus (#318): the conditional whole-record write lands only
// while the stored status is still the expected one, so a background pause
// never overwrites an operator's change made after the stream was read.
func (suite *StreamDAOMongoStatusSuite) TestUpdateIfStatus() {
	ctx := context.Background()
	mid := model.NewRecordId()
	sid := mid.Hex()
	rec := &model.StreamStateRecord{
		Id:                  mid,
		StreamConfiguration: model.StreamConfiguration{Id: sid},
		Status:              model.StreamStateEnabled,
	}
	suite.Require().NoError(suite.dao.Create(ctx, rec))

	paused := rec.DeepCopy()
	paused.SetKeyUnavailablePause("POLL-SRV: expired", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	applied, err := suite.dao.UpdateIfStatus(ctx, paused, model.StreamStateEnabled)
	suite.Require().NoError(err)
	suite.True(applied)
	got, err := suite.dao.FindByID(ctx, sid)
	suite.Require().NoError(err)
	suite.Equal(model.StreamStatePause, got.Status)
	suite.NotNil(got.KeyUnavailableSince)

	suite.Require().NoError(suite.dao.UpdateStatus(ctx, sid, model.StreamStateDisable, "operator"))
	applied, err = suite.dao.UpdateIfStatus(ctx, paused, model.StreamStateEnabled)
	suite.Require().NoError(err)
	suite.False(applied, "a stream no longer enabled is not written")
	got, err = suite.dao.FindByID(ctx, sid)
	suite.Require().NoError(err)
	suite.Equal(model.StreamStateDisable, got.Status)
	suite.Equal("operator", got.ErrorMsg)

	missing := rec.DeepCopy()
	missing.Id = model.NewRecordId()
	missing.StreamConfiguration.Id = missing.Id.Hex()
	_, err = suite.dao.UpdateIfStatus(ctx, missing, model.StreamStateEnabled)
	suite.ErrorIs(err, interfaces.ErrNotFound)
}
