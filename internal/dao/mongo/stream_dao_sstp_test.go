package mongo

import (
	"context"
	"errors"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// StreamDAOMongoSstpSuite exercises the SSTP DAO accessors against a live Mongo.
// It skips when no Mongo is reachable, mirroring the other mongo DAO suites.
type StreamDAOMongoSstpSuite struct {
	suite.Suite
	client     *mongo.Client
	collection *mongo.Collection
	dao        interfaces.StreamDAO
}

func (suite *StreamDAOMongoSstpSuite) SetupSuite() {
	opts := options.Client().ApplyURI(TestDbUrl)
	client, err := mongo.Connect(opts)
	if err != nil {
		suite.T().Skip("Mongo connection error: " + err.Error())
		return
	}
	if err = client.Ping(context.Background(), nil); err != nil {
		suite.T().Skip("Mongo ping error: " + err.Error())
		return
	}
	suite.client = client
	suite.collection = client.Database("test_db").Collection("streams_sstp")
	suite.dao = NewStreamDAO(suite.collection)
}

func (suite *StreamDAOMongoSstpSuite) TearDownSuite() {
	if suite.collection != nil {
		_ = suite.collection.Drop(context.Background())
	}
	if suite.client != nil {
		_ = suite.client.Disconnect(context.Background())
	}
}

func (suite *StreamDAOMongoSstpSuite) sstpRecord(txSid, rxSid, pairId string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		Id:     bson.NewObjectID(),
		PairId: pairId,
		StreamConfiguration: model.StreamConfiguration{
			Id:       txSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp}},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:       rxSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp}},
		},
		SstpMethod: &model.SstpMethod{Role: model.SstpRoleResponder, AuthorizationHeader: "Bearer x", PeerPairId: "peer-" + pairId},
		Status:     model.StreamStateEnabled,
	}
}

func (suite *StreamDAOMongoSstpSuite) TestFindByInboundSID() {
	ctx := context.Background()
	rec := suite.sstpRecord("tx-m1", "rx-m1", "pair-m1")
	suite.NoError(suite.dao.Create(ctx, rec))

	got, err := suite.dao.FindByInboundSID(ctx, "rx-m1")
	suite.NoError(err)
	suite.NotNil(got)
	suite.Equal("pair-m1", got.PairId)
	suite.Equal(model.DeliverySstpPair, got.GetType())

	_, err = suite.dao.FindByInboundSID(ctx, "nope")
	suite.True(errors.Is(err, interfaces.ErrNotFound), "expected ErrNotFound, got %v", err)
}

func (suite *StreamDAOMongoSstpSuite) TestFindByPairId() {
	ctx := context.Background()
	rec := suite.sstpRecord("tx-m2", "rx-m2", "pair-m2")
	suite.NoError(suite.dao.Create(ctx, rec))

	got, err := suite.dao.FindByPairId(ctx, "pair-m2")
	suite.NoError(err)
	suite.NotNil(got)
	suite.Equal("tx-m2", got.StreamConfiguration.Id)
	suite.NotNil(got.SstpInbound)
	suite.Equal("rx-m2", got.SstpInbound.Id)

	_, err = suite.dao.FindByPairId(ctx, "missing")
	suite.True(errors.Is(err, interfaces.ErrNotFound), "expected ErrNotFound, got %v", err)
}

func TestStreamDAOMongoSstpSuite(t *testing.T) {
	suite.Run(t, new(StreamDAOMongoSstpSuite))
}
