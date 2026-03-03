package mongo

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

type ServerDAOMongoSuite struct {
	suite.Suite
	client     *mongo.Client
	collection *mongo.Collection
	dao        interfaces.ServerDAO
}

func (suite *ServerDAOMongoSuite) SetupSuite() {
	opts := options.Client().ApplyURI(TestDbUrl)
	client, err := mongo.Connect(opts)
	if err != nil {
		suite.T().Skip("Mongo connection error: " + err.Error())
		return
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		suite.T().Skip("Mongo ping error: " + err.Error())
		return
	}

	suite.client = client
	suite.collection = client.Database("test_db").Collection("servers")
	suite.dao = NewServerDAO(suite.collection)
}

func (suite *ServerDAOMongoSuite) TearDownSuite() {
	if suite.client != nil {
		_ = suite.client.Disconnect(context.Background())
	}
}

func (suite *ServerDAOMongoSuite) SetupTest() {
	_ = suite.collection.Drop(context.Background())
}

func TestServerDAOMongoSuite(t *testing.T) {
	suite.Run(t, new(ServerDAOMongoSuite))
}

func (suite *ServerDAOMongoSuite) TestCreateAndFind() {
	ctx := context.Background()
	id := bson.NewObjectID()
	server := &model.Server{
		Id:    id,
		Alias: "test-server",
		Host:  "http://localhost:8080",
	}

	err := suite.dao.Create(ctx, server)
	suite.NoError(err)

	// Find by ID
	found, err := suite.dao.FindByID(ctx, id.Hex())
	suite.NoError(err)
	suite.Equal(server.Alias, found.Alias)
	suite.Equal(server.Host, found.Host)

	// Find by Alias
	found, err = suite.dao.FindByAlias(ctx, "test-server")
	suite.NoError(err)
	suite.Equal(id, found.Id)
}

func (suite *ServerDAOMongoSuite) TestUpdate() {
	ctx := context.Background()
	id := bson.NewObjectID()
	server := &model.Server{
		Id:    id,
		Alias: "test-server",
		Host:  "http://localhost:8080",
	}

	err := suite.dao.Create(ctx, server)
	suite.NoError(err)

	server.Host = "http://localhost:9090"
	err = suite.dao.Update(ctx, server)
	suite.NoError(err)

	found, err := suite.dao.FindByID(ctx, id.Hex())
	suite.NoError(err)
	suite.Equal("http://localhost:9090", found.Host)
}

func (suite *ServerDAOMongoSuite) TestDelete() {
	ctx := context.Background()
	id := bson.NewObjectID()
	server := &model.Server{
		Id:    id,
		Alias: "test-server",
	}

	err := suite.dao.Create(ctx, server)
	suite.NoError(err)

	err = suite.dao.Delete(ctx, id.Hex())
	suite.NoError(err)

	_, err = suite.dao.FindByID(ctx, id.Hex())
	suite.ErrorIs(err, interfaces.ErrNotFound)
}

func (suite *ServerDAOMongoSuite) TestCreateWithoutID() {
	ctx := context.Background()
	server := &model.Server{
		Alias: "test-server-no-id",
	}

	err := suite.dao.Create(ctx, server)
	suite.NoError(err)
	// Note: Mongo driver might not update the struct if it's not handled in DAO
	// but let's see what happens if we use FindByAlias
	found, err := suite.dao.FindByAlias(ctx, "test-server-no-id")
	suite.NoError(err)
	suite.False(found.Id.IsZero())
}

func (suite *ServerDAOMongoSuite) TestList() {
	ctx := context.Background()
	_ = suite.dao.Create(ctx, &model.Server{Id: bson.NewObjectID(), Alias: "s1"})
	_ = suite.dao.Create(ctx, &model.Server{Id: bson.NewObjectID(), Alias: "s2"})

	list, err := suite.dao.List(ctx)
	suite.NoError(err)
	suite.Len(list, 2)
}
