package memory

import (
	"context"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type ServerDAOMemorySuite struct {
	suite.Suite
	dao interfaces.ServerDAO
}

func (suite *ServerDAOMemorySuite) SetupTest() {
	suite.dao = NewServerDAO()
}

func TestServerDAOMemorySuite(t *testing.T) {
	suite.Run(t, new(ServerDAOMemorySuite))
}

func (suite *ServerDAOMemorySuite) TestCreateAndFind() {
	ctx := context.Background()
	id := bson.NewObjectID()
	server := &model.Server{
		Id:    id,
		Alias: "test-server",
		Host:  "http://localhost:8888",
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

func (suite *ServerDAOMemorySuite) TestCreateDuplicateAlias() {
	ctx := context.Background()
	server1 := &model.Server{
		Id:    bson.NewObjectID(),
		Alias: "test-server",
	}
	server2 := &model.Server{
		Id:    bson.NewObjectID(),
		Alias: "test-server",
	}

	err := suite.dao.Create(ctx, server1)
	suite.NoError(err)

	err = suite.dao.Create(ctx, server2)
	suite.Error(err)
	suite.Contains(err.Error(), "already exists")
}

func (suite *ServerDAOMemorySuite) TestUpdate() {
	ctx := context.Background()
	id := bson.NewObjectID()
	server := &model.Server{
		Id:    id,
		Alias: "test-server",
		Host:  "http://localhost:8888",
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

func (suite *ServerDAOMemorySuite) TestDelete() {
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

func (suite *ServerDAOMemorySuite) TestCreateWithoutID() {
	ctx := context.Background()
	server := &model.Server{
		Alias: "test-server-no-id",
	}

	err := suite.dao.Create(ctx, server)
	suite.NoError(err)
	suite.False(server.Id.IsZero())

	found, err := suite.dao.FindByID(ctx, server.Id.Hex())
	suite.NoError(err)
	suite.Equal(server.Alias, found.Alias)
}

func (suite *ServerDAOMemorySuite) TestList() {
	ctx := context.Background()
	_ = suite.dao.Create(ctx, &model.Server{Id: bson.NewObjectID(), Alias: "s1"})
	_ = suite.dao.Create(ctx, &model.Server{Id: bson.NewObjectID(), Alias: "s2"})

	list, err := suite.dao.List(ctx)
	suite.NoError(err)
	suite.Len(list, 2)
}
