package mongo

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type KeyDAOMongoSuite struct {
	suite.Suite
	client     *mongo.Client
	collection *mongo.Collection
	dao        interfaces.KeyDAO
}

func (suite *KeyDAOMongoSuite) SetupSuite() {
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
	suite.collection = client.Database("test_db").Collection("keys")
	suite.dao = NewKeyDAO(suite.collection)
}

func (suite *KeyDAOMongoSuite) TearDownSuite() {
	if suite.client != nil {
		_ = suite.client.Disconnect(context.Background())
	}
}

func (suite *KeyDAOMongoSuite) SetupTest() {
	_ = suite.collection.Drop(context.Background())
}

func TestKeyDAOMongoSuite(t *testing.T) {
	suite.Run(t, new(KeyDAOMongoSuite))
}

func (suite *KeyDAOMongoSuite) TestKeySummaryRotations() {
	ctx := context.Background()
	keyName := "test-key"

	// Case 1: 1 key -> 0 rotations
	key1 := &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID(),
		KeyName: keyName,
		Kid:     keyName,
		Use:     "sig",
	}
	err := suite.dao.Insert(ctx, key1)
	suite.NoError(err)

	summary, err := suite.dao.KeySummary(ctx, keyName)
	suite.NoError(err)
	suite.NotNil(summary)
	suite.Equal(keyName, summary.KeyName)
	suite.Equal(key1.Kid, summary.Kids[0])
	suite.Equal(key1.Use, summary.Use)
	suite.Equal(0, summary.Rotations)

	// Case 2: Add 2 more keys -> 3 keys total -> 2 rotations
	key2 := &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID(),
		KeyName: keyName,
		Kid:     keyName + "-2",
		Use:     "sig",
	}
	key3 := &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID(),
		KeyName: keyName,
		Kid:     keyName + "-3",
		Use:     "sig",
	}
	_ = suite.dao.Insert(ctx, key2)
	_ = suite.dao.Insert(ctx, key3)

	summary, err = suite.dao.KeySummary(ctx, keyName)
	suite.NoError(err)
	suite.NotNil(summary)
	suite.Equal(2, summary.Rotations)
}

func (suite *KeyDAOMongoSuite) TestListSummaries() {
	ctx := context.Background()

	// Add keys for multiple key names
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID(),
		KeyName: "key-a",
		Kid:     "key-a",
	})
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID(),
		KeyName: "key-b",
		Kid:     "key-b",
	})
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID(),
		KeyName: "key-b",
		Kid:     "key-b-2",
	})

	summaries, err := suite.dao.ListSummaries(ctx)
	suite.NoError(err)
	suite.Len(summaries, 2)

	var foundA, foundB bool
	for _, s := range summaries {
		if s.KeyName == "key-a" {
			suite.Equal(0, s.Rotations)
			foundA = true
		} else if s.KeyName == "key-b" {
			suite.Equal(1, s.Rotations)
			foundB = true
		}
	}
	suite.True(foundA)
	suite.True(foundB)
}
