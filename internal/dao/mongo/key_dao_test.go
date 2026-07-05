package mongo

import (
	"context"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
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
		Id:      bson.NewObjectID().Hex(),
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
		Id:      bson.NewObjectID().Hex(),
		KeyName: keyName,
		Kid:     keyName + "-2",
		Use:     "sig",
	}
	key3 := &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID().Hex(),
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

func (suite *KeyDAOMongoSuite) TestSetKeyStatus_ByKidAndClear() {
	ctx := context.Background()
	keyName := "kn"
	k1 := &interfaces.JwkKeyRec{Id: bson.NewObjectID().Hex(), KeyName: keyName, Kid: keyName}
	k2 := &interfaces.JwkKeyRec{Id: bson.NewObjectID().Hex(), KeyName: keyName, Kid: keyName + "-2"}
	suite.NoError(suite.dao.Insert(ctx, k1))
	suite.NoError(suite.dao.Insert(ctx, k2))

	now := time.Now().UTC()
	n, err := suite.dao.SetKeyStatus(ctx, keyName, k2.Kid, &now, nil)
	suite.NoError(err)
	suite.Equal(1, n)

	got1, _ := suite.dao.FindByKid(ctx, k1.Kid)
	got2, _ := suite.dao.FindByKid(ctx, k2.Kid)
	suite.True(got1.IsActive())
	suite.Equal(interfaces.KeyStatusSuspended, got2.Status())

	zero := time.Time{}
	n, err = suite.dao.SetKeyStatus(ctx, keyName, k2.Kid, &zero, nil)
	suite.NoError(err)
	suite.Equal(1, n)
	got2, _ = suite.dao.FindByKid(ctx, k2.Kid)
	suite.True(got2.IsActive())
}

func (suite *KeyDAOMongoSuite) TestSetKeyStatus_RevokeAllWriteOnce() {
	ctx := context.Background()
	keyName := "kn"
	k := &interfaces.JwkKeyRec{Id: bson.NewObjectID().Hex(), KeyName: keyName, Kid: keyName}
	suite.NoError(suite.dao.Insert(ctx, k))

	first := time.Now().UTC().Add(-time.Hour)
	n, err := suite.dao.SetKeyStatus(ctx, keyName, "", nil, &first)
	suite.NoError(err)
	suite.Equal(1, n)

	later := time.Now().UTC()
	_, err = suite.dao.SetKeyStatus(ctx, keyName, "", nil, &later)
	suite.NoError(err)
	got, _ := suite.dao.FindByKid(ctx, k.Kid)
	suite.WithinDuration(first, got.RevokedAt, time.Second, "RevokedAt is write-once")

	_, err = suite.dao.SetKeyStatus(ctx, "missing", "", &later, nil)
	suite.ErrorIs(err, interfaces.ErrKeyNotFound)
}

func (suite *KeyDAOMongoSuite) TestKeySummaryCarriesState() {
	ctx := context.Background()
	keyName := "kn"
	k1 := &interfaces.JwkKeyRec{Id: bson.NewObjectID().Hex(), KeyName: keyName, Kid: keyName}
	k2 := &interfaces.JwkKeyRec{Id: bson.NewObjectID().Hex(), KeyName: keyName, Kid: keyName + "-2"}
	suite.NoError(suite.dao.Insert(ctx, k1))
	suite.NoError(suite.dao.Insert(ctx, k2))
	now := time.Now().UTC()
	_, _ = suite.dao.SetKeyStatus(ctx, keyName, k2.Kid, nil, &now)

	summary, err := suite.dao.KeySummary(ctx, keyName)
	suite.NoError(err)
	suite.Len(summary.KeyStates, 2)
	byKid := map[string]string{}
	for _, st := range summary.KeyStates {
		byKid[st.Kid] = st.Status
	}
	suite.Equal(interfaces.KeyStatusActive, byKid[k1.Kid])
	suite.Equal(interfaces.KeyStatusRevoked, byKid[k2.Kid])
}

func (suite *KeyDAOMongoSuite) TestListSummaries() {
	ctx := context.Background()

	// Add keys for multiple key names
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID().Hex(),
		KeyName: "key-a",
		Kid:     "key-a",
	})
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID().Hex(),
		KeyName: "key-b",
		Kid:     "key-b",
	})
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      bson.NewObjectID().Hex(),
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
