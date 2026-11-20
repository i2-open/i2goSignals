package mongo

// Key record validity period on the Mongo KeyDAO (i2goSignals#318).

import (
	"context"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (suite *KeyDAOMongoSuite) TestValidity_RoundTripsAndARecordWithoutItStoresNone() {
	ctx := context.Background()
	nb := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	na := nb.AddDate(0, 0, 180)
	rec := &interfaces.JwkKeyRec{Id: bson.NewObjectID().Hex(), KeyName: "kv", Kid: "kv", KeyBytes: []byte{1}, NotBefore: nb, NotAfter: na}
	suite.Require().NoError(suite.dao.Insert(ctx, rec))

	got, err := suite.dao.FindByKid(ctx, "kv")
	suite.Require().NoError(err)
	suite.True(nb.Equal(got.NotBefore), "NotBefore %v reads back as %v", nb, got.NotBefore)
	suite.True(na.Equal(got.NotAfter), "NotAfter %v reads back as %v", na, got.NotAfter)

	open := &interfaces.JwkKeyRec{Id: bson.NewObjectID().Hex(), KeyName: "kv", Kid: "kv-open", KeyBytes: []byte{1}}
	suite.Require().NoError(suite.dao.Insert(ctx, open))
	var raw bson.M
	suite.Require().NoError(suite.collection.FindOne(ctx, bson.M{"kid": "kv-open"}).Decode(&raw))
	suite.NotContains(raw, "not_before", "a record with no validity stores no not_before")
	suite.NotContains(raw, "not_after", "a record with no validity stores no not_after")
	gotOpen, err := suite.dao.FindByKid(ctx, "kv-open")
	suite.Require().NoError(err)
	suite.True(gotOpen.NotBefore.IsZero() && gotOpen.NotAfter.IsZero())
}
