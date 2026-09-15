package mongo

// Key record creation time and newest-record selection on the Mongo KeyDAO
// (i2goSignals#316). Records minted by v0.11.0 through v0.12.0-alpha.19 carry
// random ids, so newest is decided by created_at, with _id order only for
// documents that have none.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/golang-jwt/jwt/v5"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	legacyKeyIssuer = "https://tx.example.com"
	legacyRandomHex = "f1c2a9e0d3b4c5a6e7f80912" // sorts above any id minted this century
)

// insertLegacyKeyDoc writes an active signing key document the way a
// pre-upgrade server left it: a random _id and no created_at member. alg is ""
// for RSA or "ES256". It returns the kid.
func (suite *KeyDAOMongoSuite) insertLegacyKeyDoc(id string, alg string) string {
	oid, err := bson.ObjectIDFromHex(id)
	suite.Require().NoError(err)
	var priv, pub []byte
	switch alg {
	case "":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		suite.Require().NoError(err)
		priv, pub = x509.MarshalPKCS1PrivateKey(key), x509.MarshalPKCS1PublicKey(&key.PublicKey)
	case "ES256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		suite.Require().NoError(err)
		priv, err = x509.MarshalECPrivateKey(key)
		suite.Require().NoError(err)
		pub, err = x509.MarshalPKIXPublicKey(key.Public())
		suite.Require().NoError(err)
	default:
		suite.FailNow("unsupported alg " + alg)
	}
	kid := legacyKeyIssuer + "-" + id
	doc := bson.M{"_id": oid, "key_name": legacyKeyIssuer, "kid": kid, "use": "sig", "key_bytes": priv, "pub_jwks": pub}
	if alg != "" {
		doc["alg"] = alg
	}
	_, err = suite.collection.InsertOne(context.Background(), doc)
	suite.Require().NoError(err)
	return kid
}

func (suite *KeyDAOMongoSuite) keyService() *services.KeyService {
	return services.NewKeyService(suite.dao, "DEFAULT", nil, nil)
}

func (suite *KeyDAOMongoSuite) TestCreatedAt_RoundTripsAndALegacyDocumentDecodesZero() {
	ctx := context.Background()
	minted := time.Now().UTC().Truncate(time.Millisecond)
	rec := &interfaces.JwkKeyRec{Id: bson.NewObjectID().Hex(), KeyName: "kn", Kid: "kn", KeyBytes: []byte{1}, CreatedAt: minted}
	suite.Require().NoError(suite.dao.Insert(ctx, rec))

	got, err := suite.dao.FindByKid(ctx, "kn")
	suite.Require().NoError(err)
	suite.True(minted.Equal(got.CreatedAt), "CreatedAt %v reads back as %v", minted, got.CreatedAt)

	legacyKid := suite.insertLegacyKeyDoc(legacyRandomHex, "")
	legacy, err := suite.dao.FindByKid(ctx, legacyKid)
	suite.Require().NoError(err)
	suite.True(legacy.CreatedAt.IsZero(), "a document without created_at decodes with a zero CreatedAt")

	var raw bson.M
	suite.Require().NoError(suite.collection.FindOne(ctx, bson.M{"kid": "kn"}).Decode(&raw))
	suite.Contains(raw, "created_at", "the Mongo document carries created_at")
}

// TestCreatedAt_AnUnstampedRecordStoresNoCreatedAt: a record inserted without a
// CreatedAt is stored with no created_at member, exactly like a legacy
// document, so the created_at sort orders the two by _id as the shared rule
// does. A stored zero date would sort above every legacy document instead.
func (suite *KeyDAOMongoSuite) TestCreatedAt_AnUnstampedRecordStoresNoCreatedAt() {
	ctx := context.Background()
	highest := suite.insertLegacyKeyDoc(legacyRandomHex, "")
	unstamped := &interfaces.JwkKeyRec{Id: "6aa991b90123456789000001", KeyName: legacyKeyIssuer, Kid: "unstamped", KeyBytes: []byte{1}}
	suite.Require().NoError(suite.dao.Insert(ctx, unstamped))

	var raw bson.M
	suite.Require().NoError(suite.collection.FindOne(ctx, bson.M{"kid": "unstamped"}).Decode(&raw))
	suite.NotContains(raw, "created_at")

	got, err := suite.dao.FindLatestByKeyName(ctx, legacyKeyIssuer)
	suite.Require().NoError(err)
	suite.Equal(highest, got.Kid, "between two unstamped records the higher _id is newest")
}

func (suite *KeyDAOMongoSuite) TestCreatedAt_AMintedRecordKeepsItThroughStatusChanges() {
	ctx := context.Background()
	svc := suite.keyService()
	before := time.Now().UTC().Truncate(time.Millisecond)
	_, kid, err := svc.RotateKey(ctx, legacyKeyIssuer, "RS256", "")
	suite.Require().NoError(err)

	rec, err := suite.dao.FindByKid(ctx, kid)
	suite.Require().NoError(err)
	suite.Require().False(rec.CreatedAt.IsZero(), "a minted record carries a creation time")
	suite.False(rec.CreatedAt.Before(before))
	minted := rec.CreatedAt

	for _, status := range []string{interfaces.KeyStatusSuspended, interfaces.KeyStatusActive, interfaces.KeyStatusRevoked} {
		_, _, err := svc.SetKeyStatus(ctx, legacyKeyIssuer, kid, status)
		suite.Require().NoError(err, status)
		after, err := suite.dao.FindByKid(ctx, kid)
		suite.Require().NoError(err)
		suite.Require().Equal(status, after.Status())
		suite.True(minted.Equal(after.CreatedAt), "%s leaves CreatedAt as minted", status)
	}
}

// TestNewKey_OnAStoreWithALegacyRandomIdKeySignsAtOnce: a rotation, create or
// load next to a legacy key of the same algorithm makes the new key the one the
// next SET is signed with.
func (suite *KeyDAOMongoSuite) TestNewKey_OnAStoreWithALegacyRandomIdKeySignsAtOnce() {
	ctx := context.Background()
	newKeys := []struct {
		name string
		alg  string // the stored alg: "" is RSA
		add  func(svc *services.KeyService) string
	}{
		{"rotate RS256", "", func(svc *services.KeyService) string {
			_, kid, err := svc.RotateKey(ctx, legacyKeyIssuer, "RS256", "")
			suite.Require().NoError(err)
			return kid
		}},
		{"rotate ES256", "ES256", func(svc *services.KeyService) string {
			_, kid, err := svc.RotateKey(ctx, legacyKeyIssuer, "ES256", "")
			suite.Require().NoError(err)
			return kid
		}},
		{"create ES256", "ES256", func(svc *services.KeyService) string {
			_, kid, err := svc.CreateKeyPairForAlg(ctx, legacyKeyIssuer, "ES256", "sig", "")
			suite.Require().NoError(err)
			return kid
		}},
		{"load RS256", "", func(svc *services.KeyService) string {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			suite.Require().NoError(err)
			kid := legacyKeyIssuer + "-" + bson.NewObjectID().Hex()
			suite.Require().NoError(svc.AddKey(ctx, legacyKeyIssuer, "sig", kid, key, nil, ""))
			return kid
		}},
	}
	for _, tc := range newKeys {
		suite.Run(tc.name, func() {
			suite.Require().NoError(suite.collection.Drop(ctx))
			svc := suite.keyService()
			legacyKid := suite.insertLegacyKeyDoc(legacyRandomHex, tc.alg)
			_, kid, err := svc.GetSigner(ctx, legacyKeyIssuer, tc.alg)
			suite.Require().NoError(err)
			suite.Require().Equal(legacyKid, kid, "before the change the legacy key signs")

			newKid := tc.add(svc)

			_, kid, err = svc.GetSigner(ctx, legacyKeyIssuer, tc.alg)
			suite.Require().NoError(err)
			suite.Equal(newKid, kid, "the new key signs at once")
		})
	}
}

// TestNewKey_OnTheTokenIssuerWithALegacyRandomIdKeyIssuesUnderTheNewKid: a node
// started after the rotation issues auth tokens under the rotated kid.
func (suite *KeyDAOMongoSuite) TestNewKey_OnTheTokenIssuerWithALegacyRandomIdKeyIssuesUnderTheNewKid() {
	ctx := context.Background()
	oid, err := bson.ObjectIDFromHex(legacyRandomHex)
	suite.Require().NoError(err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err)
	_, err = suite.collection.InsertOne(ctx, bson.M{"_id": oid, "key_name": "DEFAULT", "kid": "DEFAULT", "use": "sig",
		"key_bytes": x509.MarshalPKCS1PrivateKey(key), "pub_jwks": x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	suite.Require().NoError(err)
	svc := suite.keyService()
	suite.Require().NoError(svc.InitializeTokenKey(ctx, "DEFAULT"))

	_, newKid, err := svc.RotateKey(ctx, "DEFAULT", "RS256", "")
	suite.Require().NoError(err)

	restarted := suite.keyService()
	suite.Require().NoError(restarted.InitializeTokenKey(ctx, "DEFAULT"))
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"p"}}
	tok, err := restarted.GetAuthIssuer().IssueStreamClientToken(client, "p", true, "")
	suite.Require().NoError(err)
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	suite.Require().NoError(err)
	suite.Equal(newKid, parsed.Header["kid"], "a token issued after a restart carries the rotated kid")
}

// TestFindLatestByKeyName_OnlyLegacyDocumentsSelectsTheHighestId: a store whose
// documents all predate created_at selects what it selected before.
func (suite *KeyDAOMongoSuite) TestFindLatestByKeyName_OnlyLegacyDocumentsSelectsTheHighestId() {
	ctx := context.Background()
	suite.insertLegacyKeyDoc("3b0f6c1d2e4a5b6c7d8e9f01", "")
	highest := suite.insertLegacyKeyDoc(legacyRandomHex, "")
	suite.insertLegacyKeyDoc("a07e9d8c7b6a5f4e3d2c1b0a", "")

	got, err := suite.dao.FindLatestByKeyName(ctx, legacyKeyIssuer)
	suite.Require().NoError(err)
	suite.Equal(highest, got.Kid)
	_, kid, err := suite.keyService().GetSigner(ctx, legacyKeyIssuer, "RS256")
	suite.Require().NoError(err)
	suite.Equal(highest, kid, "signing selection agrees")
}

// TestFindLatestByKeyName_AgreesWithTheNewestRecordRule: the same scenario the
// services package holds signing selection, rotation use carry-over and JWKS
// kid-collision order to. The legacy document has the highest _id and no
// created_at; the other two were minted in the same millisecond, so the higher
// _id wins even though the lower one's in-memory time is later by the
// nanosecond. Mongo keeps only the millisecond, and the answer must not change.
func (suite *KeyDAOMongoSuite) TestFindLatestByKeyName_AgreesWithTheNewestRecordRule() {
	ctx := context.Background()
	minted := time.Date(2026, 9, 15, 18, 0, 0, 0, time.UTC)
	suite.insertLegacyKeyDoc(legacyRandomHex, "")
	laterByTheNanosecond := &interfaces.JwkKeyRec{Id: "6aa991b90123456789000001", KeyName: legacyKeyIssuer,
		Kid: legacyKeyIssuer + "-a", Use: "sig", KeyBytes: []byte{1}, CreatedAt: minted.Add(900 * time.Microsecond)}
	newest := &interfaces.JwkKeyRec{Id: "6aa991b90123456789000002", KeyName: legacyKeyIssuer,
		Kid: legacyKeyIssuer + "-b", Use: "sig", KeyBytes: []byte{1}, CreatedAt: minted.Add(100 * time.Microsecond)}
	suite.Require().True(newest.NewerThan(laterByTheNanosecond), "the shared rule picks newest before the round trip")
	suite.Require().NoError(suite.dao.Insert(ctx, laterByTheNanosecond))
	suite.Require().NoError(suite.dao.Insert(ctx, newest))

	got, err := suite.dao.FindLatestByKeyName(ctx, legacyKeyIssuer)
	suite.Require().NoError(err)
	suite.Equal(newest.Id, got.Id)

	recs, err := suite.dao.FindByKeyName(ctx, legacyKeyIssuer)
	suite.Require().NoError(err)
	var ruled *interfaces.JwkKeyRec
	for _, rec := range recs {
		if rec.NewerThan(ruled) {
			ruled = rec
		}
	}
	suite.Require().NotNil(ruled)
	suite.Equal(newest.Id, ruled.Id, "the shared rule picks the same record after the round trip")
}
