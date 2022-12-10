package goSsefMongoKafka

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/MicahParks/keyfunc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	ssef "i2goSignals/goSSEF/server"
	"log"
)

const dbName = "ssef"
const CStreamtable = "streams"
const CKeyTable = "keys"
const CDeliverypoll = "https://schemas.openid.net/secevent/risc/delivery-method/poll"

// const DELIVERY_PUSH = "https://schemas.openid.net/secevent/risc/delivery-method/push"
const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"

func GetSupportedEvents() []string {
	return []string{
		"urn:ietf:params:event:SCIM:feed:add",
		"urn:ietf:params:event:SCIM:feed:remove",
		"urn:ietf:params:event:SCIM:prov:create",
		"urn:ietf:params:event:SCIM:prov:patch",
		"urn:ietf:params:event:SCIM:prov:put",
		"urn:ietf:params:event:SCIM:prov:delete",
		"urn:ietf:params:event:SCIM:prov:activate",
		"urn:ietf:params:event:SCIM:prov:deactivate",
		"urn:ietf:params:event:SCIM:sig:authMethod",
		"urn:ietf:params:event:SCIM:sig:pwdReset",
		"urn:ietf:params:event:SCIM:misc:asyncResp",
	}
}

type MongoProvider struct {
	name      string
	client    *mongo.Client
	dbInit    bool
	ssefDb    *mongo.Database
	streamCol *mongo.Collection
	keyCol    *mongo.Collection
}

func (m *MongoProvider) Name() string {
	return m.name
}

func (m *MongoProvider) initialize() {
	m.ssefDb = m.client.Database(dbName)

	m.streamCol = m.ssefDb.Collection(CStreamtable)

	m.keyCol = m.ssefDb.Collection(CKeyTable)

	m.createNewJwkKeyPair(CDefIssuer)
}

func (m *MongoProvider) ResetDb() error {
	err := m.ssefDb.Drop(context.TODO())
	if err != nil {
		return err
	}
	m.initialize()
	return nil
}

func (m *MongoProvider) Open(url string) error {
	ctx := context.TODO()

	if len(url) == 0 {
		url = "mongodb://localhost:27017/"
		log.Printf("Defaulting Mongo Database to local: %s", url)
	}
	opts := options.Client().ApplyURI(url)
	client, err := mongo.NewClient(opts)
	if err != nil {
		log.Fatal(err)
		return err
	}

	m.client = client

	// Do a ping test to see that the database is actually there
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		log.Printf("Error connecting to: %s.", url)
		log.Fatal(err)
	}

	dbNames, err := client.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}

	m.dbInit = false
	for _, name := range dbNames {
		if name == dbName {
			m.dbInit = true
		}
	}
	if !m.dbInit {
		m.initialize()
	}

	return nil
}

func (m *MongoProvider) ListStreams() []ssef.StreamConfiguration {
	if !m.dbInit {
		log.Fatal("Mongo DB Provider not initialized while attempting to retrieve Stream Configs")
	}

	cursor, err := m.streamCol.Find(context.TODO(), bson.D{})
	if err != nil {
		log.Printf("Error listing Stream Configs: %v", err)
		return nil
	}
	var results []ssef.StreamConfiguration
	err = cursor.All(context.TODO(), results)
	if err != nil {
		log.Printf("Error parsing Stream Configs: %v", err)
		return nil
	}
	return results
}

func (m *MongoProvider) createNewJwkKeyPair(issuer string) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	err = m.storeJwkKeyPair(issuer, privateKey)
	if err != nil {
		return privateKey
	}

	log.Printf("Error generating key pair: %s", err.Error())
	return nil
}

func (m *MongoProvider) storeJwkKeyPair(issuer string, privateKey *rsa.PrivateKey) error {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKey := privateKey.PublicKey

	givenKey := keyfunc.NewGivenRSA(&publicKey)

	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		issuer: givenKey,
	})

	keyPairRec := JwkKeyRec{
		Id:        primitive.NewObjectID(),
		Iss:       issuer,
		StreamIds: nil,
		KeyBytes:  privKeyBytes,
		PubJwks:   jwks.RawJWKS(),
	}

	_, err := m.keyCol.InsertOne(context.TODO(), keyPairRec)
	return err
}

func (m *MongoProvider) storeReceiverKey(audience string, jwksUri string) error {

	keyPairRec := JwkKeyRec{
		Id:              primitive.NewObjectID(),
		Iss:             audience,
		StreamIds:       nil,
		ReceiverJwksUrl: jwksUri,
	}

	_, err := m.keyCol.InsertOne(context.TODO(), keyPairRec)
	return err
}

func (m *MongoProvider) GetPublicTransmitterJWKS(issuer string) *keyfunc.JWKS {
	filter := bson.D{{"iss", issuer}}

	res := m.keyCol.FindOne(context.TODO(), filter)

	var rec JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		log.Printf("Error parsing JwkKeyRec: %s", err.Error())
	}

	key, err := keyfunc.NewJSON(rec.PubJwks)
	if err != nil {
		log.Printf("Error parsing PubJwks: %s", err.Error())
	}
	return key
}

func (m *MongoProvider) GetTransmitterJWKS(issuer string) (*rsa.PrivateKey, error) {
	filter := bson.D{{"iss", issuer}}

	res := m.keyCol.FindOne(context.TODO(), filter)

	var rec JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		log.Printf("Error parsing JwkKeyRec: %s", err.Error())
	}
	if len(rec.KeyBytes) == 0 {
		return nil, errors.New("No key found for: " + issuer)
	}

	return x509.ParsePKCS1PrivateKey(rec.KeyBytes)
}

func (m *MongoProvider) RegisterStream(request ssef.RegisterParameters) ssef.StreamConfiguration {
	var config ssef.StreamConfiguration
	{
	}
	config.Id = primitive.NewObjectID()
	config.Aud = request.Audience
	config.Iss = "https://i2scim.io/test"
	config.EventsSupported = GetSupportedEvents()
	method := &ssef.OneOfStreamConfigurationDelivery{
		PollDeliveryMethod: ssef.PollDeliveryMethod{Method: CDeliverypoll, EndpointUrl: "/streams/" + config.Id.String()},
	}
	config.Delivery = method

	config.MinVerificationInterval = 15

	// SCIM services will generally use the SCIM ID
	config.Format = CSubjectFmt

	config.IssuerJWKSUrl = "/jwks/" + config.Iss

	// This may need to change.
	return config
}

type JwkKeyRec struct {
	Id              primitive.ObjectID   `json:"id" bson:"_id,$oid"`
	Iss             string               `json:"iss,omitempty" bson:"iss"`
	StreamIds       []primitive.ObjectID `json:"streamIds" bson:"stream_ids"`
	KeyBytes        []byte               `json:"keyBytes" bson:"key_bytes"`
	PubJwks         []byte               `json:"pubJwks" bson:"pub_jwks"`
	ReceiverJwksUrl string               `json:"receiverJwksUrl" bson:"receiver_jwks_url"`
}
