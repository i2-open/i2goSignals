package mongo_provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"i2goSignals/internal/authUtil"
	model "i2goSignals/internal/model"
	"i2goSignals/pkg/goSet"
	"log"
	"os"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const CDbName = "ssef"
const CDbStreamCfg = "streams"
const CDbKeys = "keys"
const CDbEvents = "events"
const CDbPending = "pendingEvents"
const CDbDelivered = "deliveredEvents"

const CDeliverypoll = "https://schemas.openid.net/secevent/risc/delivery-method/poll"

// const DELIVERY_PUSH = "https://schemas.openid.net/secevent/risc/delivery-method/push"

const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"

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
	DbUrl         string
	DbName        string
	client        *mongo.Client
	dbInit        bool
	ssefDb        *mongo.Database
	streamCol     *mongo.Collection
	keyCol        *mongo.Collection
	eventCol      *mongo.Collection
	pendingCol    *mongo.Collection
	deliveredCol  *mongo.Collection
	DefaultIssuer string
	TokenIssuer   string
	tokenKey      *rsa.PrivateKey
	tokenPubKey   *keyfunc.JWKS
}

func (m *MongoProvider) Name(token string) string {
	if _, err := m.AuthenticateToken(token); err != nil {
		return m.DbName
	}
	return CDbName
}

func (m *MongoProvider) initialize(dbName string, ctx context.Context) {

	dbNames, err := m.client.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}

	for _, name := range dbNames {
		if name == dbName {
			m.ssefDb = m.client.Database(name)
			log.Println("Connected to Existing SSEF database")
			m.streamCol = m.ssefDb.Collection(CDbStreamCfg)

			m.keyCol = m.ssefDb.Collection(CDbKeys)

			m.deliveredCol = m.ssefDb.Collection(CDbDelivered)
			m.pendingCol = m.ssefDb.Collection(CDbPending)
			m.eventCol = m.ssefDb.Collection(CDbEvents)
			m.dbInit = true
			return
		}
	}

	log.Println("Initializing new database [" + m.DbName + "]")
	m.ssefDb = m.client.Database(m.DbName)

	m.streamCol = m.ssefDb.Collection(CDbStreamCfg)

	m.keyCol = m.ssefDb.Collection(CDbKeys)

	m.deliveredCol = m.ssefDb.Collection(CDbDelivered)
	m.pendingCol = m.ssefDb.Collection(CDbPending)
	m.eventCol = m.ssefDb.Collection(CDbEvents)

	m.tokenKey = m.CreateIssuerJwkKeyPair(m.DefaultIssuer)

	// If tokenIssuer and event issuer are not the same, create the new key pair
	if m.DefaultIssuer != m.TokenIssuer {
		m.tokenKey = m.CreateIssuerJwkKeyPair(m.TokenIssuer)
	}
	m.tokenPubKey = m.GetInternalPublicTransmitterJWKS(m.TokenIssuer)

	indexSid := mongo.IndexModel{
		Keys: bson.D{
			{"sid", 1},
		},
	}

	_, err = m.pendingCol.Indexes().CreateOne(context.TODO(), indexSid)
	if err != nil {
		log.Println(err.Error())
	}
	_, err = m.deliveredCol.Indexes().CreateOne(context.TODO(), indexSid)
	if err != nil {
		log.Println(err.Error())
	}
	m.dbInit = true
}

func (m *MongoProvider) Check() error {
	return m.client.Ping(context.Background(), nil)
}

func (m *MongoProvider) ResetDb(initialize bool) error {
	err := m.ssefDb.Drop(context.TODO())
	m.dbInit = false

	if initialize {
		m.initialize(m.DbName, context.TODO())
	}
	return err
}

/*
Open will open an SSEF database using Mongo and if necessary initialize the SSEF Streams database at the URL and dbName specified. If omitted, the default
dbName is "ssef". If successful a MongoProvider handle is returned otherwise an error
*/
func Open(mongoUrl string) (*MongoProvider, error) {
	ctx := context.Background()

	defaultIssuer, issDefined := os.LookupEnv(CEnvIssuer)
	if !issDefined {
		defaultIssuer = CDefIssuer
	}

	dbName, dbDefined := os.LookupEnv(CEnvDbName)
	if !dbDefined {
		dbName = CDbName
	}

	tknIssuer, tknDefined := os.LookupEnv(CEnvTokenIssuer)
	if !tknDefined {
		tknIssuer = CDefTokenIssuer
	}

	if mongoUrl == "" {
		mongoUrl = "mongodb://localhost:27017/"
		log.Printf("Defaulting Mongo Database to local: %s", mongoUrl)
	}
	opts := options.Client().ApplyURI(mongoUrl)
	client, err := mongo.NewClient(opts)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// Do a ping test to see that the database is actually there
	if err := client.Connect(ctx); err != nil {
		log.Printf("Error connecting to: %s.", mongoUrl)
		log.Fatal(err)
	}

	m := MongoProvider{
		DbName:        dbName,
		DbUrl:         mongoUrl,
		client:        client,
		DefaultIssuer: defaultIssuer,
		TokenIssuer:   tknIssuer,
	}

	m.initialize(dbName, ctx)

	return &m, nil
}

func (m *MongoProvider) Close() error {
	return m.client.Disconnect(context.Background())
}

func (m *MongoProvider) ListStreams() []model.StreamConfiguration {
	if !m.dbInit {
		log.Fatal("Mongo DB Provider not initialized while attempting to retrieve Stream Configs")
	}

	cursor, err := m.streamCol.Find(context.TODO(), bson.D{})
	if err != nil {
		log.Printf("Error listing Stream Configs: %v", err)
		return nil
	}
	var recs []StreamStateRecord
	err = cursor.All(context.TODO(), &recs)
	if err != nil {
		log.Printf("Error parsing Stream Configs: %v", err)
		return nil
	}

	res := make([]model.StreamConfiguration, len(recs))
	for i, v := range recs {
		res[i] = v.StreamConfiguration
	}
	return res
}

func (m *MongoProvider) DeleteStream(streamId string) error {
	docId, _ := primitive.ObjectIDFromHex(streamId)
	filter := bson.M{"_id": docId}

	resp, err := m.streamCol.DeleteOne(context.TODO(), filter)
	if resp.DeletedCount == 1 {
		return nil
	}
	if resp.DeletedCount == 0 {
		return errors.New("not Found")
	}
	return err
}

func (m *MongoProvider) CreateIssuerJwkKeyPair(issuer string) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	err = m.storeJwkKeyPair(issuer, privateKey)
	if err == nil {
		return privateKey
	}

	log.Printf("Error generating key pair: %s", err.Error())
	return nil
}

func (m *MongoProvider) storeJwkKeyPair(issuer string, privateKey *rsa.PrivateKey) error {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKey := privateKey.PublicKey

	pubKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	keyPairRec := JwkKeyRec{
		Id:          primitive.NewObjectID(),
		Iss:         issuer,
		KeyBytes:    privKeyBytes,
		PubKeyBytes: pubKeyBytes,
	}

	_, err := m.keyCol.InsertOne(context.TODO(), &keyPairRec)
	return err
}

func (m *MongoProvider) StoreReceiverKey(streamId string, audience string, jwksUri string) error {

	keyPairRec := JwkKeyRec{
		Id:              primitive.NewObjectID(),
		Aud:             audience,
		StreamId:        streamId,
		ReceiverJwksUrl: jwksUri,
	}

	_, err := m.keyCol.InsertOne(context.TODO(), &keyPairRec)
	return err
}

func (m *MongoProvider) GetReceiverKey(streamId string) *JwkKeyRec {
	filter := bson.D{{"stream_id", streamId}}
	res := m.keyCol.FindOne(context.TODO(), filter)

	var rec JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		log.Println("Error locating receiver key for " + streamId + ": " + err.Error())
		return nil
	}
	return &rec
}

func (m *MongoProvider) GetInternalPublicTransmitterJWKS(issuer string) *keyfunc.JWKS {
	filter := bson.D{{"iss", issuer}}

	res := m.keyCol.FindOne(context.TODO(), filter)

	var rec JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		log.Printf("Error parsing JwkKeyRec: %s", err.Error())
	}

	pubKeyBytes := rec.PubKeyBytes
	pubKey, err := x509.ParsePKCS1PublicKey(pubKeyBytes)

	gkey := keyfunc.NewGivenRSACustomWithOptions(pubKey, keyfunc.GivenKeyOptions{
		Algorithm: "RS256",
	})
	givenKeys := make(map[string]keyfunc.GivenKey)
	givenKeys[issuer] = gkey
	return keyfunc.NewGiven(givenKeys)

}

func (m *MongoProvider) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	filter := bson.D{{"iss", issuer}}

	res := m.keyCol.FindOne(context.TODO(), filter)
	if res.Err() != nil {
		// should be not found
		return nil
	}
	var rec JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		log.Printf("Error parsing JwkKeyRec: %s", err.Error())
	}

	pubKeyBytes := rec.PubKeyBytes
	pubKey, err := x509.ParsePKCS1PublicKey(pubKeyBytes)

	jwkSet := jwkset.NewMemory[any]()

	err = jwkSet.Store.WriteKey(context.Background(), jwkset.NewKey[any](pubKey, issuer))
	if err != nil {
		log.Println("Error creating JWKS for key issuer: " + issuer + ": " + err.Error())
	}
	response, err := jwkSet.JSONPublic(context.Background())
	if err != nil {
		log.Println("Error creating JWKS response: " + err.Error())
	}

	return &response

}

func (m *MongoProvider) GetIssuerJWKS(issuer string) (*rsa.PrivateKey, error) {
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

func (m *MongoProvider) RegisterStream(request model.RegisterParameters) *model.RegisterResponse {
	resp, err := m.RegisterStreamIssuer(request, m.DefaultIssuer)
	if err != nil {
		log.Printf("Error registering stream: " + err.Error())
		return nil
	}
	eventAuthToken, err := m.IssueStreamToken(resp)
	return &model.RegisterResponse{Token: eventAuthToken}
}

func (m *MongoProvider) RegisterStreamIssuer(request model.RegisterParameters, issuer string) (model.StreamConfiguration, error) {
	mid := primitive.NewObjectID()
	var config model.StreamConfiguration
	{
	}
	config.Id = mid.Hex()
	config.Aud = request.Audience
	config.Iss = issuer
	config.EventsSupported = GetSupportedEvents()
	method := &model.OneOfStreamConfigurationDelivery{
		PollDeliveryMethod: &model.PollDeliveryMethod{Method: CDeliverypoll, EndpointUrl: "/streams/" + config.Id},
	}
	config.Delivery = method

	config.MinVerificationInterval = 15
	config.IssuerJWKSUrl = "/jwks/" + issuer

	// SCIM services will generally use the SCIM ID
	config.Format = CSubjectFmt

	config.IssuerJWKSUrl = "/jwks/" + issuer
	now := time.Now()
	streamRec := StreamStateRecord{
		Id:                  mid,
		StreamConfiguration: config,
		StartDate:           now,
		Status:              CState_Active,
		CreatedAt:           now,
	}

	_, err := m.streamCol.InsertOne(context.TODO(), &streamRec)

	// This may need to change.
	return config, err
}

func (m *MongoProvider) UpdateStream(streamId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {

	streamRec, err := m.getStreamState(streamId)
	if err != nil {
		return nil, err
	}

	config := streamRec.StreamConfiguration

	config.EventsRequested = configReq.EventsRequested
	if configReq.Delivery != nil {
		config.Delivery = configReq.Delivery
	}
	if configReq.Format != "" {
		config.Format = configReq.Format
	}

	streamRec.StreamConfiguration = config

	docId, _ := primitive.ObjectIDFromHex(streamId)
	filter := bson.M{"_id": docId}
	res, err := m.streamCol.ReplaceOne(context.TODO(), filter, streamRec)
	if err != nil {
		return nil, errors.New("Stream update error: " + err.Error())
	}
	if res.ModifiedCount == 0 {
		return nil, err
	}
	return &config, nil
}

func (m *MongoProvider) getStreamState(id string) (*StreamStateRecord, error) {
	docId, _ := primitive.ObjectIDFromHex(id)
	filter := bson.M{"_id": docId}

	res := m.streamCol.FindOne(context.TODO(), filter)
	if res.Err() == mongo.ErrNoDocuments {
		return nil, errors.New("not found")
	}
	var rec StreamStateRecord

	err := res.Decode(&rec)
	if err != nil {
		log.Printf("Error parsing StreamStateRecord: %s", err.Error())
		return nil, err
	}
	return &rec, nil
}

func (m *MongoProvider) GetStatus(streamId string, subject string) (*model.StreamStatus, error) {
	state, err := m.getStreamState(streamId)
	if err != nil {
		return nil, err
	}

	status := model.StreamStatus{
		Status: state.Status,
	}
	return &status, nil
}

func (m *MongoProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	rec, err := m.getStreamState(id)
	if err != nil {
		return nil, err
	}
	config := rec.StreamConfiguration
	return &config, nil
}

func (m *MongoProvider) AddEvent(event *goSet.SecurityEventToken, streamIds []string) {
	jti := event.ID

	rec := EventRecord{
		Jti:   jti,
		Event: *event,
	}
	_, err := m.eventCol.InsertOne(context.TODO(), &rec)
	if err != nil {
		log.Println(err.Error())
	}

	for _, id := range streamIds {
		mid, _ := primitive.ObjectIDFromHex(id)
		deliverable := DeliverableEvent{Jti: jti, StreamId: mid}
		m.pendingCol.InsertOne(context.TODO(), &deliverable)
	}
}

func (m *MongoProvider) AckEvent(jtiString string, streamId string) {

	sid, _ := primitive.ObjectIDFromHex(streamId)

	filter := bson.D{
		{"jti", jtiString},
		{"sid", sid}}

	res := m.pendingCol.FindOne(context.TODO(), filter)
	if res.Err() == nil {
		var event DeliverableEvent
		err := res.Decode(&event)
		if err != nil {
			log.Println(err.Error())
			return
		}
		acked := DeliveredEvent{
			DeliverableEvent: event,
			AckDate:          time.Now(),
		}
		m.deliveredCol.InsertOne(context.TODO(), &acked)

		m.pendingCol.DeleteOne(context.TODO(), filter)
	}
}

func (m *MongoProvider) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	sid, _ := primitive.ObjectIDFromHex(streamId)

	filter := bson.D{
		{"sid", sid},
	}

	opts := options.Find()
	if params.MaxEvents > 0 {
		opts.SetLimit(int64(params.MaxEvents))
	}

	totalCount, _ := m.pendingCol.CountDocuments(context.TODO(), filter, options.Count())

	if totalCount == 0 {
		// TODO: check pending
		if params.ReturnImmediately {
			// no events to return at the moment
			return []string{}, false
		}

		// wait for pending changes
		/*
			matchInserts := bson.D{
				{
					"$match", bson.D{
					{"operationType", "insert"},
				},
				},
			}

		*/
		matchInserts := bson.D{
			{
				"$match", bson.D{
					{"operationType", "insert"},
					{"fullDocument.sid", sid}},
			},
		}

		var opts options.ChangeStreamOptions
		if params.TimeoutSecs > 0 {

			wait := time.Duration(float64(time.Second) * float64(params.TimeoutSecs))
			opts.SetMaxAwaitTime(wait)
		}

		eventStream, err := m.pendingCol.Watch(context.TODO(), mongo.Pipeline{matchInserts}, &opts)
		if err != nil {
			log.Println("Error: Unable to initialize event stream: " + err.Error())
		}

		routineCtx := context.WithValue(context.Background(), "streamid", streamId)
		defer eventStream.Close(routineCtx)
		if eventStream.Next(routineCtx) {
			// now that there are events to return, re-poll
			// changeEvent := eventStream.Current
			// log.Printf("ChangeEvent: %v", changeEvent.String())
			return m.GetEventIds(streamId, params)
		} else {
			if routineCtx.Err() != nil {
				log.Printf("Error occurred waiting for events on sid [%v]: %s", streamId, routineCtx.Err().Error())
			}
		}
	}

	var events []DeliverableEvent
	cursor, err := m.pendingCol.Find(context.TODO(), filter, opts)
	if err = cursor.All(context.TODO(), &events); err != nil {
		log.Println("Error getting event batch: " + err.Error())
	}

	ids := make([]string, len(events))
	for i, v := range events {
		ids[i] = v.Jti
	}

	more := false
	if len(ids) < int(totalCount) {
		more = true
	}
	return ids, more
}

func (m *MongoProvider) getEvent(jti string) *goSet.SecurityEventToken {
	filter := bson.D{
		{"jti", jti},
	}
	var res EventRecord
	cursor := m.eventCol.FindOne(context.TODO(), filter)
	err := cursor.Decode(&res)
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	return &res.Event
}

func (m *MongoProvider) GetEvents(jtis []string) *[]goSet.SecurityEventToken {
	res := make([]goSet.SecurityEventToken, len(jtis))
	for i, v := range jtis {
		res[i] = *m.getEvent(v)
	}

	return &res
}

func (m *MongoProvider) IssueStreamToken(record model.StreamConfiguration) (string, error) {
	exp := time.Now().AddDate(0, 0, 90)

	eat := authUtil.EventAuthToken{
		StreamId: record.Id,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{m.TokenIssuer},
			Issuer:    m.TokenIssuer,
			ID:        goSet.GenerateJti(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = m.TokenIssuer
	return token.SignedString(m.tokenKey)
}

func (m *MongoProvider) AuthenticateToken(token string) (string, error) {
	tkn, err := authUtil.ParseAuthToken(token, m.tokenPubKey)
	if err != nil {
		return "", err
	}
	return tkn.StreamId, nil
}

func (m *MongoProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.tokenPubKey
}
