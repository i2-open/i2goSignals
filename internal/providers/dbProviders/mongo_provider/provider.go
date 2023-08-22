package mongo_provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/independentid/i2goSignals/internal/model"
	"github.com/independentid/i2goSignals/internal/providers/dbProviders/mongo_provider/watchtokens"
	"github.com/independentid/i2goSignals/pkg/goSSEF/server"
	"github.com/independentid/i2goSignals/pkg/goSet"
	"log"
	"os"
	"regexp"
	"strings"
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

const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"

var pLog = log.New(os.Stdout, "DBMONG: ", log.Ldate|log.Ltime)

func GetSupportedEvents() []string {
	return []string{
		"urn:ietf:params:SCIM:event:feed:add",
		"urn:ietf:params:SCIM:event:feed:remove",
		"urn:ietf:params:SCIM:event:prov:create:full",
		"urn:ietf:params:SCIM:event:prov:patch:full",
		"urn:ietf:params:SCIM:event:prov:put:full",
		"urn:ietf:params:SCIM:event:prov:create:notice",
		"urn:ietf:params:SCIM:event:prov:patch:notice",
		"urn:ietf:params:SCIM:event:prov:put:notice",
		"urn:ietf:params:SCIM:event:prov:delete",
		"urn:ietf:params:SCIM:event:prov:activate",
		"urn:ietf:params:SCIM:event:prov:deactivate",
		"urn:ietf:params:SCIM:event:sig:authMethod",
		"urn:ietf:params:SCIM:event:sig:pwdReset",
		"urn:ietf:params:SCIM:event:misc:asyncResp",
	}
}

type MongoProvider struct {
	DbUrl  string
	DbName string
	client *mongo.Client

	// dbInit is a flag confirming a valid SSEF database is connected and initialized
	dbInit bool
	ssefDb *mongo.Database

	// streamCol holds StreamStateRecords which contain model.StreamConfiguration
	streamCol       *mongo.Collection
	keyCol          *mongo.Collection
	eventCol        *mongo.Collection
	pendingCol      *mongo.Collection
	deliveredCol    *mongo.Collection
	receivedEvents  *mongo.Collection
	DefaultIssuer   string
	TokenIssuer     string
	tokenKey        *rsa.PrivateKey
	tokenPubKey     *keyfunc.JWKS
	resumeTokens    *watchtokens.TokenData
	receiverStreams map[string]*model.StreamStateRecord
}

func (m *MongoProvider) Name() string {
	return m.DbName
}

func (m *MongoProvider) GetEventCol() *mongo.Collection {
	return m.eventCol
}

func (m *MongoProvider) GetResumeTokens() *watchtokens.TokenData {
	return m.resumeTokens
}

func (m *MongoProvider) initialize(dbName string, ctx context.Context) {

	dbNames, err := m.client.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		pLog.Fatal(err)
	}

	for _, name := range dbNames {
		if name == dbName {
			m.ssefDb = m.client.Database(name)
			pLog.Println(fmt.Sprintf("Connected to existing database [%s] ", name))
			m.streamCol = m.ssefDb.Collection(CDbStreamCfg)

			m.keyCol = m.ssefDb.Collection(CDbKeys)

			m.deliveredCol = m.ssefDb.Collection(CDbDelivered)
			m.pendingCol = m.ssefDb.Collection(CDbPending)
			m.eventCol = m.ssefDb.Collection(CDbEvents)
			m.dbInit = true

			m.tokenKey, _ = m.GetIssuerPrivateKey(m.TokenIssuer)
			m.tokenPubKey = m.GetInternalPublicTransmitterJWKS(m.TokenIssuer)
			return
		}
	}

	pLog.Println("Initializing new database [" + m.DbName + "]")
	m.resumeTokens.Reset()

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
		pLog.Println(err.Error())
	}
	_, err = m.deliveredCol.Indexes().CreateOne(context.TODO(), indexSid)
	if err != nil {
		pLog.Println(err.Error())
	}
	m.dbInit = true
}

func (m *MongoProvider) Check() error {
	return m.client.Ping(context.Background(), nil)
}

func (m *MongoProvider) ResetDb(initialize bool) error {
	err := m.ssefDb.Drop(context.TODO())
	if err != nil {
		pLog.Fatalln("Error resetting database: " + err.Error())
	}
	m.dbInit = false

	if initialize {
		_ = m.ssefDb.Drop(context.TODO())
		m.pendingCol = nil
		m.ssefDb = nil
		m.eventCol = nil
		m.streamCol = nil
		m.keyCol = nil
		m.deliveredCol = nil
		m.resumeTokens.Reset()
		m.initialize(m.DbName, context.TODO())
	}

	return err
}

/*
Open will open an SSEF database using Mongo and if necessary initialize the SSEF Streams database at the URL and dbName specified. If omitted, the default
dbName is "ssef". If successful a MongoProvider handle is returned otherwise an error. If dbName is specified this will override environmental variables
*/
func Open(mongoUrl string, dbName string) (*MongoProvider, error) {
	ctx := context.Background()

	defaultIssuer, issDefined := os.LookupEnv(CEnvIssuer)
	if !issDefined {
		defaultIssuer = CDefIssuer
	}

	if dbName == "" {
		dbEnvName, dbDefined := os.LookupEnv(CEnvDbName)
		if !dbDefined {
			dbName = CDbName
		} else {
			dbName = dbEnvName
		}
	}

	tknIssuer, tknDefined := os.LookupEnv(CEnvTokenIssuer)
	if !tknDefined {
		tknIssuer = CDefTokenIssuer
	}

	if mongoUrl == "" {
		mongoUrl = "mongodb://localhost:27017/"
		pLog.Printf("Defaulting Mongo Database to local: %s", mongoUrl)
	}
	opts := options.Client().ApplyURI(mongoUrl)
	client, err := mongo.NewClient(opts)
	if err != nil {
		pLog.Fatal(err)
		return nil, err
	}

	// Do a ping test to see that the database is actually there
	if err := client.Connect(ctx); err != nil {
		pLog.Printf("Error connecting to: %s.", mongoUrl)
		pLog.Fatal(err)
	}

	resumeToken := watchtokens.Load()
	m := MongoProvider{
		DbName:        dbName,
		DbUrl:         mongoUrl,
		client:        client,
		DefaultIssuer: defaultIssuer,
		TokenIssuer:   tknIssuer,
		resumeTokens:  resumeToken,
	}

	m.initialize(dbName, ctx)

	m.receiverStreams = m.LoadReceiverStreams()

	return &m, nil
}

func (m *MongoProvider) Close() error {
	m.resumeTokens.Store() // Save the mongo watch context to enable resumption on restart
	return m.client.Disconnect(context.Background())
}

func (m *MongoProvider) getStates() []model.StreamStateRecord {
	if !m.dbInit {
		pLog.Fatal("Mongo DB Provider not initialized while attempting to retrieve Stream Configs")
	}

	cursor, err := m.streamCol.Find(context.TODO(), bson.D{})
	if err != nil {
		pLog.Printf("Error listing Stream Configs: %v", err)
		return nil
	}
	var recs []model.StreamStateRecord
	err = cursor.All(context.TODO(), &recs)
	if err != nil {
		pLog.Printf("Error parsing Stream Configs: %v", err)
		return nil
	}
	return recs
}

func (m *MongoProvider) GetStateMap() map[string]model.StreamStateRecord {
	states := m.getStates()

	stateMap := make(map[string]model.StreamStateRecord, len(states))
	for _, state := range states {
		stateMap[state.StreamConfiguration.Id] = state
	}
	return stateMap
}

// LoadReceiverStreams looks up the inbound streams and loads the issuers JWKS for validation
func (m *MongoProvider) LoadReceiverStreams() map[string]*model.StreamStateRecord {
	recs := m.getStates()

	res := map[string]*model.StreamStateRecord{}
	for _, streamState := range recs {
		if streamState.Inbound != nil && *streamState.Inbound {
			res[streamState.StreamConfiguration.Id] = &streamState
			m.loadJwksForReceiver(&streamState)
		}
	}
	return res
}

func (m *MongoProvider) loadJwksForReceiver(streamState *model.StreamStateRecord) {

	if streamState.Status == model.StreamStateActive {
		// Create the keyfunc keyOptions. Use an error handler that logs. Refresh the JWKS when a JWT signed by an unknown KID
		// is found or at the specified interval. Rate limit these refreshes. Timeout the initial JWKS refresh request after
		// 10 seconds. This timeout is also used to create the initial context.Context for keyfunc.Get.

		if streamState.IssuerJWKSUrl == "" {
			return
		}
		pLog.Printf("Loading JWKS key from: %s", streamState.IssuerJWKSUrl)
		jwks, err := goSet.GetJwks(streamState.IssuerJWKSUrl)
		if err != nil {
			msg := fmt.Sprintf("Error retrieving issuer JWKS public key: %s", err.Error())
			pLog.Println(msg)
			streamState.Status = model.StreamStatePause
			streamState.ErrorMsg = msg
			return
		}
		streamState.ValidateJwks = jwks
	}
}

// GetIssuerJwksForReceiver returns the public key for the issuer based on stream id.
func (m *MongoProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	streamState, ok := m.receiverStreams[sid]
	if !ok {
		var err error
		// this will typically when stream created after server startup.
		streamState, err = m.GetStreamState(sid)
		if err != nil {
			pLog.Println("Error loading receiver stream during JWKS initialization: " + sid)
			return nil
		}
		m.loadJwksForReceiver(streamState)
		m.receiverStreams[sid] = streamState

	}
	return streamState.ValidateJwks
}

func (m *MongoProvider) ListStreams() []model.StreamConfiguration {
	recs := m.getStates()

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

	pLog.Printf("Error generating key pair: %s", err.Error())
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
		pLog.Println("Error locating receiver key for " + streamId + ": " + err.Error())
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
		pLog.Printf("Error parsing JwkKeyRec: %s", err.Error())
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
		pLog.Printf("Error parsing JwkKeyRec: %s", err.Error())
	}

	pubKeyBytes := rec.PubKeyBytes
	pubKey, err := x509.ParsePKCS1PublicKey(pubKeyBytes)

	jwkSet := jwkset.NewMemory[any]()

	err = jwkSet.Store.WriteKey(context.Background(), jwkset.NewKey[any](pubKey, issuer))
	if err != nil {
		pLog.Println("Error creating JWKS for key issuer: " + issuer + ": " + err.Error())
	}
	response, err := jwkSet.JSONPublic(context.Background())
	if err != nil {
		pLog.Println("Error creating JWKS response: " + err.Error())
	}

	return &response

}

func (m *MongoProvider) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	filter := bson.D{{"iss", issuer}}

	res := m.keyCol.FindOne(context.TODO(), filter)

	var rec JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		pLog.Printf("Error parsing JwkKeyRec: %s", err.Error())
	}
	if len(rec.KeyBytes) == 0 {
		return nil, errors.New("No key found for: " + issuer)
	}

	return x509.ParsePKCS1PrivateKey(rec.KeyBytes)
}

func (m *MongoProvider) RegisterStream(request model.RegisterParameters) *model.RegisterResponse {

	issuer := m.DefaultIssuer
	if request.Issuer != "" {
		issuer = request.Issuer
	}

	resp, err := m.CreateStream(request, issuer)
	if err != nil {
		pLog.Printf("Error registering stream: " + err.Error())
		return nil
	}
	eventAuthToken, err := m.IssueStreamToken(resp)
	inbound := false
	if request.Inbound != nil {
		inbound = *request.Inbound
	}

	if inbound && resp.Delivery.PushDeliveryMethod != nil {
		return &model.RegisterResponse{
			Token:   eventAuthToken,
			PushUrl: resp.Delivery.PushDeliveryMethod.EndpointUrl,
			Inbound: &inbound,
		}
	} else if !inbound && resp.Delivery.PollDeliveryMethod != nil {
		return &model.RegisterResponse{
			Token:   eventAuthToken,
			PushUrl: resp.Delivery.PollDeliveryMethod.EndpointUrl,
		}
	}
	return &model.RegisterResponse{Token: eventAuthToken}
}

func (m *MongoProvider) insertStream(streamRec *model.StreamStateRecord) error {
	_, err := m.streamCol.InsertOne(context.TODO(), streamRec)

	return err
}

func (m *MongoProvider) CreateStream(request model.RegisterParameters, issuer string) (model.StreamConfiguration, error) {
	mid := primitive.NewObjectID()

	var config model.StreamConfiguration
	{
	}

	config.Id = mid.Hex()
	config.Aud = request.Audience
	config.Iss = issuer
	config.EventsSupported = GetSupportedEvents()

	if len(request.EventUris) > 0 {
		config.EventsRequested = request.EventUris
		config.EventsDelivered = calculatedDeliveredEvents(request.EventUris, config.EventsSupported)

	}

	if request.Method == model.DeliveryPush {
		pushMethod := &model.OneOfStreamConfigurationDelivery{
			PushDeliveryMethod: &model.PushDeliveryMethod{
				Method:              model.DeliveryPush,
				EndpointUrl:         request.EventUrl,
				AuthorizationHeader: request.EventAuth,
			},
		}
		config.Delivery = pushMethod
	} else {
		method := &model.OneOfStreamConfigurationDelivery{
			PollDeliveryMethod: &model.PollDeliveryMethod{
				Method:      model.DeliveryPoll,
				EndpointUrl: "/poll"},
		}
		config.Delivery = method
	}
	config.MinVerificationInterval = 15
	// config.IssuerJWKSUrl = "/jwks/" + issuer

	// SCIM services will generally use the SCIM ID
	config.Format = CSubjectFmt

	if request.IssuerJWKSUrl != "" {
		config.IssuerJWKSUrl = request.IssuerJWKSUrl
	} else {
		config.IssuerJWKSUrl = "/jwks/" + issuer
	}

	now := time.Now()
	inbound := false
	if request.Inbound != nil {
		inbound = *request.Inbound
	}
	streamRec := model.StreamStateRecord{
		Id:                  mid,
		StreamConfiguration: config,
		StartDate:           now,
		Status:              model.StreamStateActive,
		CreatedAt:           now,
		Inbound:             &inbound,
	}
	if inbound {
		// streamRec.IssuerJWKSUrl = request.IssuerJWKSUrl
		receiverConfiguration := model.ReceiveConfig{
			RouteMode: request.RouteMode,
			Method:    request.Method,
		}
		if receiverConfiguration.RouteMode == "" {
			receiverConfiguration.RouteMode = model.RouteModeImport
		}
		switch request.Method {
		case model.DeliveryPoll:
			receiverConfiguration.PollAuth = request.EventAuth
			receiverConfiguration.PollUrl = request.EventUrl

			// TODO: These are just defaulted for now
			receiverConfiguration.PollParams = model.PollParameters{
				MaxEvents:         1000,
				ReturnImmediately: false,
				TimeoutSecs:       10,
			}
		case model.DeliveryPush:
			// pushToken, _ := m.IssueStreamToken(config)
			pushMethod := &model.OneOfStreamConfigurationDelivery{
				PushDeliveryMethod: &model.PushDeliveryMethod{
					Method:      model.DeliveryPush,
					EndpointUrl: "/events",
					// AuthorizationHeader: pushToken,
				},
			}
			config.Delivery = pushMethod
		}

		streamRec.Receiver = receiverConfiguration
	} else {

	}

	err := m.insertStream(&streamRec)
	// This may need to change.
	return config, err
}

func calculatedDeliveredEvents(requested []string, supported []string) []string {
	var delivered []string
	if len(requested) == 0 {
		return []string{}
	}
	if requested[0] == "*" {
		delivered = supported
		return delivered
	}

	for _, reqUri := range requested {
		compUri := "(?i)" + reqUri
		if strings.Contains(reqUri, "*") {
			compUri = strings.Replace(compUri, "*", ".*", -1)
		}

		for _, eventUri := range supported {
			match, err := regexp.MatchString(compUri, eventUri)
			if err != nil {
				continue
			} // ignore bad input
			if match {
				delivered = append(delivered, eventUri)
			}
		}
	}
	return delivered
}

func (m *MongoProvider) UpdateStream(streamId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {

	streamRec, err := m.GetStreamState(streamId)
	if err != nil {
		return nil, err
	}

	config := &streamRec.StreamConfiguration

	if len(configReq.EventsRequested) > 0 {
		config.EventsRequested = configReq.EventsRequested
		config.EventsDelivered = calculatedDeliveredEvents(configReq.EventsRequested, configReq.EventsSupported)
	}

	if configReq.Format != "" {
		config.Format = configReq.Format
	}

	streamRec.StreamConfiguration = *config

	docId := streamRec.Id
	filter := bson.D{{"_id", docId}}
	res, err := m.streamCol.ReplaceOne(context.TODO(), filter, streamRec)
	if err != nil {
		return nil, errors.New("Stream update error: " + err.Error())
	}

	if res.ModifiedCount == 0 {
		return nil, nil
	}
	return config, nil
}

func (m *MongoProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	docId, _ := primitive.ObjectIDFromHex(id)
	filter := bson.M{"_id": docId}

	res := m.streamCol.FindOne(context.TODO(), filter)
	if res.Err() == mongo.ErrNoDocuments {
		return nil, errors.New("not found")
	}
	var rec model.StreamStateRecord

	err := res.Decode(&rec)
	if err != nil {
		pLog.Printf("Error parsing StreamStateRecord: %s", err.Error())
		return nil, err
	}
	return &rec, nil
}

func (m *MongoProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	streamState, _ := m.GetStreamState(streamId)
	streamState.Status = status
	streamState.ErrorMsg = errorMsg
	docId, _ := primitive.ObjectIDFromHex(streamId)
	filter := bson.M{"_id": docId}
	_, err := m.streamCol.ReplaceOne(context.TODO(), filter, streamState)
	if err != nil {
		pLog.Println("Error pausing stream: " + err.Error())
	}
}

func (m *MongoProvider) GetStatus(streamId string) (*model.StreamStatus, error) {
	state, err := m.GetStreamState(streamId)
	if err != nil {
		return nil, err
	}

	status := model.StreamStatus{
		Status: state.Status,
	}
	return &status, nil
}

func (m *MongoProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	rec, err := m.GetStreamState(id)
	if err != nil {
		return nil, err
	}
	config := rec.StreamConfiguration
	return &config, nil
}

func (m *MongoProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) *model.EventRecord {
	jti := event.ID
	keys := make([]string, len(event.Events))
	i := 0
	for k := range event.Events {
		keys[i] = k
		i++
	}

	/*
		The event time for searching is in order of preference the toe, iat, or current time.  This value is used for sorting and reseting
	*/
	var sortTime time.Time
	if event.TimeOfEvent != nil {
		sortTime = event.TimeOfEvent.Time
	} else if event.IssuedAt != nil {
		sortTime = event.IssuedAt.Time
	} else {
		sortTime = time.Now()
	}

	rec := model.EventRecord{
		Jti:      jti,
		Event:    *event,
		Original: raw,
		Types:    keys,
		Sid:      sid,
		SortTime: sortTime,
	}
	_, err := m.eventCol.InsertOne(context.TODO(), &rec)
	if err != nil {
		pLog.Println(err.Error())
		return nil
	}

	// TODO event router needs to be notified

	// The router should do this now
	/*
		for _, id := range streamIds {
			mid, _ := primitive.ObjectIDFromHex(id)
			deliverable := DeliverableEvent{Jti: jti, StreamId: mid}
			m.pendingCol.InsertOne(context.TODO(), &deliverable)
		}

	*/
	return &rec
}

func (m *MongoProvider) AddEventToStream(jti string, streamId primitive.ObjectID) {

	deliverable := DeliverableEvent{
		Jti:      jti,
		StreamId: streamId,
	}
	_, _ = m.pendingCol.InsertOne(context.TODO(), &deliverable)
}

func (m *MongoProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	// validate the request
	if jti == "" && resetDate == nil {
		return errors.New("reset error: a date or jti must be provided")
	}
	if streamId == "" {
		return errors.New("reset error: invalid stream identifier specified")
	}
	stream, err := m.GetStreamState(streamId)
	if err != nil {
		return err
	}

	// first clear any currently pending events (in order to prevent sequencing issues)

	filter := bson.D{
		{"sid", stream.Id},
	}
	many, err := m.pendingCol.DeleteMany(context.TODO(), filter)
	if err != nil {
		return err
	}
	deleteCount := many.DeletedCount
	fmt.Println(fmt.Sprintf("DEBUG: removed %d pending events before reset", deleteCount))

	var fromFilter bson.D
	// Now search and re-assign events from the event store
	if jti != "" {
		fromFilter = bson.D{
			{"jti", bson.D{{"$gte", jti}}},
		}
	} else if resetDate != nil {
		fromFilter = bson.D{
			{"sortTime", bson.D{{"$gte", resetDate}}},
		}
	} else {
		return errors.New("no reset date or JTI reset point provided")
	}
	filter = fromFilter
	/*
		types := stream.StreamConfiguration.EventsDelivered
		if len(types) == 0 {
			filter = fromFilter
		} else if len(types) == 1 {
			typeFilter := bson.D{
				{"types", types[0]},
			}
			filter = bson.D{
				{"$and", []interface{}{
					fromFilter,
					typeFilter,
				}},
			}
		} else {
			orTerms := make([]interface{}, len(types))
			for i := 0; i < len(types); i++ {
				orTerms[i] = bson.D{
					{"types", types[i]},
				}
			}

			filter = bson.D{
				{"$and", []interface{}{
					fromFilter,
					bson.D{
						{"$or", orTerms},
					},
				}},
			}
		}
	*/

	var eventRecord model.EventRecord
	cursor, err := m.eventCol.Find(context.TODO(), filter)
	if err != nil {
		return err
	}
	for cursor.Next(context.TODO()) {
		if err := cursor.Decode(&eventRecord); err != nil {
			return err
		}
		if isStreamEvent(&eventRecord) {
			m.AddEventToStream(eventRecord.Jti, stream.Id)
		}
	}

	return nil
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
			pLog.Println(err.Error())
			return
		}
		acked := DeliveredEvent{
			DeliverableEvent: event,
			AckDate:          time.Now(),
		}
		_, _ = m.deliveredCol.InsertOne(context.TODO(), &acked)

		_, _ = m.pendingCol.DeleteOne(context.TODO(), filter)
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
			pLog.Println("Error: Unable to initialize event stream: " + err.Error())
		}

		// resToken := eventStream.ResumeToken()
		// resToken.String()

		routineCtx := context.WithValue(context.Background(), "streamid", streamId)
		defer func(eventStream *mongo.ChangeStream, ctx context.Context) {
			_ = eventStream.Close(ctx)
		}(eventStream, routineCtx)

		if eventStream.Next(routineCtx) {
			// now that there are events to return, re-poll
			// changeEvent := eventStream.Current
			// pLog.Printf("ChangeEvent: %v", changeEvent.String())
			time.Sleep(time.Millisecond * 50) // Give a pause in case more events are available

			return m.GetEventIds(streamId, params)
		} else {
			if routineCtx.Err() != nil {
				pLog.Printf("Error occurred waiting for events on sid [%v]: %s", streamId, routineCtx.Err().Error())
			}
		}
	}

	var events []DeliverableEvent
	cursor, err := m.pendingCol.Find(context.TODO(), filter, opts)
	if err = cursor.All(context.TODO(), &events); err != nil {
		pLog.Println("Error getting event batch: " + err.Error())
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

func (m *MongoProvider) GetEvent(jti string) *goSet.SecurityEventToken {
	res := m.GetEventRecord(jti)
	if res != nil {
		return &res.Event
	}
	return nil
}

func (m *MongoProvider) GetEventRecord(jti string) *model.EventRecord {
	filter := bson.D{
		{"jti", jti},
	}
	var res model.EventRecord
	cursor := m.eventCol.FindOne(context.TODO(), filter)
	err := cursor.Decode(&res)
	if err != nil {
		// pLog.Println(err.Error())
		return nil
	}
	return &res
}

func (m *MongoProvider) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	res := make([]*goSet.SecurityEventToken, len(jtis))
	for i, v := range jtis {
		set := m.GetEvent(v)
		res[i] = set
	}

	return res
}

func (m *MongoProvider) IssueStreamToken(record model.StreamConfiguration) (string, error) {
	exp := time.Now().AddDate(0, 0, 90)

	eat := server.EventAuthToken{
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
	tkn, err := server.ParseAuthToken(token, m.tokenPubKey)
	if err != nil {
		return "", err
	}
	return tkn.StreamId, nil
}

func (m *MongoProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.tokenPubKey
}
