package mock_provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const CDbName = "ssef"
const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"

var pLog = log.New(os.Stdout, "MOCK_MONGO:  ", log.Ldate|log.Ltime)

// Global shared storage for all mock instances
var (
	sharedStorageMu sync.RWMutex
	sharedStorage   = make(map[string]*MockMongoProvider)
)

// MockMongoProvider provides an in-memory implementation of the DbProviderInterface
type MockMongoProvider struct {
	DbUrl  string
	DbName string
	dbInit bool
	mu     sync.RWMutex

	// In-memory storage
	streams         map[string]*model.StreamStateRecord
	keys            map[string]*JwkKeyRec
	events          map[string]*model.EventRecord
	pendingEvents   map[string][]DeliverableEvent // streamId -> events
	deliveredEvents map[string][]DeliveredEvent   // streamId -> events
	clients         map[string]*model.SsfClient

	DefaultIssuer   string
	TokenIssuer     string
	tokenKey        *rsa.PrivateKey
	tokenPubKey     *keyfunc.JWKS
	receiverStreams map[string]*model.StreamStateRecord
}

func (m *MockMongoProvider) Name() string {
	return m.DbName
}

func (m *MockMongoProvider) initialize(dbName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pLog.Println("Initializing new in-memory mock database [" + m.DbName + "]")

	m.streams = make(map[string]*model.StreamStateRecord)
	m.keys = make(map[string]*JwkKeyRec)
	m.events = make(map[string]*model.EventRecord)
	m.pendingEvents = make(map[string][]DeliverableEvent)
	m.deliveredEvents = make(map[string][]DeliveredEvent)
	m.clients = make(map[string]*model.SsfClient)

	m.tokenKey = m.createIssuerJwkKeyPairUnlocked(m.DefaultIssuer, "")

	// If tokenIssuer and event issuer are not the same, create the new key pair
	if m.DefaultIssuer != m.TokenIssuer {
		m.tokenKey = m.createIssuerJwkKeyPairUnlocked(m.TokenIssuer, "")
	}
	m.tokenPubKey = m.getInternalPublicTransmitterJWKSUnlocked(m.TokenIssuer)

	m.dbInit = true
}

func (m *MockMongoProvider) Check() error {
	// Mock provider is always available
	return nil
}

func (m *MockMongoProvider) ResetDb(initialize bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.streams = make(map[string]*model.StreamStateRecord)
	m.keys = make(map[string]*JwkKeyRec)
	m.events = make(map[string]*model.EventRecord)
	m.pendingEvents = make(map[string][]DeliverableEvent)
	m.deliveredEvents = make(map[string][]DeliveredEvent)
	m.clients = make(map[string]*model.SsfClient)

	if initialize {
		m.tokenKey = m.createIssuerJwkKeyPairUnlocked(m.DefaultIssuer, "")
		if m.DefaultIssuer != m.TokenIssuer {
			m.tokenKey = m.createIssuerJwkKeyPairUnlocked(m.TokenIssuer, "")
		}
		m.tokenPubKey = m.getInternalPublicTransmitterJWKSUnlocked(m.TokenIssuer)
	}

	return nil
}

// Open creates and initializes a new MockMongoProvider
// Multiple calls with the same mongoUrl will share the same underlying storage
func Open(mongoUrl string, dbName string) (*MockMongoProvider, error) {
	// Check if this is a mock URL
	if !strings.HasPrefix(mongoUrl, "mockdb:") && mongoUrl != "" {
		return nil, fmt.Errorf("mock provider only supports 'mockdb:' URL prefix, got: %s", mongoUrl)
	}

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
		mongoUrl = "mockdb://localhost:27017/"
		pLog.Printf("Defaulting Mock Mongo Database URL: %s", mongoUrl)
	}

	// Use URL as key for shared storage (ignore dbName for sharing)
	storageKey := mongoUrl

	sharedStorageMu.Lock()
	defer sharedStorageMu.Unlock()

	// Check if shared instance already exists
	if existing, ok := sharedStorage[storageKey]; ok {
		pLog.Printf("Reusing existing mock database for URL: %s (dbName: %s)", mongoUrl, dbName)
		// Return a new wrapper with the specified dbName but sharing the same storage
		wrapper := &MockMongoProvider{
			DbName:          dbName,
			DbUrl:           existing.DbUrl,
			dbInit:          existing.dbInit,
			mu:              existing.mu,
			streams:         existing.streams,
			keys:            existing.keys,
			events:          existing.events,
			pendingEvents:   existing.pendingEvents,
			deliveredEvents: existing.deliveredEvents,
			clients:         existing.clients,
			DefaultIssuer:   existing.DefaultIssuer,
			TokenIssuer:     existing.TokenIssuer,
			tokenKey:        existing.tokenKey,
			tokenPubKey:     existing.tokenPubKey,
			receiverStreams: existing.receiverStreams,
		}
		return wrapper, nil
	}

	// Create new shared instance
	m := &MockMongoProvider{
		DbName:        dbName,
		DbUrl:         mongoUrl,
		DefaultIssuer: defaultIssuer,
		TokenIssuer:   tknIssuer,
	}

	err := m.Check()
	if err != nil {
		return nil, err
	}

	m.initialize(dbName)
	m.receiverStreams = m.LoadReceiverStreams()

	// Store in shared storage
	sharedStorage[storageKey] = m
	pLog.Printf("Created new shared mock database for URL: %s (dbName: %s)", mongoUrl, dbName)

	return m, nil
}

func (m *MockMongoProvider) Close() error {
	// No resources to clean up for in-memory provider
	return nil
}

func (m *MockMongoProvider) getStates() []model.StreamStateRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.dbInit {
		pLog.Fatal("Mock DB Provider not initialized while attempting to retrieve Stream Configs")
	}

	var recs []model.StreamStateRecord
	for _, state := range m.streams {
		recs = append(recs, *state)
	}
	return recs
}

func (m *MockMongoProvider) GetStateMap() map[string]model.StreamStateRecord {
	states := m.getStates()

	stateMap := make(map[string]model.StreamStateRecord, len(states))
	for _, state := range states {
		stateMap[state.StreamConfiguration.Id] = state
	}
	return stateMap
}

// LoadReceiverStreams looks up the inbound streams and loads the issuers JWKS for validation
func (m *MockMongoProvider) LoadReceiverStreams() map[string]*model.StreamStateRecord {
	recs := m.getStates()

	res := map[string]*model.StreamStateRecord{}
	for _, streamState := range recs {
		if streamState.IsReceiver() {
			res[streamState.StreamConfiguration.Id] = &streamState
			m.loadJwksForReceiver(&streamState)
		}
	}
	return res
}

func (m *MockMongoProvider) loadJwksForReceiver(streamState *model.StreamStateRecord) {
	if streamState.Status == model.StreamStateEnabled {
		keyRec := m.GetReceiverKey(streamState.StreamConfiguration.Id)
		if keyRec != nil {
			jwksUri := keyRec.ReceiverJwksUrl
			_, err := keyfunc.Get(jwksUri, keyfunc.Options{})
			if err == nil {
				m.mu.Lock()
				m.receiverStreams[streamState.StreamConfiguration.Id] = streamState
				m.mu.Unlock()
			}
		}
	}
}

func (m *MockMongoProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if streamState, ok := m.receiverStreams[sid]; ok {
		if streamState.Status == model.StreamStateEnabled {
			keyRec := m.GetReceiverKey(sid)
			if keyRec != nil {
				jwksUri := keyRec.ReceiverJwksUrl
				jwks, err := keyfunc.Get(jwksUri, keyfunc.Options{})
				if err == nil {
					return jwks
				}
			}
		}
	}
	return nil
}

func (m *MockMongoProvider) ListStreams() []model.StreamConfiguration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var streams []model.StreamConfiguration
	for _, state := range m.streams {
		streams = append(streams, state.StreamConfiguration)
	}
	return streams
}

func (m *MockMongoProvider) DeleteStream(streamId string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.streams[streamId]; !exists {
		return errors.New("not Found")
	}
	delete(m.streams, streamId)
	return nil
}

// createIssuerJwkKeyPairUnlocked generates and stores a key pair without acquiring a lock.
// This is used when the caller already holds the lock (e.g., from initialize or ResetDb).
func (m *MockMongoProvider) createIssuerJwkKeyPairUnlocked(issuer string, projectId string) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	err = m.storeJwkKeyPairUnlocked(issuer, privateKey, projectId)
	if err == nil {
		return privateKey
	}

	pLog.Printf("Error generating key pair: %s", err.Error())
	return nil
}

func (m *MockMongoProvider) CreateIssuerJwkKeyPair(issuer string, projectId string) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	err = m.storeJwkKeyPair(issuer, privateKey, projectId)
	if err == nil {
		return privateKey
	}

	pLog.Printf("Error generating key pair: %s", err.Error())
	return nil
}

// storeJwkKeyPairUnlocked is an internal helper that stores a key pair without acquiring a lock.
// This is used when the caller already holds the lock (e.g., from initialize or ResetDb).
func (m *MockMongoProvider) storeJwkKeyPairUnlocked(issuer string, privateKey *rsa.PrivateKey, projectId string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKey := privateKey.PublicKey
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	keyPairRec := JwkKeyRec{
		Id:          primitive.NewObjectID(),
		Iss:         issuer,
		ProjectId:   projectId,
		KeyBytes:    privateKeyBytes,
		PubKeyBytes: pubKeyBytes,
	}

	m.keys[issuer] = &keyPairRec
	return nil
}

func (m *MockMongoProvider) storeJwkKeyPair(issuer string, privateKey *rsa.PrivateKey, projectId string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.storeJwkKeyPairUnlocked(issuer, privateKey, projectId)
}

func (m *MockMongoProvider) StoreReceiverKey(streamId string, audience string, jwksUri string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	keyPairRec := JwkKeyRec{
		Id:              primitive.NewObjectID(),
		Aud:             audience,
		StreamId:        streamId,
		ReceiverJwksUrl: jwksUri,
	}

	m.keys["receiver_"+streamId] = &keyPairRec
	return nil
}

func (m *MockMongoProvider) GetReceiverKey(streamId string) *JwkKeyRec {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if rec, ok := m.keys["receiver_"+streamId]; ok {
		return rec
	}
	return nil
}

// getInternalPublicTransmitterJWKSUnlocked retrieves public transmitter JWKS without acquiring a lock.
// This is used when the caller already holds the lock (e.g., from initialize or ResetDb).
func (m *MockMongoProvider) getInternalPublicTransmitterJWKSUnlocked(issuer string) *keyfunc.JWKS {
	rec, ok := m.keys[issuer]
	if !ok {
		pLog.Printf("Error: Key not found for issuer: %s", issuer)
		return nil
	}

	pubKeyBytes := rec.PubKeyBytes
	pubKey, err := x509.ParsePKCS1PublicKey(pubKeyBytes)
	if err != nil {
		pLog.Printf("Error parsing public key: %s", err.Error())
		return nil
	}

	givenKey := keyfunc.NewGivenRSACustomWithOptions(pubKey, keyfunc.GivenKeyOptions{
		Algorithm: "RS256",
	})
	givenKeys := make(map[string]keyfunc.GivenKey)
	givenKeys[issuer] = givenKey
	return keyfunc.NewGiven(givenKeys)
}

func (m *MockMongoProvider) GetInternalPublicTransmitterJWKS(issuer string) *keyfunc.JWKS {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.getInternalPublicTransmitterJWKSUnlocked(issuer)
}

func (m *MockMongoProvider) GetIssuerKeyNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	issuers := make([]string, 0, len(m.keys))
	for issuer := range m.keys {
		issuers = append(issuers, issuer)
	}

	return issuers
}

func (m *MockMongoProvider) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.keys[issuer]
	if !ok {
		return nil
	}

	pubKeyBytes := rec.PubKeyBytes
	pubKey, err := x509.ParsePKCS1PublicKey(pubKeyBytes)
	if err != nil {
		pLog.Printf("Error parsing public key: %s", err.Error())
		return nil
	}

	jwkstore := jwkset.NewMemoryStorage()

	metadata := jwkset.JWKMetadataOptions{
		KID: issuer,
	}
	jwkOptions := jwkset.JWKOptions{
		Metadata: metadata,
	}

	jwkSet, err := jwkset.NewJWKFromKey(pubKey, jwkOptions)
	if err != nil {
		pLog.Println("Error parsing rsa key into jwk: " + err.Error())
		return nil
	}
	err = jwkstore.KeyWrite(context.Background(), jwkSet)
	if err != nil {
		pLog.Println("Error creating JWKS for key issuer: " + issuer + ": " + err.Error())
		return nil
	}

	response, err := jwkstore.JSONPublic(context.Background())
	if err != nil {
		pLog.Println("Error creating JWKS response: " + err.Error())
		return nil
	}

	return &response
}

func (m *MockMongoProvider) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.keys[issuer]
	if !ok {
		return nil, fmt.Errorf("issuer key not found: %s", issuer)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(rec.KeyBytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (m *MockMongoProvider) RegisterClient(client model.SsfClient, projectId string) *model.RegisterResponse {
	m.mu.Lock()
	client.Id = primitive.NewObjectID()
	clientId := client.Id.Hex()
	m.clients[clientId] = &client
	m.mu.Unlock()

	token, err := m.GetAuthIssuer().IssueStreamClientToken(client, projectId, true)
	if err != nil {
		pLog.Println("Error issuing stream admin token: " + err.Error())
		return nil
	}

	return &model.RegisterResponse{Token: token}
}

func (m *MockMongoProvider) insertStream(streamRec *model.StreamStateRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.streams[streamRec.StreamConfiguration.Id] = streamRec
	return nil
}

func (m *MockMongoProvider) CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error) {
	mid := primitive.NewObjectID()

	var config model.StreamConfiguration

	if request.Iss == "" {
		config.Iss = m.DefaultIssuer
	} else {
		config.Iss = request.Iss
	}

	config.Id = mid.Hex()
	config.Aud = request.Aud

	config.EventsSupported = model.GetSupportedEvents()

	if len(request.EventsRequested) > 0 {
		config.EventsRequested = request.EventsRequested
		config.EventsDelivered = calculatedDeliveredEvents(request.EventsRequested, config.EventsSupported)
	}

	delivery := request.Delivery
	config.RouteMode = request.RouteMode
	switch delivery.GetMethod() {
	case model.DeliveryPush:
		config.Delivery = request.Delivery
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModePublish // default is publish
		}

	case model.DeliveryPoll, "DEFAULT":
		authToken, _ := m.GetAuthIssuer().IssueStreamToken(mid.Hex(), projectId)
		delivery := &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method:              model.DeliveryPoll,
				EndpointUrl:         fmt.Sprintf("/poll/%s", mid.Hex()),
				AuthorizationHeader: "Bearer " + authToken,
			},
		}
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModePublish // default is publish
		}
		config.Delivery = delivery

	case model.ReceivePush:
		config.Delivery = request.Delivery
		method := config.Delivery.PushReceiveMethod
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModeImport
		}
		method.EndpointUrl = fmt.Sprintf("/events/%s", mid.Hex())
		authToken, _ := m.GetAuthIssuer().IssueStreamToken(mid.Hex(), projectId)
		method.AuthorizationHeader = "Bearer " + authToken

	case model.ReceivePoll:
		config.Delivery = request.Delivery
		method := config.Delivery.PollReceiveMethod

		if request.RouteMode == "" {
			config.RouteMode = model.RouteModeImport
		}

		if method.PollConfig == nil {
			// Set the default polling if missing
			config.Delivery.PollReceiveMethod.PollConfig = &model.PollParameters{
				MaxEvents:         1000,
				ReturnImmediately: false,
				TimeoutSecs:       10,
			}
		}
	}

	config.MinVerificationInterval = 15

	// SCIM services will generally use the SCIM ID
	config.Format = CSubjectFmt

	if request.IssuerJWKSUrl != "" {
		config.IssuerJWKSUrl = request.IssuerJWKSUrl
	} else {
		config.IssuerJWKSUrl = "/jwks/" + config.Iss
	}

	now := time.Now()

	streamRec := model.StreamStateRecord{
		Id:                  mid,
		ProjectId:           projectId,
		StreamConfiguration: config,
		StartDate:           now,
		Status:              model.StreamStateEnabled,
		CreatedAt:           now,
	}

	m.mu.Lock()
	m.streams[config.Id] = &streamRec
	m.mu.Unlock()

	return config, nil
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

func (m *MockMongoProvider) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.streams[streamId]
	if !exists {
		return nil, errors.New("stream not found")
	}

	if state.ProjectId != projectId {
		return nil, errors.New("invalid project_id - invalid token")
	}

	config := &state.StreamConfiguration

	// Update the configuration
	if configReq.Delivery != nil {
		config.Delivery = configReq.Delivery
	}

	if len(configReq.EventsRequested) > 0 {
		config.EventsRequested = configReq.EventsRequested
		// Use EventsSupported from the request if provided, otherwise use what's already in config
		eventsSupported := configReq.EventsSupported
		if len(eventsSupported) == 0 {
			eventsSupported = config.EventsSupported
		}
		config.EventsDelivered = calculatedDeliveredEvents(configReq.EventsRequested, eventsSupported)
	}

	if configReq.Format != "" {
		config.Format = configReq.Format
	}

	state.StreamConfiguration = *config
	m.streams[streamId] = state
	return config, nil
}

func (m *MockMongoProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, ok := m.streams[id]; ok {
		return state, nil
	}
	return nil, errors.New("stream not found")
}

func (m *MockMongoProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state, ok := m.streams[streamId]; ok {
		state.Status = status
		state.ErrorMsg = errorMsg
	}
}

func (m *MockMongoProvider) GetStatus(streamId string) (*model.StreamStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.streams[streamId]
	if !ok {
		return nil, errors.New("stream not found")
	}

	return &model.StreamStatus{
		Status: state.Status,
		Reason: state.ErrorMsg,
	}, nil
}

func (m *MockMongoProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, ok := m.streams[id]; ok {
		return &state.StreamConfiguration, nil
	}
	return nil, errors.New("stream not found")
}

func (m *MockMongoProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) *model.EventRecord {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Extract event types from event.Events map keys
	keys := make([]string, 0, len(event.Events))
	for k := range event.Events {
		keys = append(keys, k)
	}

	// Determine sort time from toe, iat, or current time
	var sortTime time.Time
	if event.TimeOfEvent != nil {
		sortTime = event.TimeOfEvent.Time
	} else if event.IssuedAt != nil {
		sortTime = event.IssuedAt.Time
	} else {
		sortTime = time.Now()
	}

	eventRecord := &model.EventRecord{
		Jti:      event.ID,
		Event:    *event,
		Original: raw,
		Sid:      sid,
		Types:    keys,
		SortTime: sortTime,
	}

	m.events[event.ID] = eventRecord
	return eventRecord
}

func (m *MockMongoProvider) AddEventToStream(jti string, streamId primitive.ObjectID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.events[jti]; ok {
		streamIdHex := streamId.Hex()
		deliverable := DeliverableEvent{
			Jti:      jti,
			StreamId: streamId,
		}
		m.pendingEvents[streamIdHex] = append(m.pendingEvents[streamIdHex], deliverable)
	}
}

func (m *MockMongoProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear pending events for this stream
	delete(m.pendingEvents, streamId)

	// Optionally filter and re-add events based on criteria
	if resetDate != nil {
		// Truncate resetDate to second precision to match JWT NumericDate behavior
		// JWT timestamps only have second precision, so events will have truncated sortTime
		resetDateTruncated := resetDate.Truncate(time.Second)

		for jtiKey, event := range m.events {
			if isStreamEvent != nil && isStreamEvent(event) {
				// Use >= comparison to match MongoDB's $gte behavior
				// Compare with truncated resetDate since event.SortTime comes from JWT and has second precision
				if event.SortTime.Equal(resetDateTruncated) || event.SortTime.After(resetDateTruncated) {
					streamObjId, _ := primitive.ObjectIDFromHex(streamId)
					deliverable := DeliverableEvent{
						Jti:      jtiKey,
						StreamId: streamObjId,
					}
					m.pendingEvents[streamId] = append(m.pendingEvents[streamId], deliverable)
				}
			}
		}
	}

	return nil
}

func (m *MockMongoProvider) AckEvent(jtiString string, streamId string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from pending
	if pending, ok := m.pendingEvents[streamId]; ok {
		var newPending []DeliverableEvent
		var acknowledged *DeliverableEvent
		for _, event := range pending {
			if event.Jti == jtiString {
				acknowledged = &event
			} else {
				newPending = append(newPending, event)
			}
		}
		m.pendingEvents[streamId] = newPending

		// Add to delivered
		if acknowledged != nil {
			delivered := DeliveredEvent{
				DeliverableEvent: *acknowledged,
				AckDate:          time.Now(),
			}
			m.deliveredEvents[streamId] = append(m.deliveredEvents[streamId], delivered)
		}
	}
}

func (m *MockMongoProvider) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pending, ok := m.pendingEvents[streamId]
	if !ok || len(pending) == 0 {
		return []string{}, false
	}

	maxEvents := params.MaxEvents
	if maxEvents <= 0 {
		maxEvents = 10
	}

	var jtis []string
	for i, event := range pending {
		if int32(i) >= maxEvents {
			break
		}
		jtis = append(jtis, event.Jti)
	}

	moreAvailable := int32(len(pending)) > maxEvents
	return jtis, moreAvailable
}

func (m *MockMongoProvider) GetEvent(jti string) *goSet.SecurityEventToken {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if eventRec, ok := m.events[jti]; ok {
		return &eventRec.Event
	}
	return nil
}

func (m *MockMongoProvider) GetEventRecord(jti string) *model.EventRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if eventRec, ok := m.events[jti]; ok {
		return eventRec
	}
	return nil
}

func (m *MockMongoProvider) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var events []*goSet.SecurityEventToken
	for _, jti := range jtis {
		if eventRec, ok := m.events[jti]; ok {
			events = append(events, &eventRec.Event)
		}
	}
	return events
}

func (m *MockMongoProvider) GetAuthIssuer() *authUtil.AuthIssuer {
	privateKey, err := m.GetIssuerPrivateKey(m.TokenIssuer)
	if err != nil {
		pLog.Printf("Error getting token private key: %s", err.Error())
		return nil
	}

	issuer := authUtil.AuthIssuer{
		TokenIssuer: m.TokenIssuer,
		PrivateKey:  privateKey,
		PublicKey:   m.tokenPubKey,
	}
	return &issuer
}

func (m *MockMongoProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.tokenPubKey
}
