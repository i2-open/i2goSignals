package mongo_provider

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider/watchtokens"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
)

var pLog2 = logger.Sub("MONGO_V2")

type MongoProviderV2 struct {
	mu          sync.RWMutex
	DbUrl       string
	DbName      string
	mongoClient *mongo.Client

	// dbInit is a flag confirming a valid SSEF database is connected and initialized
	dbInit bool
	ssefDb *mongo.Database

	// Collections
	streamCol    *mongo.Collection
	keyCol       *mongo.Collection
	eventCol     *mongo.Collection
	pendingCol   *mongo.Collection
	deliveredCol *mongo.Collection
	clientCol    *mongo.Collection

	// DAOs
	streamDAO interfaces.StreamDAO
	eventDAO  interfaces.EventDAO
	keyDAO    interfaces.KeyDAO
	clientDAO interfaces.ClientDAO

	// Services
	keyService    *services.KeyService
	streamService *services.StreamService
	eventService  *services.EventService
	clientService *services.ClientService

	DefaultIssuer string
	TokenIssuer   string
	resumeTokens  *watchtokens.TokenData
	stopMonitor   chan struct{}
}

func (m *MongoProviderV2) Name() string {
	return m.DbName
}

func (m *MongoProviderV2) initialize(dbName string, ctx context.Context) error {
	dbNames, err := m.mongoClient.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		return err
	}

	dbExists := false
	for _, name := range dbNames {
		if name == dbName {
			dbExists = true
			break
		}
	}

	if dbExists {
		m.ssefDb = m.mongoClient.Database(dbName)
		pLog2.Info("Connected to existing database", "dbName", dbName)
	} else {
		pLog2.Info("Initializing new database", "dbName", m.DbName)
		m.resumeTokens.Reset()
		m.ssefDb = m.mongoClient.Database(m.DbName)
	}

	// Initialize collections
	m.streamCol = m.ssefDb.Collection(CDbStreamCfg)
	m.keyCol = m.ssefDb.Collection(CDbKeys)
	m.deliveredCol = m.ssefDb.Collection(CDbDelivered)
	m.pendingCol = m.ssefDb.Collection(CDbPending)
	m.eventCol = m.ssefDb.Collection(CDbEvents)
	m.clientCol = m.ssefDb.Collection(CDbClients)

	// Create indexes
	if !dbExists {
		m.createIndexes(ctx)
	}

	// Initialize DAOs
	m.streamDAO = mongodao.NewStreamDAO(m.streamCol)
	m.eventDAO = mongodao.NewEventDAO(m.eventCol, m.pendingCol, m.deliveredCol)
	m.keyDAO = mongodao.NewKeyDAO(m.keyCol)
	m.clientDAO = mongodao.NewClientDAO(m.clientCol)

	// Initialize Services
	m.keyService = services.NewKeyService(m.keyDAO, m.TokenIssuer)
	m.streamService = services.NewStreamService(m.streamDAO, m.keyService, m.DefaultIssuer)
	m.eventService = services.NewEventService(m.eventDAO)
	m.clientService = services.NewClientService(m.clientDAO, m.keyService)

	// Initialize token keys
	err = m.keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
	if err != nil {
		return err
	}

	m.dbInit = true

	// Load receiver streams
	_ = m.streamService.LoadReceiverStreams(ctx)

	return nil
}

func (m *MongoProviderV2) createIndexes(ctx context.Context) {
	indexSid := mongo.IndexModel{
		Keys: bson.M{"sid": 1},
	}

	_, err := m.pendingCol.Indexes().CreateOne(ctx, indexSid)
	if err != nil {
		pLog2.Error("Error creating index for pendingCol", "error", err)
	}
	_, err = m.deliveredCol.Indexes().CreateOne(ctx, indexSid)
	if err != nil {
		pLog2.Error("Error creating index for deliveredCol", "error", err)
	}

	indexIss := mongo.IndexModel{
		Keys: bson.M{"iss": 1},
	}
	_, err = m.keyCol.Indexes().CreateOne(ctx, indexIss)
	if err != nil {
		pLog2.Error("Error creating index for keyCol", "error", err)
	}
}

func (m *MongoProviderV2) Check() error {
	if m.mongoClient == nil {
		return errors.New("mongo client not initialized")
	}
	return m.mongoClient.Ping(context.Background(), nil)
}

func (m *MongoProviderV2) ResetDb(initialize bool) error {
	if m.ssefDb == nil {
		return errors.New("database not initialized")
	}
	err := m.ssefDb.Drop(context.TODO())
	if err != nil {
		pLog2.Error("Error resetting database", "error", err)
		return err
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
		_ = m.initialize(m.DbName, context.TODO())
	}

	return err
}

func (m *MongoProviderV2) connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Client().ApplyURI(m.DbUrl)
	opts.WriteConcern = &writeconcern.WriteConcern{
		W: "majority",
	}
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return err
	}
	m.mongoClient = client

	err = m.Check()
	if err != nil {
		return err
	}

	err = m.initialize(m.DbName, ctx)
	if err != nil {
		return err
	}

	return nil
}

func (m *MongoProviderV2) monitor() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.mu.RLock()
			dbInit := m.dbInit
			m.mu.RUnlock()
			if !dbInit {
				pLog2.Info("Attempting to reconnect to Mongo...")
				err := m.connect()
				if err != nil {
					pLog2.Error("Reconnect failed", "error", err)
				} else {
					pLog2.Info("Reconnect successful")
				}
			} else {
				err := m.Check()
				if err != nil {
					pLog2.Warn("Mongo availability check failed", "error", err)
					m.mu.Lock()
					m.dbInit = false
					m.mu.Unlock()
				}
			}
		case <-m.stopMonitor:
			pLog2.Info("Stopping Mongo monitor goroutine")
			return
		}
	}
}

func OpenV2(mongoUrl string, dbName string) (*MongoProviderV2, error) {
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
		pLog2.Info("Defaulting Mongo Database to local", "url", mongoUrl)
	}

	resumeToken := watchtokens.Load()
	m := &MongoProviderV2{
		DbName:        dbName,
		DbUrl:         mongoUrl,
		DefaultIssuer: defaultIssuer,
		TokenIssuer:   tknIssuer,
		resumeTokens:  resumeToken,
		stopMonitor:   make(chan struct{}),
	}

	if logger.IsDebugEnabled() {
		pLog2.Info("Pausing to allow debug to load")
		time.Sleep(10 * time.Second)
	}

	err := m.connect()
	if err != nil {
		pLog2.Warn("initial Mongo connection failed. Retrying in background.", "error", err)
	} else {
		pLog2.Info("Initial Mongo connection successful")
	}

	go m.monitor()

	return m, nil
}

func (m *MongoProviderV2) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resumeTokens.Store() // Save the mongo watch context to enable resumption on restart
	if m.stopMonitor != nil {
		select {
		case <-m.stopMonitor:
			// already closed
		default:
			close(m.stopMonitor)
		}
	}
	if m.mongoClient != nil {
		err := m.mongoClient.Disconnect(context.Background())
		m.mongoClient = nil
		m.dbInit = false
		return err
	}
	return nil
}

// Provider Interface Implementation - delegating to services

func (m *MongoProviderV2) DeleteIssuer(issuer string) error {
	return m.keyService.DeleteIssuer(context.Background(), issuer)
}

func (m *MongoProviderV2) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	return m.keyService.GetPublicTransmitterJWKS(context.Background(), issuer)
}

func (m *MongoProviderV2) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	return m.keyService.GetIssuerPrivateKey(context.Background(), issuer)
}

func (m *MongoProviderV2) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.keyService.GetAuthValidatorPubKey()
}

func (m *MongoProviderV2) GetAuthIssuer() *authUtil.AuthIssuer {
	return m.keyService.GetAuthIssuer()
}

func (m *MongoProviderV2) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return m.streamService.GetIssuerJwksForReceiver(context.Background(), sid)
}

func (m *MongoProviderV2) CreateIssuerJwkKeyPair(issuer string, projectId string) *rsa.PrivateKey {
	return m.keyService.CreateIssuerJwkKeyPair(context.Background(), issuer, projectId)
}

func (m *MongoProviderV2) RotateIssuerKey(issuer string, projectId string) (*rsa.PrivateKey, string, error) {
	return m.keyService.RotateIssuerKey(context.Background(), issuer, projectId)
}

func (m *MongoProviderV2) GetIssuerKeyNames() []string {
	names, _ := m.keyService.GetIssuerKeyNames(context.Background())
	return names
}

func (m *MongoProviderV2) GetIssuerPrivateKeyWithKid(issuer string) (*rsa.PrivateKey, string, error) {
	return m.keyService.GetIssuerPrivateKeyWithKid(context.Background(), issuer)
}

func (m *MongoProviderV2) AddIssuerKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	return m.keyService.AddIssuerKey(context.Background(), issuer, kid, privateKey, publicKey, projectId)
}

func (m *MongoProviderV2) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	return m.clientService.RegisterClient(context.Background(), request, projectId)
}

func (m *MongoProviderV2) CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error) {
	return m.streamService.CreateStream(context.Background(), request, projectId)
}

func (m *MongoProviderV2) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	return m.streamService.UpdateStream(context.Background(), streamId, projectId, configReq)
}

func (m *MongoProviderV2) DeleteStream(streamId string) error {
	return m.streamService.DeleteStream(context.Background(), streamId)
}

func (m *MongoProviderV2) GetStream(id string) (*model.StreamConfiguration, error) {
	return m.streamService.GetStream(context.Background(), id)
}

func (m *MongoProviderV2) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return m.streamService.GetStreamState(context.Background(), id)
}

func (m *MongoProviderV2) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	m.streamService.UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
}

func (m *MongoProviderV2) GetStatus(streamId string) (*model.StreamStatus, error) {
	return m.streamService.GetStatus(context.Background(), streamId)
}

func (m *MongoProviderV2) ListStreams() []model.StreamConfiguration {
	return m.streamService.ListStreams(context.Background())
}

func (m *MongoProviderV2) GetStateMap() map[string]model.StreamStateRecord {
	return m.streamService.GetStateMap(context.Background())
}

func (m *MongoProviderV2) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return m.eventService.GetEventIds(context.Background(), streamId, params)
}

func (m *MongoProviderV2) GetEvent(jti string) *goSet.SecurityEventToken {
	return m.eventService.GetEvent(context.Background(), jti)
}

func (m *MongoProviderV2) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	return m.eventService.GetEvents(context.Background(), jtis)
}

func (m *MongoProviderV2) GetEventRecord(jti string) *model.EventRecord {
	return m.eventService.GetEventRecord(context.Background(), jti)
}

func (m *MongoProviderV2) AckEvent(jtiString string, streamId string) {
	m.eventService.AckEvent(context.Background(), jtiString, streamId)
}

func (m *MongoProviderV2) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (eventRecord *model.EventRecord) {
	return m.eventService.AddEvent(context.Background(), event, sid, raw)
}

func (m *MongoProviderV2) AddEventToStream(jti string, streamId primitive.ObjectID) {
	m.eventService.AddEventToStream(context.Background(), jti, streamId)
}

func (m *MongoProviderV2) WatchPending(ctx context.Context, callback func(jti string, streamId primitive.ObjectID)) {
	m.eventService.WatchPending(ctx, callback)
}

func (m *MongoProviderV2) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	return m.eventService.ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
}
