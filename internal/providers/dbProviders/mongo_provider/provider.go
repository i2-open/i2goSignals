package mongo_provider

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/url"
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
	"go.mongodb.org/mongo-driver/v2/bson"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const CDbName = "ssef"
const CDbStreamCfg = "streams"
const CDbKeys = "keys"
const CDbEvents = "events"
const CDbPending = "pendingEvents"
const CDbDelivered = "deliveredEvents"
const CDbClients = "clients"
const CDbLeases = "cluster_leases"
const CDbNodes = "cluster_nodes"

const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"
const ErrorInvalidProject = "invalid project_id - invalid token"

var pLog = logger.Sub("MONGO")

type MongoProvider struct {
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
	leaseCol     *mongo.Collection
	nodeCol      *mongo.Collection

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

func (m *MongoProvider) Name() string {
	return m.DbName
}

func (m *MongoProvider) initialize(dbName string, ctx context.Context) error {
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
		pLog.Info("Connected to existing database", "dbName", dbName)
	} else {
		pLog.Info("Initializing new database", "dbName", m.DbName)
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
	m.leaseCol = m.ssefDb.Collection(CDbLeases)
	m.nodeCol = m.ssefDb.Collection(CDbNodes)

	// Create indexes
	if !dbExists {
		err = m.createIndexes(ctx)
		if err != nil {
			return err
		}
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
	if m.streamService.LoadReceiverStreams(ctx) == nil {
		pLog.Warn("No receiver streams loaded during initialization")
	}

	return nil
}

func (m *MongoProvider) createIndexes(ctx context.Context) error {
	indexSid := mongo.IndexModel{
		Keys: bson.M{"sid": 1},
	}

	_, err := m.pendingCol.Indexes().CreateOne(ctx, indexSid)
	if err != nil {
		pLog.Error("Error creating index for pendingCol", "error", err)
		return err
	}
	_, err = m.deliveredCol.Indexes().CreateOne(ctx, indexSid)
	if err != nil {
		pLog.Error("Error creating index for deliveredCol", "error", err)
		return err
	}

	indexIss := mongo.IndexModel{
		Keys: bson.M{"iss": 1},
	}
	_, err = m.keyCol.Indexes().CreateOne(ctx, indexIss)
	if err != nil {
		pLog.Error("Error creating index for keyCol", "error", err)
		return err
	}
	return nil
}

func (m *MongoProvider) Check() error {
	if m.mongoClient == nil {
		return errors.New("mongo client not initialized")
	}
	return m.mongoClient.Ping(context.Background(), nil)
}

func (m *MongoProvider) ResetDb(initialize bool) error {
	if m.ssefDb == nil {
		return errors.New("database not initialized")
	}
	err := m.ssefDb.Drop(context.TODO())
	if err != nil {
		pLog.Error("Error resetting database", "error", err)
		return err
	}
	m.dbInit = false

	if initialize {
		err = m.ssefDb.Drop(context.TODO())
		if err != nil {
			pLog.Error("Error dropping database during re-initialization", "error", err)
		}
		m.pendingCol = nil
		m.ssefDb = nil
		m.eventCol = nil
		m.streamCol = nil
		m.keyCol = nil
		m.deliveredCol = nil
		m.resumeTokens.Reset()
		err = m.initialize(m.DbName, context.TODO())
		if err != nil {
			pLog.Error("Error re-initializing database", "error", err)
		}
	}

	return err
}

func (m *MongoProvider) connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Client().ApplyURI(m.DbUrl)
	opts.WriteConcern = &writeconcern.WriteConcern{
		W: "majority",
	}
	client, err := mongo.Connect(opts)
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

func (m *MongoProvider) monitor() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.mu.RLock()
			dbInit := m.dbInit
			m.mu.RUnlock()
			if !dbInit {
				pLog.Info("Attempting to reconnect to Mongo...")
				err := m.connect()
				if err != nil {
					pLog.Error("Reconnect failed", "error", err)
				} else {
					pLog.Info("Reconnect successful")
				}
			} else {
				err := m.Check()
				if err != nil {
					pLog.Warn("Mongo availability check failed", "error", err)
					m.mu.Lock()
					m.dbInit = false
					m.mu.Unlock()
				}
			}
		case <-m.stopMonitor:
			pLog.Info("Stopping Mongo monitor goroutine")
			return
		}
	}
}

func Open(mongoUrl string, dbName string) (*MongoProvider, error) {
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
		pLog.Info("Defaulting Mongo Database to local", "url", mongoUrl)
	}

	resumeToken := watchtokens.Load()
	m := &MongoProvider{
		DbName:        dbName,
		DbUrl:         mongoUrl,
		DefaultIssuer: defaultIssuer,
		TokenIssuer:   tknIssuer,
		resumeTokens:  resumeToken,
		stopMonitor:   make(chan struct{}),
	}

	if logger.IsDebugEnabled() {
		pLog.Info("Pausing to allow debug to load")
		time.Sleep(10 * time.Second)
	}

	err := m.connect()
	if err != nil {
		pLog.Warn("initial Mongo connection failed. Retrying in background.", "error", err)
	} else {
		pLog.Info("Initial Mongo connection successful")
	}

	go m.monitor()

	return m, nil
}

func (m *MongoProvider) Close() error {
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

func (m *MongoProvider) DeleteIssuer(issuer string) error {
	return m.keyService.DeleteIssuer(context.Background(), issuer)
}

func (m *MongoProvider) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	return m.keyService.GetPublicTransmitterJWKS(context.Background(), issuer)
}

func (m *MongoProvider) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	return m.keyService.GetIssuerPrivateKey(context.Background(), issuer)
}

func (m *MongoProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.keyService.GetAuthValidatorPubKey()
}

func (m *MongoProvider) GetAuthIssuer() *authUtil.AuthIssuer {
	return m.keyService.GetAuthIssuer()
}

func (m *MongoProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return m.streamService.GetIssuerJwksForReceiver(context.Background(), sid)
}

func (m *MongoProvider) CreateIssuerJwkKeyPair(issuer string, projectId string) (*rsa.PrivateKey, error) {
	return m.keyService.CreateIssuerJwkKeyPair(context.Background(), issuer, projectId)
}

func (m *MongoProvider) RotateIssuerKey(issuer string, projectId string) (*rsa.PrivateKey, string, error) {
	return m.keyService.RotateIssuerKey(context.Background(), issuer, projectId)
}

func (m *MongoProvider) GetIssuerKeyNames() []string {
	names, _ := m.keyService.GetIssuerKeyNames(context.Background())
	return names
}

func (m *MongoProvider) GetIssuerPrivateKeyWithKid(issuer string) (*rsa.PrivateKey, string, error) {
	return m.keyService.GetIssuerPrivateKeyWithKid(context.Background(), issuer)
}

func (m *MongoProvider) AddIssuerKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	return m.keyService.AddIssuerKey(context.Background(), issuer, kid, privateKey, publicKey, projectId)
}

func (m *MongoProvider) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	return m.clientService.RegisterClient(context.Background(), request, projectId)
}

func (m *MongoProvider) CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error) {
	return m.streamService.CreateStream(context.Background(), request, projectId)
}

func (m *MongoProvider) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	return m.streamService.UpdateStream(context.Background(), streamId, projectId, configReq)
}

func (m *MongoProvider) DeleteStream(streamId string) error {
	return m.streamService.DeleteStream(context.Background(), streamId)
}

func (m *MongoProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	return m.streamService.GetStream(context.Background(), id)
}

func (m *MongoProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return m.streamService.GetStreamState(context.Background(), id)
}

func (m *MongoProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	m.streamService.UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
}

func (m *MongoProvider) GetStatus(streamId string) (*model.StreamStatus, error) {
	return m.streamService.GetStatus(context.Background(), streamId)
}

func (m *MongoProvider) ListStreams() []model.StreamConfiguration {
	return m.streamService.ListStreams(context.Background())
}

func (m *MongoProvider) GetStateMap() map[string]model.StreamStateRecord {
	return m.streamService.GetStateMap(context.Background())
}

func (m *MongoProvider) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return m.eventService.GetEventIds(context.Background(), streamId, params)
}

func (m *MongoProvider) GetEvent(jti string) *goSet.SecurityEventToken {
	return m.eventService.GetEvent(context.Background(), jti)
}

func (m *MongoProvider) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	return m.eventService.GetEvents(context.Background(), jtis)
}

func (m *MongoProvider) GetEventRecord(jti string) *model.EventRecord {
	return m.eventService.GetEventRecord(context.Background(), jti)
}

func (m *MongoProvider) AckEvent(jtiString string, streamId string, fencingToken int64) error {
	return m.eventService.AckEvent(context.Background(), jtiString, streamId, fencingToken)
}

func (m *MongoProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (*model.EventRecord, error) {
	return m.eventService.AddEvent(context.Background(), event, sid, raw)
}

func (m *MongoProvider) AddEventToStream(jti string, streamId bson.ObjectID) error {
	return m.eventService.AddEventToStream(context.Background(), jti, streamId)
}

func (m *MongoProvider) WatchPending(ctx context.Context, callback func(jti string, streamId bson.ObjectID)) {
	m.eventService.WatchPending(ctx, callback)
}

func (m *MongoProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	return m.eventService.ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
}

// Helper methods for receiver key management (used by tests)
func (m *MongoProvider) StoreReceiverKey(streamID string, audience string, jwksUri string) error {
	return m.keyService.StoreReceiverKey(context.Background(), streamID, audience, jwksUri)
}

func (m *MongoProvider) GetReceiverKey(streamID string) *interfaces.JwkKeyRec {
	rec, _ := m.keyService.GetReceiverKey(context.Background(), streamID)
	return rec
}

// TryAcquireOrRenewLease atomically acquires the lease if it is expired/unowned, or renews it if already owned by nodeId.
func (m *MongoProvider) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now().UTC()
	leaseUntil := now.Add(leaseDuration)

	filter := bson.M{
		"_id": resource,
		"$or": []bson.M{
			{"leaseUntil": bson.M{"$lte": now}},
			{"ownerNodeId": nodeId},
		},
	}

	update := bson.M{
		"$set": bson.M{
			"ownerNodeId": nodeId,
			"leaseUntil":  leaseUntil,
			"updatedAt":   now,
		},
		"$inc":         bson.M{"fencingToken": 1},
		"$setOnInsert": bson.M{"createdAt": now},
	}

	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)

	var lease model.ClusterLease
	err := m.leaseCol.FindOneAndUpdate(ctx, filter, update, opts).Decode(&lease)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, 0, nil
		}
		return false, 0, err
	}

	return lease.OwnerNodeId == nodeId, lease.FencingToken, nil
}

// ReleaseLeaseIfOwned clears/shortens the lease if (and only if) it's owned by nodeId.
func (m *MongoProvider) ReleaseLeaseIfOwned(resource string, nodeId string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"_id":         resource,
		"ownerNodeId": nodeId,
	}

	update := bson.M{
		"$set": bson.M{
			"leaseUntil": time.Now().UTC(),
			"updatedAt":  time.Now().UTC(),
		},
	}

	_, err := m.leaseCol.UpdateOne(ctx, filter, update)
	return err
}

// RegisterNode updates the node registry with heartbeats and metadata.
func (m *MongoProvider) RegisterNode(node model.ClusterNode) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": node.Id}
	update := bson.M{
		"$set": bson.M{
			"address":    node.Address,
			"version":    node.Version,
			"lastSeenAt": node.LastSeenAt,
		},
		"$setOnInsert": bson.M{
			"startedAt": node.StartedAt,
		},
	}

	opts := options.UpdateOne().SetUpsert(true)
	_, err := m.nodeCol.UpdateOne(ctx, filter, update, opts)
	return err
}

// GetActiveNodeCount returns the number of nodes that have heartbeated within the last 60 seconds.
func (m *MongoProvider) GetActiveNodeCount() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	threshold := time.Now().UTC().Add(-60 * time.Second)
	filter := bson.M{
		"lastSeenAt": bson.M{"$gte": threshold},
	}

	return m.nodeCol.CountDocuments(ctx, filter)
}

func (m *MongoProvider) SetBaseUrl(u *url.URL) {
	m.streamService.SetBaseUrl(u)
}
