package mongo_provider

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/common"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider/watchtokens"
	"github.com/i2-open/i2goSignals/internal/services"
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
	*common.BaseProvider

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
	streamDAO := mongodao.NewStreamDAO(m.streamCol)
	eventDAO := mongodao.NewEventDAO(m.eventCol, m.pendingCol, m.deliveredCol)
	keyDAO := mongodao.NewKeyDAO(m.keyCol)
	clientDAO := mongodao.NewClientDAO(m.clientCol)

	// Initialize Services
	keyService := services.NewKeyService(keyDAO, m.TokenIssuer)
	streamService := services.NewStreamService(streamDAO, keyService, m.DefaultIssuer)
	eventService := services.NewEventService(eventDAO)
	clientService := services.NewClientService(clientDAO, keyService)

	// Initialize BaseProvider with services
	m.BaseProvider = common.NewBaseProvider(
		streamDAO, eventDAO, keyDAO, clientDAO,
		keyService, streamService, eventService, clientService,
	)

	// Initialize token keys
	err = keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
	if err != nil {
		return err
	}

	m.dbInit = true

	// Load receiver streams
	if streamService.LoadReceiverStreams(ctx) == nil {
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

// Helper methods for receiver key management (used by tests)
// These extend BaseProvider functionality with mongo-specific test helpers
func (m *MongoProvider) StoreReceiverKey(streamID string, audience string, jwksUri string) error {
	// Access the keyService through a helper method on BaseProvider
	// For now, we need to provide access via an accessor
	return m.BaseProvider.StoreReceiverKey(streamID, audience, jwksUri)
}

func (m *MongoProvider) GetReceiverKey(streamID string) *interfaces.JwkKeyRec {
	return m.BaseProvider.GetReceiverKey(streamID)
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

// SetBaseUrl is delegated to BaseProvider which handles it
