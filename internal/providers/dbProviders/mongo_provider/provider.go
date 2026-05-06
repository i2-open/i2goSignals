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

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/common"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider/watchtokens"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
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
const CDbServers = "servers"
const CDbTokens = "tokens"

const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CEnvBaseURL = "BASE_URL"
const CEnvClusterInternalToken = "I2SIG_CLUSTER_INTERNAL_TOKEN"
const CEnvClusterInternalPort = "I2SIG_CLUSTER_INTERNAL_PORT"
const CEnvTransmitterBackfillInterval = "I2SIG_TRANSMITTER_BACKFILL_INTERVAL"
const CEnvTransmitterBackfillBatch = "I2SIG_TRANSMITTER_BACKFILL_BATCH"
const CEnvMongoWatchEnabled = "I2SIG_MONGO_WATCH_ENABLED"
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
	serverCol    *mongo.Collection
	tokenCol     *mongo.Collection

	DefaultIssuer string
	TokenIssuer   string
	resumeTokens  *watchtokens.TokenData
	stopMonitor   chan struct{}

	// x509Source is non-nil when SPIFFE mTLS is enabled for MongoDB connections.
	// It is closed in Close().
	x509Source interface{ Close() error }
}

func (m *MongoProvider) Name() string {
	return m.DbName
}

// initBaseProvider initializes the embedded BaseProvider with "disconnected" services
// that use nil collections. This prevents nil pointer panics when the provider is
// accessed before the initial MongoDB connection is established.
func (m *MongoProvider) initBaseProvider() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize DAOs with nil collections (mongodao.New... handles nil safely)
	streamDAO := mongodao.NewStreamDAO(nil)
	eventDAO := mongodao.NewEventDAO(nil, nil, nil)
	keyDAO := mongodao.NewKeyDAO(nil)
	clientDAO := mongodao.NewClientDAO(nil)
	serverDAO := mongodao.NewServerDAO(nil)
	tokenDAO := mongodao.NewTokenDAO(nil)

	// Initialize Services (services.New... handles nil safely)
	tokenService := services.NewTokenService(tokenDAO)
	keyService := services.NewKeyService(keyDAO, m.TokenIssuer, tokenService)
	streamService := services.NewStreamService(streamDAO, keyService, m.DefaultIssuer)
	eventService := services.NewEventService(eventDAO)
	clientService := services.NewClientService(clientDAO, keyService)
	serverService := services.NewServerService(serverDAO)

	// Initialize BaseProvider with services
	m.BaseProvider = common.NewBaseProvider(
		streamDAO, eventDAO, keyDAO, clientDAO, serverDAO, tokenDAO,
		keyService, streamService, eventService, clientService, serverService, tokenService,
	)
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
	m.serverCol = m.ssefDb.Collection(CDbServers)
	m.leaseCol = m.ssefDb.Collection(CDbLeases)
	m.nodeCol = m.ssefDb.Collection(CDbNodes)
	m.tokenCol = m.ssefDb.Collection(CDbTokens)

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
	serverDAO := mongodao.NewServerDAO(m.serverCol)
	tokenDAO := mongodao.NewTokenDAO(m.tokenCol)

	// Initialize Services
	tokenService := services.NewTokenService(tokenDAO)
	keyService := services.NewKeyService(keyDAO, m.TokenIssuer, tokenService)
	streamService := services.NewStreamService(streamDAO, keyService, m.DefaultIssuer)
	eventService := services.NewEventService(eventDAO)
	clientService := services.NewClientService(clientDAO, keyService)
	serverService := services.NewServerService(serverDAO)

	// Initialize token keys before replacing m.BaseProvider so that a failed
	// InitializeTokenKey (e.g. context deadline on a slow MongoDB reconnect)
	// does not leave m.BaseProvider pointing at a new AuthIssuer whose
	// PublicKey is nil, which would cause all subsequent token validations to
	// return 503 until the next successful reconnect.
	err = keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
	if err != nil {
		return err
	}

	// Initialize BaseProvider with services (only after keys are ready)
	m.BaseProvider = common.NewBaseProvider(
		streamDAO, eventDAO, keyDAO, clientDAO, serverDAO, tokenDAO,
		keyService, streamService, eventService, clientService, serverService, tokenService,
	)

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
	m.mu.RLock()
	dbInit := m.dbInit
	m.mu.RUnlock()
	if !dbInit {
		return errors.New("database not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return m.CheckWithContext(ctx)
}

func (m *MongoProvider) CheckWithContext(ctx context.Context) error {
	if m.mongoClient == nil {
		return errors.New("mongo client not initialized")
	}
	return m.mongoClient.Ping(ctx, nil)
}

func (m *MongoProvider) ResetDb(initialize bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

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
		m.pendingCol = nil
		m.ssefDb = nil
		m.eventCol = nil
		m.streamCol = nil
		m.serverCol = nil
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

const (
	// CEnvSpiffeMongoEnabled controls whether SPIFFE mTLS is used for MongoDB
	// connections. Requires SPIFFE_ENDPOINT_SOCKET to also be set.
	CEnvSpiffeMongoEnabled = "SPIFFE_MONGO_ENABLED"
)

func (m *MongoProvider) connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Disconnect existing client if it exists to prevent leaks
	if m.mongoClient != nil {
		_ = m.mongoClient.Disconnect(context.Background())
		m.mongoClient = nil
	}

	// Overall timeout for the connection attempt, including SPIFFE setup, MongoDB connection, ping, and initialization.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	opts := options.Client().ApplyURI(m.DbUrl)
	opts.WriteConcern = &writeconcern.WriteConcern{
		W: "majority",
	}

	// When SPIFFE mTLS is enabled for MongoDB, obtain the workload's X509-SVID
	// and use it as the client certificate. This replaces username/password
	// authentication with cryptographic workload identity, provided the MongoDB
	// server is configured to accept mTLS with the SPIRE CA bundle.
	if os.Getenv(CEnvSpiffeMongoEnabled) == "true" && tlsSupport.SpiffeEnabled() {
		// Close any existing X509Source before creating a new one on reconnection.
		// Without this, the old source's background watcher goroutine leaks.
		if m.x509Source != nil {
			_ = m.x509Source.Close()
			m.x509Source = nil
		}

		// Dedicate 60 seconds of the overall timeout to obtaining the X509Source.
		spiffeCtx, spiffeCancel := context.WithTimeout(ctx, 60*time.Second)
		x509Source, err := tlsSupport.NewX509Source(spiffeCtx)
		spiffeCancel()
		if err == nil {
			tlsCfg, cfgErr := tlsSupport.NewResilientMTLSClientConfig(x509Source)
			if cfgErr == nil {
				opts.SetTLSConfig(tlsCfg)
				m.x509Source = x509Source
				pLog.Info("MongoDB: SPIFFE mTLS enabled for database connection")
			} else {
				_ = x509Source.Close()
				pLog.Warn("MongoDB: SPIFFE config error; using password auth", "err", cfgErr)
			}
		} else {
			pLog.Warn("MongoDB: SPIFFE enabled but X509Source failed; using password auth", "err", err)
		}
	}

	client, err := mongo.Connect(opts)
	if err != nil {
		return err
	}
	m.mongoClient = client

	err = m.CheckWithContext(ctx)
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
	const (
		minRetryInterval  = 5 * time.Second
		maxRetryInterval  = 60 * time.Second
		healthCheckPeriod = time.Minute
	)

	retryInterval := minRetryInterval

	// Start retrying immediately if the initial connect already failed;
	// otherwise begin with the normal health-check cadence.
	m.mu.RLock()
	firstInterval := healthCheckPeriod
	if !m.dbInit {
		firstInterval = minRetryInterval
	}
	m.mu.RUnlock()

	timer := time.NewTimer(firstInterval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			m.mu.RLock()
			dbInit := m.dbInit
			m.mu.RUnlock()

			if !dbInit {
				pLog.Info("Attempting to reconnect to Mongo...")
				if err := m.connect(); err != nil {
					pLog.Error("Reconnect failed", "error", err)
					timer.Reset(retryInterval)
					retryInterval = min(retryInterval*2, maxRetryInterval)
				} else {
					pLog.Info("Reconnect successful")
					retryInterval = minRetryInterval
					timer.Reset(healthCheckPeriod)
				}
			} else {
				if err := m.Check(); err != nil {
					pLog.Warn("Mongo availability check failed", "error", err)
					m.mu.Lock()
					m.dbInit = false
					m.mu.Unlock()
					retryInterval = minRetryInterval
					timer.Reset(retryInterval)
					retryInterval = min(retryInterval*2, maxRetryInterval)
				} else {
					timer.Reset(healthCheckPeriod)
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
		defaultIssuer, issDefined = os.LookupEnv(CEnvBaseURL)
		if !issDefined {
			defaultIssuer = CDefIssuer
		}
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

	// Initialize a minimal BaseProvider so that methods like GetAuthIssuer can be called
	// safely even before the initial connection is established.
	m.initBaseProvider()

	if os.Getenv("PAUSE_FOR_DEBUG") == "TRUE" {
		pLog.Info("Pausing to allow debug to load")
		// Using a channel and select to allow for potentially shorter pauses or cancellations if needed,
		// but keeping the 10s requirement for now.
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-timer.C:
		}
	}

	// Use a longer timeout for the overall connect attempt to allow for network delays and SPIFFE overhead.
	// But let m.connect handle its own internal contexts.
	err := m.connect()
	if err != nil {
		pLog.Warn("initial Mongo connection failed. Retrying in background.", "error", err)
	} else {
		pLog.Info("Initial Mongo connection successful")
	}

	go m.monitor()

	return m, err
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
	if m.x509Source != nil {
		_ = m.x509Source.Close()
		m.x509Source = nil
	}
	if m.mongoClient != nil {
		err := m.mongoClient.Disconnect(context.Background())
		m.mongoClient = nil
		m.dbInit = false
		return err
	}
	return nil
}

// getBaseProvider returns the embedded BaseProvider with proper RLock protection
func (m *MongoProvider) getBaseProvider() *common.BaseProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.BaseProvider
}

// DbProviderInterface delegation with thread-safety

func (m *MongoProvider) DeleteKeysByName(keyName string) error {
	return m.getBaseProvider().DeleteKeysByName(keyName)
}

func (m *MongoProvider) GetPublicJWKS(keyName string) *json.RawMessage {
	return m.getBaseProvider().GetPublicJWKS(keyName)
}

func (m *MongoProvider) GetPrivateKey(keyName string) (*rsa.PrivateKey, error) {
	return m.getBaseProvider().GetPrivateKey(keyName)
}

func (m *MongoProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.getBaseProvider().GetAuthValidatorPubKey()
}

func (m *MongoProvider) GetAuthIssuer() *authUtil.AuthIssuer {
	return m.getBaseProvider().GetAuthIssuer()
}

func (m *MongoProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return m.getBaseProvider().GetIssuerJwksForReceiver(sid)
}

func (m *MongoProvider) CreateKeyPair(keyName string, use string, projectId string) (*rsa.PrivateKey, error) {
	return m.getBaseProvider().CreateKeyPair(keyName, use, projectId)
}

func (m *MongoProvider) RotateKey(keyName string, projectId string) (*rsa.PrivateKey, string, error) {
	return m.getBaseProvider().RotateKey(keyName, projectId)
}

func (m *MongoProvider) ListKeyNames() []string {
	return m.getBaseProvider().ListKeyNames()
}

func (m *MongoProvider) ListSummaries() ([]interfaces.KeySummary, error) {
	return m.getBaseProvider().ListSummaries()
}

func (m *MongoProvider) GetPrivateKeyWithKid(keyName string) (*rsa.PrivateKey, string, error) {
	return m.getBaseProvider().GetPrivateKeyWithKid(keyName)
}

func (m *MongoProvider) AddKey(keyName string, use string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	return m.getBaseProvider().AddKey(keyName, use, kid, privateKey, publicKey, projectId)
}

func (m *MongoProvider) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	return m.getBaseProvider().RegisterClient(request, projectId)
}

func (m *MongoProvider) CreateStream(request model.StreamConfiguration, authCtx *authUtil.AuthContext) (model.StreamConfiguration, error) {
	return m.getBaseProvider().CreateStream(request, authCtx)
}

func (m *MongoProvider) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	return m.getBaseProvider().UpdateStream(streamId, projectId, configReq)
}

func (m *MongoProvider) DeleteStream(streamId string) error {
	return m.getBaseProvider().DeleteStream(streamId)
}

func (m *MongoProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	return m.getBaseProvider().GetStream(id)
}

func (m *MongoProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return m.getBaseProvider().GetStreamState(id)
}

func (m *MongoProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	m.getBaseProvider().UpdateStreamStatus(streamId, status, errorMsg)
}

func (m *MongoProvider) GetStatus(streamId string) (*model.StreamStatus, error) {
	return m.getBaseProvider().GetStatus(streamId)
}

func (m *MongoProvider) ListStreams() []model.StreamConfiguration {
	return m.getBaseProvider().ListStreams()
}

func (m *MongoProvider) GetStateMap() map[string]model.StreamStateRecord {
	return m.getBaseProvider().GetStateMap()
}

func (m *MongoProvider) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return m.getBaseProvider().GetEventIds(streamId, params)
}

func (m *MongoProvider) GetEvent(jti string) *goSet.SecurityEventToken {
	return m.getBaseProvider().GetEvent(jti)
}

func (m *MongoProvider) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	return m.getBaseProvider().GetEvents(jtis)
}

func (m *MongoProvider) GetEventRecord(jti string) *model.AgEventRecord {
	return m.getBaseProvider().GetEventRecord(jti)
}

func (m *MongoProvider) AckEvent(jtiString string, streamId string, fencingToken int64) error {
	return m.getBaseProvider().AckEvent(jtiString, streamId, fencingToken)
}

func (m *MongoProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (*model.AgEventRecord, error) {
	return m.getBaseProvider().AddEvent(event, sid, raw)
}

func (m *MongoProvider) AddOperationalEvent(event *goSet.SecurityEventToken, sid string, raw string) (*model.AgEventRecord, error) {
	return m.getBaseProvider().AddOperationalEvent(event, sid, raw)
}

func (m *MongoProvider) AddEventToStream(jti string, streamId bson.ObjectID) error {
	return m.getBaseProvider().AddEventToStream(jti, streamId)
}

func (m *MongoProvider) ClearPending(streamId string) error {
	return m.getBaseProvider().ClearPending(streamId)
}

func (m *MongoProvider) WatchPending(ctx context.Context, callback func(jti string, streamId bson.ObjectID)) {
	m.getBaseProvider().WatchPending(ctx, callback)
}

func (m *MongoProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.AgEventRecord) bool) error {
	return m.getBaseProvider().ResetEventStream(streamId, jti, resetDate, isStreamEvent)
}

func (m *MongoProvider) SetBaseUrl(u *url.URL) {
	m.getBaseProvider().SetBaseUrl(u)
}

func (m *MongoProvider) CreateServer(ctx context.Context, server *model.Server) error {
	return m.getBaseProvider().CreateServer(ctx, server)
}

func (m *MongoProvider) GetServer(ctx context.Context, id string) (*model.Server, error) {
	return m.getBaseProvider().GetServer(ctx, id)
}

func (m *MongoProvider) GetServerByAlias(ctx context.Context, alias string) (*model.Server, error) {
	return m.getBaseProvider().GetServerByAlias(ctx, alias)
}

func (m *MongoProvider) UpdateServer(ctx context.Context, server *model.Server) error {
	return m.getBaseProvider().UpdateServer(ctx, server)
}

func (m *MongoProvider) DeleteServer(ctx context.Context, id string) error {
	return m.getBaseProvider().DeleteServer(ctx, id)
}

func (m *MongoProvider) ListServers(ctx context.Context) ([]model.Server, error) {
	return m.getBaseProvider().ListServers(ctx)
}

func (m *MongoProvider) GetTokenService() *services.TokenService {
	return m.getBaseProvider().GetTokenService()
}

// Helper methods for external key management (used by tests)
func (m *MongoProvider) StoreExternalKey(keyName string, kids []string, streamID string, use string, jwksUri string) error {
	return m.getBaseProvider().StoreExternalKey(keyName, kids, streamID, use, jwksUri)
}

func (m *MongoProvider) GetKeyByStreamID(streamID string) *interfaces.JwkKeyRec {
	return m.getBaseProvider().GetKeyByStreamID(streamID)
}

// TryAcquireOrRenewLease atomically acquires the lease if it is expired/unowned, or renews it if already owned by nodeId.
func (m *MongoProvider) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
	m.mu.RLock()
	col := m.leaseCol
	m.mu.RUnlock()
	if col == nil {
		return false, 0, errors.New("mongo provider not initialized")
	}

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
	err := col.FindOneAndUpdate(ctx, filter, update, opts).Decode(&lease)
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
	m.mu.RLock()
	col := m.leaseCol
	m.mu.RUnlock()
	if col == nil {
		return errors.New("mongo provider not initialized")
	}

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

	_, err := col.UpdateOne(ctx, filter, update)
	return err
}

// RegisterNode updates the node registry with heartbeats and metadata.
func (m *MongoProvider) RegisterNode(node model.ClusterNode) error {
	m.mu.RLock()
	col := m.nodeCol
	m.mu.RUnlock()
	if col == nil {
		return errors.New("mongo provider not initialized")
	}

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
	_, err := col.UpdateOne(ctx, filter, update, opts)
	return err
}

// GetActiveNodeCount returns the number of nodes that have heartbeated within the last 60 seconds.
func (m *MongoProvider) GetActiveNodeCount() (int64, error) {
	m.mu.RLock()
	col := m.nodeCol
	m.mu.RUnlock()
	if col == nil {
		return 0, errors.New("mongo provider not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	threshold := time.Now().UTC().Add(-60 * time.Second)
	filter := bson.M{
		"lastSeenAt": bson.M{"$gte": threshold},
	}

	return col.CountDocuments(ctx, filter)
}

// GetActiveNodes returns the nodes that have heartbeated within the last 60 seconds.
func (m *MongoProvider) GetActiveNodes() ([]model.ClusterNode, error) {
	m.mu.RLock()
	col := m.nodeCol
	m.mu.RUnlock()
	if col == nil {
		return nil, errors.New("mongo provider not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	threshold := time.Now().UTC().Add(-60 * time.Second)
	filter := bson.M{
		"lastSeenAt": bson.M{"$gte": threshold},
	}

	cursor, err := col.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer func(cursor *mongo.Cursor, ctx context.Context) {
		_ = cursor.Close(ctx)
	}(cursor, ctx)

	var nodes []model.ClusterNode
	if err := cursor.All(ctx, &nodes); err != nil {
		return nil, err
	}

	return nodes, nil
}

// GetLeaseOwner returns the owner node ID and lease expiration time for a resource.
func (m *MongoProvider) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
	m.mu.RLock()
	col := m.leaseCol
	m.mu.RUnlock()
	if col == nil {
		return "", time.Time{}, 0, errors.New("mongo provider not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var lease model.ClusterLease
	err := col.FindOne(ctx, bson.M{"_id": resource}).Decode(&lease)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", time.Time{}, 0, nil
		}
		return "", time.Time{}, 0, err
	}

	return lease.OwnerNodeId, lease.LeaseUntil, lease.FencingToken, nil
}

// GetNode returns a node by its ID.
func (m *MongoProvider) GetNode(nodeId string) (*model.ClusterNode, error) {
	m.mu.RLock()
	col := m.nodeCol
	m.mu.RUnlock()
	if col == nil {
		return nil, errors.New("mongo provider not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var node model.ClusterNode
	err := col.FindOne(ctx, bson.M{"_id": nodeId}).Decode(&node)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}

	return &node, nil
}

// SetBaseUrl is delegated to BaseProvider which handles it
