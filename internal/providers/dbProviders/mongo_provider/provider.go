package mongo_provider

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/common"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider/watchtokens"
	"github.com/i2-open/i2goSignals/internal/services"
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

	// coordinator owns the cluster lease/node-registry methods. Collections
	// are pushed in via SetCollections during initialize/reconnect.
	coordinator *MongoCoordinator
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

	if m.coordinator == nil {
		m.coordinator = NewMongoCoordinator()
	}
}

// Coordinator returns the MongoCoordinator owning lease and node-registry
// state. Always non-nil after Open / initBaseProvider.
func (m *MongoProvider) Coordinator() cluster.ClusterCoordinator {
    return m.coordinator
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

	if m.coordinator == nil {
		m.coordinator = NewMongoCoordinator()
	}
	m.coordinator.SetCollections(m.leaseCol, m.nodeCol)

	// Create indexes
	if !dbExists {
		err = m.createIndexes(ctx)
		if err != nil {
			return err
		}
	}

    // Rebind the existing DAOs in place. The DAOs are created once by
    // initBaseProvider with nil collections; here we point them at the
    // collections from the freshly-(re)connected database. This replaces
    // the previous "rebuild BaseProvider on every initialize" pattern.
    m.BaseProvider.GetStreamDAO().(*mongodao.StreamDAOMongo).SetCollection(m.streamCol)
    m.BaseProvider.GetEventDAO().(*mongodao.EventDAOMongo).SetCollections(m.eventCol, m.pendingCol, m.deliveredCol)
    m.BaseProvider.GetKeyDAO().(*mongodao.KeyDAOMongo).SetCollection(m.keyCol)
    m.BaseProvider.GetClientDAO().(*mongodao.ClientDAOMongo).SetCollection(m.clientCol)
    m.BaseProvider.GetServerDAO().(*mongodao.ServerDAOMongo).SetCollection(m.serverCol)
    m.BaseProvider.GetTokenDAOForRebind().(*mongodao.TokenDAOMongo).SetCollection(m.tokenCol)

    // Initialize token keys against the existing keyService so a slow
    // reconnect doesn't leave the AuthIssuer with a nil PublicKey.
    err = m.BaseProvider.GetKeyService().InitializeTokenKey(ctx, m.DefaultIssuer)
    if err != nil {
        return err
    }

    // BaseProvider is constructed once at startup (initBaseProvider). After
    // a (re)connect we keep the same BaseProvider/services and only rebind
    // collections (above). This is the swap-on-reconnect kill point.
    m.dbInit = true

    // Load receiver streams against the same StreamService instance we
    // wired into BaseProvider at startup.
    if m.BaseProvider.GetStreamService().LoadReceiverStreams(ctx) == nil {
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

// MongoProvider's wrapper-method tax (~160 methods that delegated to
// BaseProvider behind an RWMutex-protected swap) is gone. After PR4 phase B
// (#46) the BaseProvider is no longer swapped — the embedded *BaseProvider
// promotes its accessors directly. After PR4 phase C (#47) consumers go
// through the per-service references on SignalsApplication anyway, so the
// wrappers had no callers. SetBaseUrl, GetAuthIssuer, and the service
// accessors come from *BaseProvider via embedding.

// TryAcquireOrRenewLease delegates to the embedded MongoCoordinator. The
// method is retained on MongoProvider so existing call sites keep compiling
// during the slice-by-slice provider collapse.
func (m *MongoProvider) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
    return m.coordinator.TryAcquireOrRenewLease(resource, nodeId, leaseDuration)
}

func (m *MongoProvider) ReleaseLeaseIfOwned(resource string, nodeId string) error {
    return m.coordinator.ReleaseLeaseIfOwned(resource, nodeId)
}

func (m *MongoProvider) RegisterNode(node model.ClusterNode) error {
    return m.coordinator.RegisterNode(node)
}

func (m *MongoProvider) GetActiveNodeCount() (int64, error) {
    return m.coordinator.GetActiveNodeCount()
}

func (m *MongoProvider) GetActiveNodes() ([]model.ClusterNode, error) {
    return m.coordinator.GetActiveNodes()
}

func (m *MongoProvider) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
    return m.coordinator.GetLeaseOwner(resource)
}

func (m *MongoProvider) GetNode(nodeId string) (*model.ClusterNode, error) {
    return m.coordinator.GetNode(nodeId)
}

// SetBaseUrl is delegated to BaseProvider which handles it
