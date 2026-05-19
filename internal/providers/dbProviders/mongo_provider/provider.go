package mongo_provider

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
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
const CDbSubjectFilters = "subject_filters"

const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_STORE_MONGO_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CEnvBaseURL = "BASE_URL"
const CEnvClusterInternalToken = "I2SIG_CLUSTER_INTERNAL_TOKEN"
const CEnvClusterInternalPort = "I2SIG_CLUSTER_INTERNAL_PORT"
const CEnvTransmitterBackfillInterval = "I2SIG_TRANSMITTER_BACKFILL_INTERVAL"
const CEnvTransmitterBackfillBatch = "I2SIG_TRANSMITTER_BACKFILL_BATCH"
const CEnvMongoWatchEnabled = "I2SIG_STORE_MONGO_WATCH_ENABLED"
const CDefTokenIssuer = "DEFAULT"
const ErrorInvalidProject = "invalid project_id - invalid token"

var pLog = logger.Sub("MONGO")

// MongoProvider is the production persistence adapter. After PRD #39 PR4
// phase E it holds its DAOs and services as direct fields rather than
// embedding *common.BaseProvider — the dbProviders god-interface and façade
// have been deleted, and consumers depend on services directly via the
// Persistence record.
type MongoProvider struct {
	mu          sync.RWMutex
	DbUrl       string
	DbName      string
	mongoClient *mongo.Client

	// DAOs are constructed once in initServices() with nil collections and
	// rebound in initialize() after each (re)connect via SetCollection. The
	// concrete *mongodao.* types are needed for the rebind path; the
	// interfaces.* references satisfy the service constructors.
	streamDAO        *mongodao.StreamDAOMongo
	eventDAO         *mongodao.EventDAOMongo
	keyDAO           *mongodao.KeyDAOMongo
	clientDAO        *mongodao.ClientDAOMongo
	serverDAO        *mongodao.ServerDAOMongo
	tokenDAO         *mongodao.TokenDAOMongo
	subjectFilterDAO *mongodao.SubjectFilterDAOMongo

	// Services — long-lived, never swapped after Open returns. Reconnects
	// only rebind DAO collections in place (rebindable-collection pattern).
	streamService        *services.StreamService
	keyService           *services.KeyService
	eventService         *services.EventService
	clientService        *services.ClientService
	serverService        *services.ServerService
	tokenService         *services.TokenService
	subjectFilterService *services.SubjectFilterService
	subjectRelayService  *services.SubjectRelayService

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
	serverCol        *mongo.Collection
	tokenCol         *mongo.Collection
	subjectFilterCol *mongo.Collection

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

// initServices constructs the long-lived DAO and service instances. DAOs are
// created with nil collections so that handlers reaching the provider before
// the initial MongoDB connection completes don't panic; the connect path
// later calls SetCollection on each DAO. Services are wired once and never
// rebuilt — reconnects only rebind collections.
func (m *MongoProvider) initServices() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.streamDAO = mongodao.NewStreamDAO(nil).(*mongodao.StreamDAOMongo)
	m.eventDAO = mongodao.NewEventDAO(nil, nil, nil).(*mongodao.EventDAOMongo)
	m.keyDAO = mongodao.NewKeyDAO(nil).(*mongodao.KeyDAOMongo)
	m.clientDAO = mongodao.NewClientDAO(nil).(*mongodao.ClientDAOMongo)
	m.serverDAO = mongodao.NewServerDAO(nil).(*mongodao.ServerDAOMongo)
	m.tokenDAO = mongodao.NewTokenDAO(nil).(*mongodao.TokenDAOMongo)
	m.subjectFilterDAO = mongodao.NewSubjectFilterDAO(nil).(*mongodao.SubjectFilterDAOMongo)

	m.tokenService = services.NewTokenService(m.tokenDAO)
	m.keyService = services.NewKeyService(m.keyDAO, m.TokenIssuer, m.tokenService)
	m.streamService = services.NewStreamService(m.streamDAO, m.keyService, m.DefaultIssuer)
	m.eventService = services.NewEventService(m.eventDAO)
	m.clientService = services.NewClientService(m.clientDAO, m.keyService)
	m.serverService = services.NewServerService(m.serverDAO)
	m.subjectFilterService = services.NewSubjectFilterService(m.subjectFilterDAO)

	// StreamService.CreateStream needs ServerService to resolve tx_alias.
	m.streamService.SetServerService(m.serverService)
	// A defaultSubjects baseline change clears the stream's subject filter.
	m.streamService.SetSubjectFilterService(m.subjectFilterService)

	// PRD #89 #95: the relay service validates subject-filter modes at config
	// time and relays PASSTHRU subject changes to the upstream transmitter.
	m.subjectRelayService = services.NewSubjectRelayService(
		m.streamService.ListReceiverStreams,
		services.NewDefaultUpstreamResolver(m.serverService),
	)
	m.streamService.SetSubjectRelayService(m.subjectRelayService)

	if m.coordinator == nil {
		m.coordinator = NewMongoCoordinator()
	}
}

// Service accessors used by dbProviders.OpenPersistence to hydrate the
// Persistence composition root. MongoProvider keeps its services for the
// lifetime of the process, so these never change after initServices().
func (m *MongoProvider) GetStreamService() *services.StreamService { return m.streamService }
func (m *MongoProvider) GetKeyService() *services.KeyService       { return m.keyService }
func (m *MongoProvider) GetEventService() *services.EventService   { return m.eventService }
func (m *MongoProvider) GetClientService() *services.ClientService { return m.clientService }
func (m *MongoProvider) GetServerService() *services.ServerService { return m.serverService }
func (m *MongoProvider) GetTokenService() *services.TokenService   { return m.tokenService }
func (m *MongoProvider) GetSubjectFilterService() *services.SubjectFilterService {
	return m.subjectFilterService
}
func (m *MongoProvider) GetSubjectRelayService() *services.SubjectRelayService {
	return m.subjectRelayService
}

// GetKeyDAO returns the underlying KeyDAO. Used by rebind tests in
// internal/providers/dbProviders/mongo_provider/test/rebind_test.go to assert
// that collection rebinding takes effect on the same DAO instance.
func (m *MongoProvider) GetKeyDAO() interfaces.KeyDAO { return m.keyDAO }

// Coordinator returns the MongoCoordinator owning lease and node-registry
// state. Always non-nil after Open / initServices.
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
	m.subjectFilterCol = m.ssefDb.Collection(CDbSubjectFilters)

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
    // initServices with nil collections; here we point them at the
    // collections from the freshly-(re)connected database. Services hold
    // the same DAO instances so they immediately see the new collections.
    m.streamDAO.SetCollection(m.streamCol)
    m.eventDAO.SetCollections(m.eventCol, m.pendingCol, m.deliveredCol)
    m.keyDAO.SetCollection(m.keyCol)
    m.clientDAO.SetCollection(m.clientCol)
    m.serverDAO.SetCollection(m.serverCol)
    m.tokenDAO.SetCollection(m.tokenCol)
    m.subjectFilterDAO.SetCollection(m.subjectFilterCol)

    // Initialize token keys against the existing keyService so a slow
    // reconnect doesn't leave the AuthIssuer with a nil PublicKey.
    err = m.keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
    if err != nil {
        return err
    }

    // Services are constructed once at startup (initServices). After a
    // (re)connect we keep the same services and only rebind DAO
    // collections (above). This is the swap-on-reconnect kill point.
    m.dbInit = true

    // Load receiver streams against the same StreamService instance we
    // wired up at startup.
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
	// CEnvSpiffeMongoEnabled is the canonical (v0.11.0+) env var that
	// controls whether SPIFFE mTLS is used for MongoDB connections.
	// Requires SPIFFE_ENDPOINT_SOCKET to also be set. The deprecated
	// SPIFFE_MONGO_ENABLED is still accepted at runtime via envcompat.
	CEnvSpiffeMongoEnabled = "I2SIG_SPIFFE_MONGO_ENABLED"
)

// spiffeMongoEnabled returns true when SPIFFE mTLS should be used for
// MongoDB. Reads I2SIG_SPIFFE_MONGO_ENABLED (preferred) or the
// deprecated SPIFFE_MONGO_ENABLED through envcompat.
func spiffeMongoEnabled() bool {
	return envcompat.Lookup(CEnvSpiffeMongoEnabled, "SPIFFE_MONGO_ENABLED") == "true"
}

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
	if spiffeMongoEnabled() && tlsSupport.SpiffeEnabled() {
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
	defaultIssuer := envcompat.Lookup("I2SIG_ISSUER_DEFAULT", CEnvIssuer)
	if defaultIssuer == "" {
		if baseURL := os.Getenv(CEnvBaseURL); baseURL != "" {
			defaultIssuer = baseURL
		} else {
			defaultIssuer = CDefIssuer
		}
	}

	if dbName == "" {
		if dbEnvName := envcompat.Lookup(CEnvDbName, "I2SIG_DBNAME"); dbEnvName != "" {
			dbName = dbEnvName
		} else {
			dbName = CDbName
		}
	}

	tknIssuer := envcompat.Lookup("I2SIG_ISSUER_TOKEN", CEnvTokenIssuer)
	if tknIssuer == "" {
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

	// Construct services with nil-collection DAOs so callers reaching the
	// provider before the initial Mongo connection completes don't panic.
	m.initServices()

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

// Cluster pass-throughs retained for the lease/cluster integration tests
// under mongo_provider/test/. Production callers use Persistence.Coordinator.
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
