package memory_provider

import (
    "context"
    "fmt"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/i2-open/i2goSignals/internal/dao/memory"
    "github.com/i2-open/i2goSignals/internal/envcompat"
    "github.com/i2-open/i2goSignals/internal/providers/cluster"
    "github.com/i2-open/i2goSignals/internal/services"
    "github.com/i2-open/i2goSignals/pkg/logger"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

const CDbName = "goSignalsMem"
const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_STORE_MONGO_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"

const CEnvMemDir = "I2SIG_STORE_MEM_DIRECTORY"
const CEnvMemSaveRate = "I2SIG_STORE_MEM_SAVE_RATE"
const CDefMemSaveRate = 30

var pLog = logger.Sub("MEMORY_DB")

// MemoryProvider provides an in-memory implementation using DAOs and services.
//
// After PRD #39 PR4 phase E, MemoryProvider holds its services and DAOs as
// direct fields rather than embedding *common.BaseProvider. The dbProviders
// god-interface and façade have been deleted; consumers depend on services
// directly via the Persistence record.
type MemoryProvider struct {
    DbUrl  string
    DbName string
    dbInit bool

    DefaultIssuer string
    TokenIssuer   string

    // Cluster coordination — owned by a MemoryCoordinator value-typed field.
    coordinator *MemoryCoordinator

    mu sync.RWMutex

    // Services — the live business surface. Pointers so that ResetDb(true)
    // can swap them and the Persistence.Refresh() helper can rehydrate the
    // composition root without callers caching stale references.
    streamService        *services.StreamService
    keyService           *services.KeyService
    eventService         *services.EventService
    clientService        *services.ClientService
    serverService        *services.ServerService
    tokenService         *services.TokenService
    subjectFilterService *services.SubjectFilterService
    subjectRelayService  *services.SubjectRelayService

    // Direct references to the raw memory DAOs. Services see notifyingDAO
    // wrappers around these for after-mutation persistence triggering (#44);
    // PersistenceManager works against the raw DAOs because it needs the
    // concrete GetState/SetState/SetPersistDir methods.
    rawStreamDAO *memory.StreamDAOMemory
    rawEventDAO  *memory.EventDAOMemory
    rawKeyDAO    *memory.KeyDAOMemory
    rawClientDAO *memory.ClientDAOMemory
    rawServerDAO *memory.ServerDAOMemory
    rawTokenDAO  *memory.TokenDAOMemory

    // Persistence
    persistence *PersistenceManager
}

// markDirty is the after-mutation callback installed on every notifyingDAO.
// It funnels through MemoryProvider so that mutations performed before
// PersistenceManager has been created (during initialize()) are no-ops, and
// later mutations after Open() / ResetDb() flow into the live persistence.
func (m *MemoryProvider) markDirty() {
    if m.persistence != nil {
        m.persistence.MarkDirty()
    }
}

// Coordinator returns the in-process MemoryCoordinator. Always non-nil after
// initialize/Open completes.
func (m *MemoryProvider) Coordinator() cluster.ClusterCoordinator {
    return m.coordinator
}

// Service accessors used by dbProviders.OpenPersistence to hydrate the
// Persistence composition root (and by Persistence.Refresh after ResetDb).
func (m *MemoryProvider) GetStreamService() *services.StreamService { return m.streamService }
func (m *MemoryProvider) GetKeyService() *services.KeyService       { return m.keyService }
func (m *MemoryProvider) GetEventService() *services.EventService   { return m.eventService }
func (m *MemoryProvider) GetClientService() *services.ClientService { return m.clientService }
func (m *MemoryProvider) GetServerService() *services.ServerService { return m.serverService }
func (m *MemoryProvider) GetTokenService() *services.TokenService   { return m.tokenService }
func (m *MemoryProvider) GetSubjectFilterService() *services.SubjectFilterService {
    return m.subjectFilterService
}
func (m *MemoryProvider) GetSubjectRelayService() *services.SubjectRelayService {
    return m.subjectRelayService
}

func (m *MemoryProvider) StoreExternalKey(keyName string, kids []string, streamID string, use string, jwksUri string) error {
    // TODO implement me
    panic("implement me")
}

func (m *MemoryProvider) Name() string {
    return m.DbName
}

// buildServices wires up the notifyingDAO decorators around the raw memory
// DAOs and constructs the per-domain services. Used by both initialize() and
// ResetDb(true) so the wiring stays in one place.
func (m *MemoryProvider) buildServices() {
    streamDAO := newNotifyingStreamDAO(m.rawStreamDAO, m.markDirty)
    eventDAO := newNotifyingEventDAO(m.rawEventDAO, m.markDirty)
    keyDAO := newNotifyingKeyDAO(m.rawKeyDAO, m.markDirty)
    clientDAO := newNotifyingClientDAO(m.rawClientDAO, m.markDirty)
    serverDAO := newNotifyingServerDAO(m.rawServerDAO, m.markDirty)
    tokenDAO := newNotifyingTokenDAO(m.rawTokenDAO, m.markDirty)

    m.tokenService = services.NewTokenService(tokenDAO)
    m.tokenService.SetStreamDAO(streamDAO)
    m.keyService = services.NewKeyService(keyDAO, m.TokenIssuer, m.tokenService, oauthServersFromEnv)
    m.streamService = services.NewStreamService(streamDAO, m.keyService, m.DefaultIssuer, streamServiceConfigFromEnv())
    m.eventService = services.NewEventService(eventDAO)
    m.clientService = services.NewClientService(clientDAO, m.keyService)
    m.serverService = services.NewServerService(serverDAO)
    m.subjectFilterService = services.NewSubjectFilterService(memory.NewSubjectFilterDAO())

    // StreamService.CreateStream needs ServerService to resolve tx_alias.
    m.streamService.SetServerService(m.serverService)
    // A defaultSubjects baseline change clears the stream's subject filter.
    m.streamService.SetSubjectFilterService(m.subjectFilterService)

    // PRD #89 #95 #96: the relay service validates subject-filter modes at
    // config time, relays PASSTHRU subject changes 1:1 to the upstream, and
    // relays HYBRID changes on the interested-set 0↔1 boundary.
    m.subjectRelayService = services.NewSubjectRelayService(
        m.streamService.ListReceiverStreams,
        m.streamService.ListTransmitterStreams,
        m.subjectFilterService.Selects,
        services.NewDefaultUpstreamResolver(m.serverService),
    )
    m.streamService.SetSubjectRelayService(m.subjectRelayService)
}

func (m *MemoryProvider) initialize() {
    pLog.Info("Initializing new in-memory database", "dbName", m.DbName)

    if m.coordinator == nil {
        m.coordinator = NewMemoryCoordinator()
    }

    // Raw DAOs (concrete types — PersistenceManager calls GetState/SetState
    // on these directly). Stash them on the provider so the persistence
    // layer can find them without type-asserting through the wrapper.
    m.rawStreamDAO = memory.NewStreamDAO().(*memory.StreamDAOMemory)
    m.rawEventDAO = memory.NewEventDAO()
    m.rawKeyDAO = memory.NewKeyDAO().(*memory.KeyDAOMemory)
    m.rawClientDAO = memory.NewClientDAO().(*memory.ClientDAOMemory)
    m.rawServerDAO = memory.NewServerDAO().(*memory.ServerDAOMemory)
    m.rawTokenDAO = memory.NewTokenDAO().(*memory.TokenDAOMemory)

    m.buildServices()

    // Initialize token keys
    ctx := context.Background()
    err := m.keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
    if err != nil {
        pLog.Error("Error initializing token key", "error", err)
    }

    m.dbInit = true
}

func (m *MemoryProvider) Check() error {
    // Mock provider is always available
    return nil
}

func (m *MemoryProvider) ResetDb(initialize bool) error {
    if initialize {
        // Re-allocate raw DAOs and rebuild the wrapping notifying DAOs +
        // services. Existing service pointers in callers become stale —
        // Persistence.Refresh() rehydrates them.
        m.rawStreamDAO = memory.NewStreamDAO().(*memory.StreamDAOMemory)
        m.rawEventDAO = memory.NewEventDAO()
        m.rawKeyDAO = memory.NewKeyDAO().(*memory.KeyDAOMemory)
        m.rawClientDAO = memory.NewClientDAO().(*memory.ClientDAOMemory)
        m.rawServerDAO = memory.NewServerDAO().(*memory.ServerDAOMemory)
        m.rawTokenDAO = memory.NewTokenDAO().(*memory.TokenDAOMemory)

        m.buildServices()

        ctx := context.Background()
        err := m.keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
        if err != nil {
            pLog.Error("Error reinitializing token key", "error", err)
        }

        // Recreate persistence pointing at the newly-allocated raw DAOs.
        if m.persistence != nil {
            memDir := m.persistence.directory
            saveRate := m.persistence.saveRate
            m.persistence.Close()
            m.persistence = newPersistenceManagerForProvider(memDir, saveRate, m)
        }
    }

    if m.persistence != nil {
        m.persistence.MarkDirty()
    }

    return nil
}

// Open creates and initializes a new MemoryProvider
func Open(mongoUrl string, dbName string) (*MemoryProvider, error) {
    // Check if this is a memory URL
    if !strings.HasPrefix(mongoUrl, "memorydb:") && mongoUrl != "" {
        return nil, fmt.Errorf("memory provider only supports 'memorydb:' URL prefix, got: %s", mongoUrl)
    }

    defaultIssuer := envcompat.Lookup("I2SIG_ISSUER_DEFAULT", CEnvIssuer)
    if defaultIssuer == "" {
        defaultIssuer = CDefIssuer
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
        mongoUrl = "memorydb://localhost"
        pLog.Info("Defaulting Memory Database URL", "url", mongoUrl)
    }

    memDir := envcompat.Lookup(CEnvMemDir, "MEM_DIRECTORY")
    if memDir == "" {
        memDir = filepath.Join("config", dbName)
    }

    saveRate := CDefMemSaveRate
    if rateStr := envcompat.Lookup(CEnvMemSaveRate, "MEM_SAVE_RATE"); rateStr != "" {
        if r, err := strconv.Atoi(rateStr); err == nil {
            saveRate = r
        }
    }

    m := &MemoryProvider{
        DbName:        dbName,
        DbUrl:         mongoUrl,
        DefaultIssuer: defaultIssuer,
        TokenIssuer:   tknIssuer,
    }

    err := m.Check()
    if err != nil {
        return nil, err
    }

    m.initialize()

    // Initialize persistence using direct refs to the raw memory DAOs.
    // The notifyingDAO wrappers around those DAOs invoke m.markDirty after
    // every successful mutation, so MarkDirty fires automatically once
    // m.persistence is non-nil. No WriteHook plumbing is required (#44).
    m.persistence = newPersistenceManagerForProvider(memDir, saveRate, m)
    err = m.persistence.Initialize()
    if err != nil {
        pLog.Warn("Persistence initialization failed, continuing in memory-only mode", "error", err)
    }

    pLog.Info("Created new memory database", "dbName", dbName)
    if m.persistence.directory != "" {
        pLog.Info("Persistence ENABLED", "directory", m.persistence.directory, "saveRate", m.persistence.saveRate)
    } else {
        pLog.Warn("****************************************************************")
        pLog.Warn("* WARNING: The server is running with an IN-MEMORY database.   *")
        pLog.Warn("* This is for development and testing purposes only.           *")
        pLog.Warn("* Data will NOT be persisted across restarts.                  *")
        pLog.Warn("* The server is running as a SINGLE NODE.                      *")
        pLog.Warn("****************************************************************")
    }

    return m, nil
}

func (m *MemoryProvider) Close() error {
    if m.persistence != nil {
        m.persistence.Close()
    }
    return nil
}

// Cluster coordination methods delegate to MemoryCoordinator. Real lease
// semantics (atomic acquire, expiry, fencing-token monotonicity) live there.

func (m *MemoryProvider) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
    return m.coordinator.TryAcquireOrRenewLease(resource, nodeId, leaseDuration)
}

func (m *MemoryProvider) ReleaseLeaseIfOwned(resource string, nodeId string) error {
    return m.coordinator.ReleaseLeaseIfOwned(resource, nodeId)
}

func (m *MemoryProvider) RegisterNode(node model.ClusterNode) error {
    return m.coordinator.RegisterNode(node)
}

func (m *MemoryProvider) GetActiveNodeCount() (int64, error) {
    return m.coordinator.GetActiveNodeCount()
}

func (m *MemoryProvider) GetActiveNodes() ([]model.ClusterNode, error) {
    return m.coordinator.GetActiveNodes()
}

func (m *MemoryProvider) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
    return m.coordinator.GetLeaseOwner(resource)
}

func (m *MemoryProvider) GetNode(nodeId string) (*model.ClusterNode, error) {
    return m.coordinator.GetNode(nodeId)
}
