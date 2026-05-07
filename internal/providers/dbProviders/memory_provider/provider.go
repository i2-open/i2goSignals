package memory_provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/common"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

const CDbName = "goSignalsMem"
const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"

const CEnvMemDir = "MEM_DIRECTORY"
const CEnvMemSaveRate = "MEM_SAVE_RATE"
const CDefMemSaveRate = 30

var pLog = logger.Sub("MEMORY_DB")

// MemoryProvider provides an in-memory implementation using DAOs and services
type MemoryProvider struct {
	*common.BaseProvider

	DbUrl  string
	DbName string
	dbInit bool

	DefaultIssuer string
	TokenIssuer   string

	// Cluster coordination — owned by a MemoryCoordinator value-typed field.
	coordinator *MemoryCoordinator

	mu sync.RWMutex

	// Persistence
	persistence *PersistenceManager
}

// Coordinator returns the in-process MemoryCoordinator. Always non-nil after
// initialize/Open completes.
func (m *MemoryProvider) Coordinator() cluster.ClusterCoordinator {
	return m.coordinator
}

func (m *MemoryProvider) StoreExternalKey(keyName string, kids []string, streamID string, use string, jwksUri string) error {
	// TODO implement me
	panic("implement me")
}

func (m *MemoryProvider) Name() string {
	return m.DbName
}

func (m *MemoryProvider) initialize() {
	pLog.Info("Initializing new in-memory database", "dbName", m.DbName)

	if m.coordinator == nil {
		m.coordinator = NewMemoryCoordinator()
	}

	// Initialize DAOs
	streamDAO := memory.NewStreamDAO()
	eventDAO := memory.NewEventDAO()
	keyDAO := memory.NewKeyDAO()
	clientDAO := memory.NewClientDAO()
	serverDAO := memory.NewServerDAO()
	tokenDAO := memory.NewTokenDAO()

	// Initialize Services
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

	// Initialize token keys
	ctx := context.Background()
	err := keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
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
	// Create new DAOs to reset all data
	streamDAO := memory.NewStreamDAO()
	eventDAO := memory.NewEventDAO()
	keyDAO := memory.NewKeyDAO()
	clientDAO := memory.NewClientDAO()
	serverDAO := memory.NewServerDAO()
	tokenDAO := memory.NewTokenDAO()

	if initialize {
		// Re-initialize services with new DAOs
		tokenService := services.NewTokenService(tokenDAO)
		keyService := services.NewKeyService(keyDAO, m.TokenIssuer, tokenService)
		streamService := services.NewStreamService(streamDAO, keyService, m.DefaultIssuer)
		eventService := services.NewEventService(eventDAO)
		clientService := services.NewClientService(clientDAO, keyService)
		serverService := services.NewServerService(serverDAO)

		// Reinitialize BaseProvider
		m.BaseProvider = common.NewBaseProvider(
			streamDAO, eventDAO, keyDAO, clientDAO, serverDAO, tokenDAO,
			keyService, streamService, eventService, clientService, serverService, tokenService,
		)

		ctx := context.Background()
		err := keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
		if err != nil {
			pLog.Error("Error reinitializing token key", "error", err)
		}

		// Recreate persistence with new BaseProvider
		if m.persistence != nil {
			memDir := m.persistence.directory
			saveRate := m.persistence.saveRate
			m.persistence.Close()
			m.persistence = NewPersistenceManager(memDir, saveRate, m.BaseProvider)
			m.BaseProvider.SetWriteHook(m.persistence.MarkDirty)
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
		mongoUrl = "memorydb://localhost"
		pLog.Info("Defaulting Memory Database URL", "url", mongoUrl)
	}

	memDir, _ := os.LookupEnv(CEnvMemDir)
	if memDir == "" {
		memDir = filepath.Join("config", dbName)
	}

	saveRate := CDefMemSaveRate
	if rateStr, ok := os.LookupEnv(CEnvMemSaveRate); ok {
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

	// Initialize persistence
	m.persistence = NewPersistenceManager(memDir, saveRate, m.BaseProvider)
	m.BaseProvider.SetWriteHook(m.persistence.MarkDirty)
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
