package dbProviders

import (
	"strings"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/internal/providers/storage"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

var factoryLog = logger.Sub("dbProviders")

// Persistence is the composition root the server uses for everything that
// ultimately reaches the database. After PRD #39 it bundles the per-domain
// services, the cluster coordinator, and the lifecycle storage seam — no
// more god-interface façade.
//
// Callers that only need one concern should depend on the narrowest type
// available (one service, or Coordinator, or Storage).
type Persistence struct {
	StreamService *services.StreamService
	KeyService    *services.KeyService
	EventService  *services.EventService
	ClientService *services.ClientService
	ServerService *services.ServerService
	TokenService  *services.TokenService

	Coordinator cluster.ClusterCoordinator
	Storage     storage.Storage

	// src is the underlying provider used to refresh service references
	// after a Storage.ResetDb(true) call. The memory adapter rebuilds its
	// services on reset; without Refresh the cached service pointers above
	// would dangle. Mongo's reconnect rebinds in place so Refresh is a no-op
	// there.
	src serviceSource
}

// Refresh re-pulls the per-domain service references from the underlying
// provider. Call this after Storage.ResetDb(true) on the in-memory adapter
// (the only path that swaps service instances on reset).
func (p *Persistence) Refresh() {
	if p == nil || p.src == nil {
		return
	}
	p.StreamService = p.src.GetStreamService()
	p.KeyService = p.src.GetKeyService()
	p.EventService = p.src.GetEventService()
	p.ClientService = p.src.GetClientService()
	p.ServerService = p.src.GetServerService()
	p.TokenService = p.src.GetTokenService()
}

// serviceSource is the accessor surface present on both *MemoryProvider and
// *MongoProvider. Both expose per-domain service getters; we use this to
// hydrate the Persistence record without importing the concrete provider
// packages from anywhere else.
type serviceSource interface {
	GetStreamService() *services.StreamService
	GetKeyService() *services.KeyService
	GetEventService() *services.EventService
	GetClientService() *services.ClientService
	GetServerService() *services.ServerService
	GetTokenService() *services.TokenService
}

// OpenPersistence detects the database URL and returns the Persistence record
// (services + Coordinator + Storage).
func OpenPersistence(mongoUrl string, dbName string) (*Persistence, error) {
	if strings.HasPrefix(mongoUrl, "memorydb:") || mongoUrl == "" {
		mp, err := memory_provider.Open(mongoUrl, dbName)
		if err != nil {
			return nil, err
		}
		return persistenceFromMemory(mp), nil
	}

	mp, err := mongo_provider.Open(mongoUrl, dbName)
	if err != nil {
		if strings.ToUpper(envcompat.Lookup("I2SIG_STORE_MONGO_BACKGROUND_RECONNECT", "MONGO_BACKGROUND_RECONNECT")) == "TRUE" {
			factoryLog.Warn("Mongo connection failed. Background reconnect enabled.", "error", err)
			return persistenceFromMongo(mp), nil
		}

		failToMem := strings.ToUpper(envcompat.Lookup("I2SIG_STORE_MONGO_FALLBACK_MEM", "MONGO_FAILTOMEM"))
		if failToMem == "FALSE" {
			factoryLog.Error("Mongo Server connection failed. Exiting.", "error", err)
			return nil, err
		}

		factoryLog.Warn("Mongo Server connection failed, falling back to memory provider", "error", err)
		if mp != nil {
			_ = mp.Close()
		}
		fb, ferr := memory_provider.Open("memorydb:", dbName)
		if ferr != nil {
			return nil, ferr
		}
		return persistenceFromMemory(fb), nil
	}

	return persistenceFromMongo(mp), nil
}

func persistenceFromMemory(mp *memory_provider.MemoryProvider) *Persistence {
	return &Persistence{
		StreamService: mp.GetStreamService(),
		KeyService:    mp.GetKeyService(),
		EventService:  mp.GetEventService(),
		ClientService: mp.GetClientService(),
		ServerService: mp.GetServerService(),
		TokenService:  mp.GetTokenService(),
		Coordinator:   mp.Coordinator(),
		Storage:       memory_provider.NewMemoryStorage(mp),
		src:           mp,
	}
}

func persistenceFromMongo(mp *mongo_provider.MongoProvider) *Persistence {
	var svcSrc serviceSource = mp
	return &Persistence{
		StreamService: svcSrc.GetStreamService(),
		KeyService:    svcSrc.GetKeyService(),
		EventService:  svcSrc.GetEventService(),
		ClientService: svcSrc.GetClientService(),
		ServerService: svcSrc.GetServerService(),
		TokenService:  svcSrc.GetTokenService(),
		Coordinator:   mp.Coordinator(),
		Storage:       mongo_provider.NewMongoStorage(mp),
		src:           mp,
	}
}