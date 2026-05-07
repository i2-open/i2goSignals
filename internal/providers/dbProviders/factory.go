package dbProviders

import (
	"strings"

	"os"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/internal/providers/storage"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

var factoryLog = logger.Sub("dbProviders")

// Persistence is the composition root the server uses for everything that
// ultimately reaches the database. It bundles the legacy provider façade
// (still required while DbProviderInterface is alive — slice 4 deletes it),
// the cluster coordinator, and the lifecycle storage seam.
//
// Callers that only need one concern should depend on the narrowest type
// available (Coordinator or Storage), not on Provider.
type Persistence struct {
	Provider    DbProviderInterface
	Coordinator cluster.ClusterCoordinator
	Storage     storage.Storage
}

// OpenProvider preserves the original signature for callers that still
// expect just a DbProviderInterface. New callers should prefer
// OpenPersistence.
func OpenProvider(mongoUrl string, dbName string) (DbProviderInterface, error) {
	p, err := OpenPersistence(mongoUrl, dbName)
	if err != nil {
		return nil, err
	}
	return p.Provider, nil
}

// OpenPersistence detects the database URL and returns the full Persistence
// record (Provider + Coordinator + Storage).
func OpenPersistence(mongoUrl string, dbName string) (*Persistence, error) {
	if strings.HasPrefix(mongoUrl, "memorydb:") || mongoUrl == "" {
		mp, err := memory_provider.Open(mongoUrl, dbName)
		if err != nil {
			return nil, err
		}
		return &Persistence{
			Provider:    mp,
			Coordinator: mp.Coordinator(),
			Storage:     memory_provider.NewMemoryStorage(mp),
		}, nil
	}

	mp, err := mongo_provider.Open(mongoUrl, dbName)
	if err != nil {
		if strings.ToUpper(os.Getenv("MONGO_BACKGROUND_RECONNECT")) == "TRUE" {
			factoryLog.Warn("Mongo connection failed. Background reconnect enabled.", "error", err)
			return &Persistence{
				Provider:    mp,
				Coordinator: mp.Coordinator(),
				Storage:     mongo_provider.NewMongoStorage(mp),
			}, nil
		}

		failToMem := strings.ToUpper(os.Getenv("MONGO_FAILTOMEM"))
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
		return &Persistence{
			Provider:    fb,
			Coordinator: fb.Coordinator(),
			Storage:     memory_provider.NewMemoryStorage(fb),
		}, nil
	}

	return &Persistence{
		Provider:    mp,
		Coordinator: mp.Coordinator(),
		Storage:     mongo_provider.NewMongoStorage(mp),
	}, nil
}
