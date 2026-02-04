package dbProviders

import (
	"strings"

	"os"

	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
)

var factoryLog = logger.Sub("dbProviders")

// OpenProvider detects the database URL and returns the appropriate provider implementation.
// If the URL starts with "memorydb:" or is empty, it returns an in-memory provider.
// Otherwise, it attempts to return a real MongoDB provider.
func OpenProvider(mongoUrl string, dbName string) (DbProviderInterface, error) {
	if strings.HasPrefix(mongoUrl, "memorydb:") || mongoUrl == "" {
		return memory_provider.Open(mongoUrl, dbName)
	}

	p, err := mongo_provider.Open(mongoUrl, dbName)
	if err == nil {
		// Verify connectivity.
		err = p.Check()
	}

	if err != nil {
		failToMem := strings.ToUpper(os.Getenv("MONGO_FAILTOMEM"))
		if failToMem == "FALSE" {
			factoryLog.Error("Mongo Server connection failed. Exiting.", "error", err)
			return nil, err
		}

		factoryLog.Warn("Mongo Server connection failed, falling back to memory provider", "error", err)
		if p != nil {
			_ = p.Close()
		}
		return memory_provider.Open("memorydb:", dbName)
	}

	return p, nil
}
