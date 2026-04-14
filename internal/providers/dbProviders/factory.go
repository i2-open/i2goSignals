package dbProviders

import (
	"strings"

	"os"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/pkg/logger"
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
	if err != nil {
		if strings.ToUpper(os.Getenv("MONGO_BACKGROUND_RECONNECT")) == "TRUE" {
			factoryLog.Warn("Mongo connection failed. Background reconnect enabled.", "error", err)
			return p, nil
		}

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
