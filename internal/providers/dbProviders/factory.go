package dbProviders

import (
	"strings"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mock_provider"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
)

// OpenProvider detects the database URL and returns the appropriate provider implementation.
// If the URL starts with "mockdb:", it returns a mock in-memory provider.
// Otherwise, it returns a real MongoDB provider.
func OpenProvider(mongoUrl string, dbName string) (DbProviderInterface, error) {
	if strings.HasPrefix(mongoUrl, "mockdb:") {
		return mock_provider.Open(mongoUrl, dbName)
	}
	return mongo_provider.Open(mongoUrl, dbName)
}
