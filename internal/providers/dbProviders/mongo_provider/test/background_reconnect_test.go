package test

import (
	"os"
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	ssef "github.com/i2-open/i2goSignals/pkg/goSignals/server"
	"github.com/stretchr/testify/assert"
)

// TestNewApplication_BackgroundReconnect verifies that the application can start
// even if the initial MongoDB connection fails, and that it doesn't panic.
func TestNewApplication_BackgroundReconnect(t *testing.T) {
	// Use a non-existent Mongo URL to force a connection failure.
	// serverSelectionTimeoutMS=3000 caps the driver's retry loop so the test fails fast.
	mongoUrl := "mongodb://localhost:27019/nonexistent?serverSelectionTimeoutMS=3000"
	dbName := "test_db_bg_reconnect"

	// Create provider - Open returns an error on initial failure but always returns a
	// valid (non-nil) provider so that background reconnect can proceed.
	p, err := mongo_provider.Open(mongoUrl, dbName)
	assert.Error(t, err)
	assert.NotNil(t, p)
	defer p.Close()

	// Verify it's not initialized yet
	assert.Error(t, p.Check())

	// Create application - this used to panic!
	sa := ssef.NewApplication(p, "https://example.com/")
	assert.NotNil(t, sa)

	// sa.GetAuth() should be non-nil but have no keys
	auth := sa.GetAuth()
	assert.NotNil(t, auth)
	assert.Nil(t, auth.PrivateKey)

	// Shutdown application
	sa.Shutdown()
}

// TestNewApplication_LazyAuthRefresh verifies that sa.GetAuth() correctly
// reflects the updated AuthIssuer once the provider connects.
func TestNewApplication_LazyAuthRefresh(t *testing.T) {
	mongoUrl := os.Getenv("MONGO_URL")
	if mongoUrl == "" {
		mongoUrl = TestDbUrl
	}
	dbName := "test_db_lazy_refresh"

	// Create provider (should connect successfully)
	p, err := mongo_provider.Open(mongoUrl, dbName)
	if err != nil {
		t.Skip("Mongo not available for this test")
	}
	defer p.Close()

	// Initially connected
	assert.NoError(t, p.Check())

	// Create application
	sa := ssef.NewApplication(p, "https://example.com/")
	assert.NotNil(t, sa)

	// sa.Auth should have a private key
	auth1 := sa.GetAuth()
	assert.NotNil(t, auth1)
	assert.NotNil(t, auth1.PrivateKey)

	// Simulate a "reset" which replaces the internal BaseProvider and AuthIssuer
	err = p.ResetDb(true)
	assert.NoError(t, err)

	// sa.GetAuth() should now return a different (new) AuthIssuer
	auth2 := sa.GetAuth()
	assert.NotNil(t, auth2)
	assert.NotSame(t, auth1, auth2)
	assert.NotNil(t, auth2.PrivateKey)

	sa.Shutdown()
}
