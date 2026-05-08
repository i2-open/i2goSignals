package dbProviders

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestOpenPersistence_Memory exercises the composition root: the memory
// adapter must produce a complete Persistence (services + Coordinator +
// Storage) so callers can depend on the narrowest seam they need.
func TestOpenPersistence_Memory(t *testing.T) {
	t.Setenv("MEM_DIRECTORY", t.TempDir())
	p, err := OpenPersistence("memorydb:", "test_persist_mem")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.StreamService, "StreamService must be set")
	assert.NotNil(t, p.KeyService, "KeyService must be set")
	assert.NotNil(t, p.EventService, "EventService must be set")
	assert.NotNil(t, p.ClientService, "ClientService must be set")
	assert.NotNil(t, p.ServerService, "ServerService must be set")
	assert.NotNil(t, p.TokenService, "TokenService must be set")
	assert.NotNil(t, p.Coordinator, "Coordinator must be set")
	assert.NotNil(t, p.Storage, "Storage must be set")

	// Coordinator seam exercises the real (non-stub) MemoryCoordinator.
	ok, _, err := p.Coordinator.TryAcquireOrRenewLease("smoke", "node-A", 5_000_000_000)
	assert.NoError(t, err)
	assert.True(t, ok, "MemoryCoordinator should grant first acquire")

	_ = p.Storage.Close()
}

// TestOpenPersistence_Fallback proves the Mongo→memory fallback returns a
// complete Persistence record (the same shape as a direct memory open).
func TestOpenPersistence_Fallback(t *testing.T) {
	t.Setenv("MEM_DIRECTORY", t.TempDir())
	wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=1000"

	p, err := OpenPersistence(wrongUrl, "test_persist_fallback")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.StreamService)
	assert.NotNil(t, p.Coordinator)
	assert.NotNil(t, p.Storage)

	_ = p.Storage.Close()
}

// TestOpenPersistence_FailToMemFalse confirms MONGO_FAILTOMEM=FALSE surfaces
// the Mongo error instead of falling back.
func TestOpenPersistence_FailToMemFalse(t *testing.T) {
	t.Setenv("MONGO_FAILTOMEM", "FALSE")

	wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=100"
	p, err := OpenPersistence(wrongUrl, "test_fail")
	assert.Error(t, err, "Should return error when MONGO_FAILTOMEM is FALSE")
	assert.Nil(t, p, "Persistence should be nil on failure")
}