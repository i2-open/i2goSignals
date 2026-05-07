package dbProviders

import (
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	"github.com/stretchr/testify/assert"
)

func TestOpenProvider_Fallback(t *testing.T) {
	t.Setenv("MEM_DIRECTORY", t.TempDir())
	// Use a wrong Mongo URL that will fail to connect
	wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=1000"

	p, err := OpenProvider(wrongUrl, "test_fallback")
	assert.NoError(t, err, "OpenProvider should not return error on fallback")
	assert.NotNil(t, p, "Provider should not be nil")

	_, isMem := p.(*memory_provider.MemoryProvider)
	assert.True(t, isMem, "Should have fallen back to memory provider")

	_ = p.Close()
}

func TestOpenProvider_Memory(t *testing.T) {
	t.Setenv("MEM_DIRECTORY", t.TempDir())
	p, err := OpenProvider("memorydb:", "test_mem")
	assert.NoError(t, err)

	_, isMem := p.(*memory_provider.MemoryProvider)
	assert.True(t, isMem, "Should be memory provider")

	_ = p.Close()
}

func TestOpenProvider_EmptyUrl(t *testing.T) {
	t.Setenv("MEM_DIRECTORY", t.TempDir())
	p, err := OpenProvider("", "test_empty")
	assert.NoError(t, err)

	_, isMem := p.(*memory_provider.MemoryProvider)
	assert.True(t, isMem, "Should be memory provider when URL is empty")

	_ = p.Close()
}

func TestOpenProvider_FailToMemFalse(t *testing.T) {
	t.Setenv("MONGO_FAILTOMEM", "FALSE")

	wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=100"
	p, err := OpenProvider(wrongUrl, "test_fail")
	assert.Error(t, err, "Should return error when MONGO_FAILTOMEM is FALSE")
	assert.Nil(t, p, "Provider should be nil on failure")
}

// TestOpenPersistence_Memory exercises the composition root: the memory
// adapter must produce a complete Persistence (Provider + Coordinator +
// Storage) so callers can depend on the narrowest seam they need.
func TestOpenPersistence_Memory(t *testing.T) {
	t.Setenv("MEM_DIRECTORY", t.TempDir())
	p, err := OpenPersistence("memorydb:", "test_persist_mem")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.Provider, "Provider must be set")
	assert.NotNil(t, p.Coordinator, "Coordinator must be set")
	assert.NotNil(t, p.Storage, "Storage must be set")

	// Storage seam reports the same name as the underlying provider.
	assert.Equal(t, p.Provider.Name(), p.Storage.Name())

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
	assert.NotNil(t, p.Provider)
	assert.NotNil(t, p.Coordinator)
	assert.NotNil(t, p.Storage)

	_ = p.Storage.Close()
}
