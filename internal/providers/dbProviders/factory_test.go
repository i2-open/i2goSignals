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
