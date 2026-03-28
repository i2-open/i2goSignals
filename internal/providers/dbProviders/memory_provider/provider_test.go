package memory_provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryProviderOpen(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv(CEnvMemDir, tmpDir)

	provider, err := Open("memorydb://localhost", "test_db")
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "test_db", provider.Name())

	err = provider.Close()
	assert.NoError(t, err)
}

func TestMemoryProviderViaFactory(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv(CEnvMemDir, tmpDir)

	provider, err := Open("memorydb:", "test_db")
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "test_db", provider.Name())

	err = provider.Close()
	assert.NoError(t, err)
}

func TestMemoryProviderRejectNonMemoryURL(t *testing.T) {
	_, err := Open("mongodb://localhost:27017/", "test_db")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "memory provider only supports 'memorydb:' URL prefix")
}

func TestMemoryProviderBasicOperations(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv(CEnvMemDir, tmpDir)

	provider, err := Open("memorydb:", "test_db")
	assert.NoError(t, err)
	defer func(provider *MemoryProvider) {
		_ = provider.Close()
	}(provider)

	// Test ResetDb
	err = provider.ResetDb(true)
	assert.NoError(t, err)

	// Test Check
	err = provider.Check()
	assert.NoError(t, err)

	// Test ListStreams (should be empty initially)
	streams := provider.ListStreams()
	assert.Empty(t, streams)

	// Test GetAuthIssuer
	authIssuer := provider.GetAuthIssuer()
	assert.NotNil(t, authIssuer)
	assert.NotNil(t, authIssuer.PrivateKey)

	// Test GetPublicJWKS
	jwks := provider.GetPublicJWKS("DEFAULT")
	assert.NotNil(t, jwks)
}
