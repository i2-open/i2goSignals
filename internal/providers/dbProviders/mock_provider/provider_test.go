package mock_provider

import (
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/stretchr/testify/assert"
)

func TestMockProviderOpen(t *testing.T) {
	provider, err := Open("mockdb://localhost:27017/", "test_db")
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "test_db", provider.Name())

	err = provider.Close()
	assert.NoError(t, err)
}

func TestMockProviderViaFactory(t *testing.T) {
	provider, err := dbProviders.OpenProvider("mockdb:", "test_db")
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "test_db", provider.Name())

	err = provider.Close()
	assert.NoError(t, err)
}

func TestMockProviderRejectNonMockURL(t *testing.T) {
	_, err := Open("mongodb://localhost:27017/", "test_db")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock provider only supports 'mockdb:' URL prefix")
}

func TestMockProviderBasicOperations(t *testing.T) {
	provider, err := Open("mockdb:", "test_db")
	assert.NoError(t, err)
	defer provider.Close()

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

	// Test GetPublicTransmitterJWKS
	jwks := provider.GetPublicTransmitterJWKS("DEFAULT")
	assert.NotNil(t, jwks)
}
