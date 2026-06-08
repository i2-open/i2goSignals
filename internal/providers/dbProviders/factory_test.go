package dbProviders

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
)

// assertDedupParity exercises the slice #156 cross-provider parity check: a
// double-AddEvent on the same JTI must return interfaces.ErrDuplicateJTI on
// the second call. The Persistence record's EventService is wired to the
// underlying provider's EventDAO, so a green assertion proves the dedup
// sentinel propagates correctly through the composition root for this
// variant.
func assertDedupParity(t *testing.T, p *Persistence) {
	t.Helper()
	ctx := context.Background()
	evt := &goSet.SecurityEventToken{Events: map[string]interface{}{"x": "y"}}
	evt.ID = "dedup-parity-jti"
	_, err := p.EventService.AddEvent(ctx, evt, "stream-x", "raw-1")
	assert.NoError(t, err, "first AddEvent should succeed")
	_, err2 := p.EventService.AddEvent(ctx, evt, "stream-x", "raw-2")
	assert.True(t, errors.Is(err2, interfaces.ErrDuplicateJTI),
		"second AddEvent should return ErrDuplicateJTI, got %v", err2)
}

// TestOpenPersistence_Memory exercises the composition root: the memory
// adapter must produce a complete Persistence (services + Coordinator +
// Storage) so callers can depend on the narrowest seam they need.
func TestOpenPersistence_Memory(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	p, err := OpenPersistence("memorydb:", "test_persist_mem")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.StreamService, "StreamService must be set")
	assert.NotNil(t, p.KeyService, "KeyService must be set")
	assert.NotNil(t, p.EventService, "EventService must be set")
	assert.NotNil(t, p.ClientService, "ClientService must be set")
	assert.NotNil(t, p.ServerService, "ServerService must be set")
	assert.NotNil(t, p.TokenService, "TokenService must be set")
	assert.NotNil(t, p.SubjectFilterService, "SubjectFilterService must be set")
	assert.NotNil(t, p.SubjectRelayService, "SubjectRelayService must be set")
	assert.NotNil(t, p.Coordinator, "Coordinator must be set")
	assert.NotNil(t, p.Storage, "Storage must be set")

	// Coordinator seam exercises the real (non-stub) MemoryCoordinator.
	ok, _, err := p.Coordinator.TryAcquireOrRenewLease("smoke", "node-A", 5_000_000_000)
	assert.NoError(t, err)
	assert.True(t, ok, "MemoryCoordinator should grant first acquire")

	// events-dedup parity: confirms the EventService wired into the memory
	// provider surfaces interfaces.ErrDuplicateJTI on a duplicate JTI.
	assertDedupParity(t, p)

	_ = p.Storage.Close()
}

// TestOpenPersistence_Fallback proves the Mongo→memory fallback returns a
// complete Persistence record (the same shape as a direct memory open).
func TestOpenPersistence_Fallback(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))
	wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=1000"

	p, err := OpenPersistence(wrongUrl, "test_persist_fallback")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.StreamService)
	assert.NotNil(t, p.Coordinator)
	assert.NotNil(t, p.Storage)

	// events-dedup parity: the fallback variant must propagate the dedup
	// sentinel through the underlying memory EventDAO.
	assertDedupParity(t, p)

	_ = p.Storage.Close()
}

// TestOpenPersistence_FailToMemFalse_Legacy confirms the deprecated
// MONGO_FAILTOMEM=FALSE name still surfaces the Mongo error instead of
// falling back. Coverage of the new I2SIG_STORE_MONGO_FALLBACK_MEM name
// lives in factory_envcompat_test.go.
func TestOpenPersistence_FailToMemFalse_Legacy(t *testing.T) {
	t.Setenv("MONGO_FAILTOMEM", "FALSE")
	t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))

	wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=100"
	p, err := OpenPersistence(wrongUrl, "test_fail")
	assert.Error(t, err, "Deprecated MONGO_FAILTOMEM=FALSE must still surface the connection error")
	assert.Nil(t, p, "Persistence should be nil on failure")
}