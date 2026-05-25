package dbProviders

import (
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/assert"
)

// Wiring tracer for slice #67: factory env vars must read through
// envcompat so the new I2SIG_STORE_MONGO_* names work *and* legacy
// MONGO_FAILTOMEM / MONGO_BACKGROUND_RECONNECT continue to function.

// TestOpenPersistence_NewFailToMemFalse asserts the new
// I2SIG_STORE_MONGO_FALLBACK_MEM=FALSE surfaces a connection error
// instead of falling back to memory, matching the legacy semantics
// of MONGO_FAILTOMEM=FALSE.
func TestOpenPersistence_NewFailToMemFalse(t *testing.T) {
    t.Setenv("I2SIG_STORE_MONGO_FALLBACK_MEM", "FALSE")
    t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))

    wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=100"
    p, err := OpenPersistence(wrongUrl, "test_fail_new")
    assert.Error(t, err, "Should return error when I2SIG_STORE_MONGO_FALLBACK_MEM is FALSE")
    assert.Nil(t, p, "Persistence should be nil on failure")
}

// TestOpenPersistence_NewBackgroundReconnect asserts the new
// I2SIG_STORE_MONGO_BACKGROUND_RECONNECT=TRUE keeps OpenPersistence
// returning a Persistence (no error) when Mongo is unreachable, so the
// background reconnect loop can take over.
func TestOpenPersistence_NewBackgroundReconnect(t *testing.T) {
    t.Setenv("I2SIG_STORE_MONGO_BACKGROUND_RECONNECT", "TRUE")
    t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))

    wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=100"
    p, err := OpenPersistence(wrongUrl, "test_bg_new")
    assert.NoError(t, err, "Background reconnect must swallow the initial connect error")
    assert.NotNil(t, p, "Persistence must be returned so background reconnect can drive it")
    if p != nil {
        _ = p.Storage.Close()
    }
}
