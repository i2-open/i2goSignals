package memory_provider

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

// Slice #67 tracer: Open() must read I2SIG_STORE_MONGO_DBNAME through
// envcompat so the deprecated I2SIG_DBNAME still configures the database
// name and the new name takes precedence when both are set. The constant
// CEnvDbName must already be the new name so any consumer reaching for it
// gets the canonical v0.11.0 spelling.

func TestMemoryProviderOpen_DbName_NewNameWins(t *testing.T) {
    t.Setenv(CEnvMemDir, t.TempDir())
    t.Setenv("I2SIG_STORE_MONGO_DBNAME", "new_db_name")
    t.Setenv("I2SIG_DBNAME", "legacy_db_name")

    p, err := Open("memorydb:", "")
    assert.NoError(t, err)
    defer p.Close()
    assert.Equal(t, "new_db_name", p.DbName, "new I2SIG_STORE_MONGO_DBNAME must win over deprecated I2SIG_DBNAME")
}

func TestMemoryProviderOpen_DbName_OldNameStillWorks(t *testing.T) {
    t.Setenv(CEnvMemDir, t.TempDir())
    t.Setenv("I2SIG_STORE_MONGO_DBNAME", "")
    t.Setenv("I2SIG_DBNAME", "legacy_db_name")

    p, err := Open("memorydb:", "")
    assert.NoError(t, err)
    defer p.Close()
    assert.Equal(t, "legacy_db_name", p.DbName, "deprecated I2SIG_DBNAME must still configure DbName")
}

func TestMemoryProviderOpen_DbName_ConstantIsNewName(t *testing.T) {
    assert.Equal(t, "I2SIG_STORE_MONGO_DBNAME", CEnvDbName, "CEnvDbName constant must use the v0.11.0 name")
}
