package memory_provider

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

// Slice #67 tracer: MEM_DIRECTORY → I2SIG_STORE_MEM_DIRECTORY and
// MEM_SAVE_RATE → I2SIG_STORE_MEM_SAVE_RATE must read through envcompat
// so the deprecated names still work and the new names take precedence.

func TestMemoryProviderOpen_MemDir_NewNameWins(t *testing.T) {
    newDir := t.TempDir()
    oldDir := t.TempDir()
    t.Setenv("I2SIG_STORE_MEM_DIRECTORY", newDir)
    t.Setenv("MEM_DIRECTORY", oldDir)

    p, err := Open("memorydb:", "mem_test_newwins")
    assert.NoError(t, err)
    defer p.Close()
    assert.Equal(t, newDir, p.persistence.directory, "new I2SIG_STORE_MEM_DIRECTORY must win")
}

func TestMemoryProviderOpen_MemDir_OldNameStillWorks(t *testing.T) {
    oldDir := t.TempDir()
    t.Setenv("I2SIG_STORE_MEM_DIRECTORY", "")
    t.Setenv("MEM_DIRECTORY", oldDir)

    p, err := Open("memorydb:", "mem_test_oldworks")
    assert.NoError(t, err)
    defer p.Close()
    assert.Equal(t, oldDir, p.persistence.directory, "deprecated MEM_DIRECTORY must still configure persistence directory")
}

func TestMemoryProviderOpen_MemSaveRate_NewNameWins(t *testing.T) {
    t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
    t.Setenv("I2SIG_STORE_MEM_SAVE_RATE", "77")
    t.Setenv("MEM_SAVE_RATE", "11")

    p, err := Open("memorydb:", "mem_test_rate_new")
    assert.NoError(t, err)
    defer p.Close()
    assert.Equal(t, 77, p.persistence.saveRate, "new I2SIG_STORE_MEM_SAVE_RATE must win")
}

func TestMemoryProviderOpen_MemSaveRate_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
    t.Setenv("I2SIG_STORE_MEM_SAVE_RATE", "")
    t.Setenv("MEM_SAVE_RATE", "11")

    p, err := Open("memorydb:", "mem_test_rate_old")
    assert.NoError(t, err)
    defer p.Close()
    assert.Equal(t, 11, p.persistence.saveRate, "deprecated MEM_SAVE_RATE must still configure saveRate")
}

func TestMemoryProvider_MemDirConstantIsNewName(t *testing.T) {
    assert.Equal(t, "I2SIG_STORE_MEM_DIRECTORY", CEnvMemDir)
    assert.Equal(t, "I2SIG_STORE_MEM_SAVE_RATE", CEnvMemSaveRate)
}
