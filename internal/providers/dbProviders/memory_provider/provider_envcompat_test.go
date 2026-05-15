package memory_provider

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

// Slice #66 tracer: Open() must read I2SIG_ISSUER_DEFAULT /
// I2SIG_ISSUER_TOKEN through envcompat so the deprecated I2SIG_ISSUER /
// I2SIG_TOKEN_ISSUER names still configure the provider (with a
// deprecation WARN, asserted in envcompat's own tests), and the new
// names take precedence when both are set.

func TestMemoryProviderOpen_IssuerEnvVars_OldNameStillWorks(t *testing.T) {
    t.Setenv(CEnvMemDir, t.TempDir())
    t.Setenv("I2SIG_ISSUER_DEFAULT", "")
    t.Setenv("I2SIG_ISSUER_TOKEN", "")
    t.Setenv("I2SIG_ISSUER", "https://legacy.example.com")
    t.Setenv("I2SIG_TOKEN_ISSUER", "legacy-token-issuer")

    provider, err := Open("memorydb://localhost", "test_db")
    assert.NoError(t, err)
    defer provider.Close()

    assert.Equal(t, "https://legacy.example.com", provider.DefaultIssuer,
        "deprecated I2SIG_ISSUER should still set DefaultIssuer")
    assert.Equal(t, "legacy-token-issuer", provider.TokenIssuer,
        "deprecated I2SIG_TOKEN_ISSUER should still set TokenIssuer")
}

func TestMemoryProviderOpen_IssuerEnvVars_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv(CEnvMemDir, t.TempDir())
    t.Setenv("I2SIG_ISSUER_DEFAULT", "https://new.example.com")
    t.Setenv("I2SIG_ISSUER_TOKEN", "new-token-issuer")
    t.Setenv("I2SIG_ISSUER", "https://legacy.example.com")
    t.Setenv("I2SIG_TOKEN_ISSUER", "legacy-token-issuer")

    provider, err := Open("memorydb://localhost", "test_db")
    assert.NoError(t, err)
    defer provider.Close()

    assert.Equal(t, "https://new.example.com", provider.DefaultIssuer,
        "new I2SIG_ISSUER_DEFAULT must win over deprecated I2SIG_ISSUER")
    assert.Equal(t, "new-token-issuer", provider.TokenIssuer,
        "new I2SIG_ISSUER_TOKEN must win over deprecated I2SIG_TOKEN_ISSUER")
}
