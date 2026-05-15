package eventRouter

import (
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

// Slice #68 tracer: LoadRecoveryConfig must read the renamed PUSH env vars
// through envcompat so the new I2SIG_PUSH_AUTH_RETRY_* names win and the
// legacy I2SIG_PUSH_UNAUTHORIZED_RETRY_* names still work as fallback.
// Same pattern applies to I2SIG_PUSH_PROBE_INTERVAL (was STATUS_CHECK_INTERVAL).

func TestLoadRecoveryConfig_NewPushNames_TakePrecedence(t *testing.T) {
    t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", "7s")
    t.Setenv("I2SIG_PUSH_AUTH_RETRY_LIMIT", "3")
    t.Setenv("I2SIG_PUSH_PROBE_INTERVAL", "11s")
    t.Setenv("I2SIG_PUSH_UNAUTHORIZED_RETRY_DELAY", "99s")
    t.Setenv("I2SIG_PUSH_UNAUTHORIZED_RETRY_LIMIT", "99")
    t.Setenv("I2SIG_PUSH_STATUS_CHECK_INTERVAL", "99s")

    cfg := LoadRecoveryConfig()

    assert.Equal(t, 7*time.Second, cfg.AuthRetryDelay)
    assert.Equal(t, 3, cfg.AuthRetryLimit)
    assert.Equal(t, 11*time.Second, cfg.StatusCheckInterval)
}

func TestLoadRecoveryConfig_OldPushNames_StillWork(t *testing.T) {
    t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", "")
    t.Setenv("I2SIG_PUSH_AUTH_RETRY_LIMIT", "")
    t.Setenv("I2SIG_PUSH_PROBE_INTERVAL", "")
    t.Setenv("I2SIG_PUSH_UNAUTHORIZED_RETRY_DELAY", "13s")
    t.Setenv("I2SIG_PUSH_UNAUTHORIZED_RETRY_LIMIT", "4")
    t.Setenv("I2SIG_PUSH_STATUS_CHECK_INTERVAL", "17s")

    cfg := LoadRecoveryConfig()

    assert.Equal(t, 13*time.Second, cfg.AuthRetryDelay)
    assert.Equal(t, 4, cfg.AuthRetryLimit)
    assert.Equal(t, 17*time.Second, cfg.StatusCheckInterval)
}

func TestLoadIdleVerifyInterval_NewKeepaliveName_TakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "23s")
    t.Setenv("I2SIG_PUSH_IDLE_VERIFY_INTERVAL", "99s")

    assert.Equal(t, 23*time.Second, LoadIdleVerifyInterval())
}

func TestLoadIdleVerifyInterval_OldIdleVerifyName_StillWorks(t *testing.T) {
    t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "")
    t.Setenv("I2SIG_PUSH_IDLE_VERIFY_INTERVAL", "29s")

    assert.Equal(t, 29*time.Second, LoadIdleVerifyInterval())
}
