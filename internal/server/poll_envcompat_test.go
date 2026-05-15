package server

import (
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

// Slice #68 tracer: poll-receiver loop must read its retry config through
// envcompat. The new I2SIG_POLL_* names take precedence; legacy POLL_* names
// still work as a deprecated fallback.

func TestLoadPollConfig_NewPollNames_TakePrecedence(t *testing.T) {
    t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "2")
    t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "200")
    t.Setenv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "3")
    t.Setenv("I2SIG_POLL_RETRY_LIMIT", "120")
    t.Setenv("I2SIG_POLL_PROBE_INTERVAL", "7")
    t.Setenv("I2SIG_POLL_AUTH_RETRY_DELAY", "9")
    t.Setenv("I2SIG_POLL_AUTH_RETRY_LIMIT", "5")
    t.Setenv("POLL_RETRY_BASE_DELAY", "99")
    t.Setenv("POLL_RETRY_MAX_DELAY", "99")
    t.Setenv("POLL_RETRY_BACKOFF_FACTOR", "99")
    t.Setenv("POLL_RETRY_LIMIT", "99")
    t.Setenv("POLL_STATUS_CHECK_INTERVAL", "99")
    t.Setenv("POLL_UNAUTHORIZED_RETRY_DELAY", "99")
    t.Setenv("POLL_UNAUTHORIZED_RETRY_LIMIT", "99")

    cfg := loadPollConfig()

    assert.Equal(t, 2.0, cfg.BaseDelay)
    assert.Equal(t, 200.0, cfg.MaxDelay)
    assert.Equal(t, 3.0, cfg.BackoffFactor)
    assert.Equal(t, 120*time.Second, cfg.RetryLimit)
    assert.Equal(t, 7*time.Second, cfg.StatusCheckInterval)
    assert.Equal(t, 9*time.Second, cfg.UnauthorizedRetryDelay)
    assert.Equal(t, 5, cfg.UnauthorizedRetryLimit)
}

func TestLoadPollConfig_OldPollNames_StillWork(t *testing.T) {
    t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "")
    t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "")
    t.Setenv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "")
    t.Setenv("I2SIG_POLL_RETRY_LIMIT", "")
    t.Setenv("I2SIG_POLL_PROBE_INTERVAL", "")
    t.Setenv("I2SIG_POLL_AUTH_RETRY_DELAY", "")
    t.Setenv("I2SIG_POLL_AUTH_RETRY_LIMIT", "")
    t.Setenv("POLL_RETRY_BASE_DELAY", "4")
    t.Setenv("POLL_RETRY_MAX_DELAY", "400")
    t.Setenv("POLL_RETRY_BACKOFF_FACTOR", "6")
    t.Setenv("POLL_RETRY_LIMIT", "60")
    t.Setenv("POLL_STATUS_CHECK_INTERVAL", "8")
    t.Setenv("POLL_UNAUTHORIZED_RETRY_DELAY", "12")
    t.Setenv("POLL_UNAUTHORIZED_RETRY_LIMIT", "7")

    cfg := loadPollConfig()

    assert.Equal(t, 4.0, cfg.BaseDelay)
    assert.Equal(t, 400.0, cfg.MaxDelay)
    assert.Equal(t, 6.0, cfg.BackoffFactor)
    assert.Equal(t, 60*time.Second, cfg.RetryLimit)
    assert.Equal(t, 8*time.Second, cfg.StatusCheckInterval)
    assert.Equal(t, 12*time.Second, cfg.UnauthorizedRetryDelay)
    assert.Equal(t, 7, cfg.UnauthorizedRetryLimit)
}

func TestLoadPollConfig_Defaults(t *testing.T) {
    t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "")
    t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "")
    t.Setenv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "")
    t.Setenv("I2SIG_POLL_RETRY_LIMIT", "")
    t.Setenv("I2SIG_POLL_PROBE_INTERVAL", "")
    t.Setenv("I2SIG_POLL_AUTH_RETRY_DELAY", "")
    t.Setenv("I2SIG_POLL_AUTH_RETRY_LIMIT", "")
    t.Setenv("POLL_RETRY_BASE_DELAY", "")
    t.Setenv("POLL_RETRY_MAX_DELAY", "")
    t.Setenv("POLL_RETRY_BACKOFF_FACTOR", "")
    t.Setenv("POLL_RETRY_LIMIT", "")
    t.Setenv("POLL_STATUS_CHECK_INTERVAL", "")
    t.Setenv("POLL_UNAUTHORIZED_RETRY_DELAY", "")
    t.Setenv("POLL_UNAUTHORIZED_RETRY_LIMIT", "")

    cfg := loadPollConfig()

    assert.Equal(t, 1.0, cfg.BaseDelay)
    assert.Equal(t, 300.0, cfg.MaxDelay)
    assert.Equal(t, 2.0, cfg.BackoffFactor)
    assert.Equal(t, 6*time.Hour, cfg.RetryLimit)
    assert.Equal(t, 30*time.Second, cfg.StatusCheckInterval)
    assert.Equal(t, 15*time.Second, cfg.UnauthorizedRetryDelay)
    assert.Equal(t, 10, cfg.UnauthorizedRetryLimit)
}
