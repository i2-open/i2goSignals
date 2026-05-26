package server

import (
    "strconv"
    "time"

    "github.com/i2-open/i2goSignals/internal/envcompat"
)

// pollConfig holds the exponential-backoff parameters used by the poll-receiver
// loop. Values are read via envcompat so the v0.11.0 I2SIG_POLL_* names take
// precedence over the legacy POLL_* names while still honoring those with a
// one-time deprecation WARN.
type pollConfig struct {
    BaseDelay              float64       // seconds
    MaxDelay               float64       // seconds
    BackoffFactor          float64
    RetryLimit             time.Duration
    StatusCheckInterval    time.Duration
    UnauthorizedRetryDelay time.Duration
    UnauthorizedRetryLimit int
    ForbiddenRetryDelay    time.Duration
    ForbiddenRetryLimit    int
}

func loadPollConfig() pollConfig {
    cfg := pollConfig{
        BaseDelay:              1.0,
        MaxDelay:               300.0,
        BackoffFactor:          2.0,
        RetryLimit:             6 * time.Hour,
        StatusCheckInterval:    30 * time.Second,
        UnauthorizedRetryDelay: 15 * time.Second,
        UnauthorizedRetryLimit: 10,
        ForbiddenRetryDelay:    30 * time.Second,
        ForbiddenRetryLimit:    3,
    }

    if v, err := strconv.ParseFloat(envcompat.Lookup("I2SIG_POLL_RETRY_BASE_DELAY", "POLL_RETRY_BASE_DELAY"), 64); err == nil {
        cfg.BaseDelay = v
    }
    if v, err := strconv.ParseFloat(envcompat.Lookup("I2SIG_POLL_RETRY_MAX_DELAY", "POLL_RETRY_MAX_DELAY"), 64); err == nil {
        cfg.MaxDelay = v
    }
    if v, err := strconv.ParseFloat(envcompat.Lookup("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "POLL_RETRY_BACKOFF_FACTOR"), 64); err == nil {
        cfg.BackoffFactor = v
    }
    if v, err := strconv.ParseFloat(envcompat.Lookup("I2SIG_POLL_RETRY_LIMIT", "POLL_RETRY_LIMIT"), 64); err == nil {
        cfg.RetryLimit = time.Duration(v) * time.Second
    }
    if v, err := strconv.ParseFloat(envcompat.Lookup("I2SIG_POLL_PROBE_INTERVAL", "POLL_STATUS_CHECK_INTERVAL"), 64); err == nil {
        cfg.StatusCheckInterval = time.Duration(v * float64(time.Second))
    }
    if v, err := strconv.ParseFloat(envcompat.Lookup("I2SIG_POLL_AUTH_RETRY_DELAY", "POLL_UNAUTHORIZED_RETRY_DELAY"), 64); err == nil {
        cfg.UnauthorizedRetryDelay = time.Duration(v * float64(time.Second))
    }
    if v, err := strconv.Atoi(envcompat.Lookup("I2SIG_POLL_AUTH_RETRY_LIMIT", "POLL_UNAUTHORIZED_RETRY_LIMIT")); err == nil {
        cfg.UnauthorizedRetryLimit = v
    }
    if v, err := strconv.ParseFloat(envcompat.Lookup("I2SIG_POLL_FORBIDDEN_RETRY_DELAY", "POLL_FORBIDDEN_RETRY_DELAY"), 64); err == nil {
        cfg.ForbiddenRetryDelay = time.Duration(v * float64(time.Second))
    }
    if v, err := strconv.Atoi(envcompat.Lookup("I2SIG_POLL_FORBIDDEN_RETRY_LIMIT", "POLL_FORBIDDEN_RETRY_LIMIT")); err == nil {
        cfg.ForbiddenRetryLimit = v
    }

    return cfg
}

// loadPollRespectStatus reads I2SIG_POLL_RESPECT_STATUS as a boolean, falling
// back to the legacy POLL_SRV_BEHAVIOR string (MODE→true, ALWAYSON→false).
// Defaults to true when unset, matching the legacy "MODE" default. Any other
// legacy value is treated as the default (true).
func loadPollRespectStatus() bool {
    raw := envcompat.LookupWithTranslate(
        "I2SIG_POLL_RESPECT_STATUS",
        "POLL_SRV_BEHAVIOR",
        translatePollBehavior,
    )
    if raw == "" {
        return true
    }
    b, err := strconv.ParseBool(raw)
    if err != nil {
        return true
    }
    return b
}

func translatePollBehavior(legacy string) string {
    switch legacy {
    case "ALWAYSON":
        return "false"
    case "MODE":
        return "true"
    default:
        return ""
    }
}
