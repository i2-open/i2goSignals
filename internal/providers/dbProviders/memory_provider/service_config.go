package memory_provider

import (
    "net/url"
    "os"
    "strconv"

    "github.com/i2-open/i2goSignals/internal/envcompat"
    "github.com/i2-open/i2goSignals/pkg/services"
)

const CEnvBaseURL = "BASE_URL"

// oauthServersFromEnv resolves the OAuth Authorization Server discovery
// endpoints from the environment, honoring the deprecated OAUTH_SERVERS alias
// (with a one-time deprecation WARN) in favor of I2SIG_AUTH_OAUTH_SERVERS. It
// lives in the wiring tree and is injected into services.KeyService so the
// services package stays free of internal/envcompat.
func oauthServersFromEnv() string {
    return envcompat.Lookup("I2SIG_AUTH_OAUTH_SERVERS", "OAUTH_SERVERS")
}

// streamServiceConfigFromEnv resolves the StreamService operator knobs from the
// environment. The env-var parsing (including the v0.11.0 rename aliases) is a
// wiring-tree concern; the services package receives concrete values via
// services.StreamServiceConfig.
func streamServiceConfigFromEnv() services.StreamServiceConfig {
    cfg := services.StreamServiceConfig{}

    if base, exist := os.LookupEnv(CEnvBaseURL); exist {
        baseUrl, err := url.Parse(base)
        if err != nil {
            pLog.Error("Invalid BASE_URL value", "error", err.Error())
        } else {
            cfg.BaseUrl = baseUrl
        }
    }

    if minVer := envcompat.Lookup("I2SIG_STREAM_MIN_VERIFICATION_INTERVAL", "MIN_VERIFICATION_INTERVAL"); minVer != "" {
        v, err := strconv.Atoi(minVer)
        if err != nil {
            pLog.Error("Invalid I2SIG_STREAM_MIN_VERIFICATION_INTERVAL value", "error", err.Error())
        } else {
            cfg.MinVerificationInterval = v
        }
    }

    if maxInactivityStr := envcompat.Lookup("I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT", "MAX_INACTIVITY_TIMEOUT"); maxInactivityStr != "" {
        v, err := strconv.Atoi(maxInactivityStr)
        if err != nil {
            pLog.Error("Invalid I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT value", "error", err.Error())
        } else {
            cfg.MaxInactivityTimeout = v
        }
    }

    return cfg
}
