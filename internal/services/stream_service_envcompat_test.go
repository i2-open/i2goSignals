package services

import (
    "testing"
)

// Wiring tracer for slice #66: NewStreamService must read STREAM env vars
// through envcompat so the old, undecorated names still configure the
// service (with a deprecation WARN, asserted in envcompat's own tests),
// and the new I2SIG_STREAM_* names take precedence when both are set.

func TestNewStreamService_StreamEnvVars_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_STREAM_MIN_VERIFICATION_INTERVAL", "")
    t.Setenv("I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT", "")
    t.Setenv("MIN_VERIFICATION_INTERVAL", "42")
    t.Setenv("MAX_INACTIVITY_TIMEOUT", "84")

    svc := NewStreamService(nil, nil, "")

    if svc.minVerificationInterval != 42 {
        t.Errorf("minVerificationInterval = %d, want 42 (deprecated MIN_VERIFICATION_INTERVAL should still work)", svc.minVerificationInterval)
    }
    if svc.maxInactivityTimeout != 84 {
        t.Errorf("maxInactivityTimeout = %d, want 84 (deprecated MAX_INACTIVITY_TIMEOUT should still work)", svc.maxInactivityTimeout)
    }
}

func TestNewStreamService_StreamEnvVars_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_STREAM_MIN_VERIFICATION_INTERVAL", "99")
    t.Setenv("I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT", "999")
    t.Setenv("MIN_VERIFICATION_INTERVAL", "42")
    t.Setenv("MAX_INACTIVITY_TIMEOUT", "84")

    svc := NewStreamService(nil, nil, "")

    if svc.minVerificationInterval != 99 {
        t.Errorf("minVerificationInterval = %d, want 99 (new I2SIG_STREAM_MIN_VERIFICATION_INTERVAL must win)", svc.minVerificationInterval)
    }
    if svc.maxInactivityTimeout != 999 {
        t.Errorf("maxInactivityTimeout = %d, want 999 (new I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT must win)", svc.maxInactivityTimeout)
    }
}
