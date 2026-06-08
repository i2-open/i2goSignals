package test

import (
    "os"
    "testing"
)

// TestMain caps the long-poll default timeout for the whole package. The poll
// transmitter and the SSTP server endpoint both block for the resolved
// I2SIG_POLL_DEFAULT_TIMEOUT (production default 30s) when a request neither
// sets returnImmediately nor carries its own TimeoutSecs. No test in this
// package exercises a long hold for its own sake, so a 1s floor caps any
// accidental wait at 1s instead of 30s. Tests that assert a specific hold
// duration pass an explicit per-request TimeoutSecs, which is unaffected by
// this default.
func TestMain(m *testing.M) {
    if os.Getenv("I2SIG_POLL_DEFAULT_TIMEOUT") == "" {
        _ = os.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "1")
    }
    // SignalsApplication.Shutdown() drains for I2SIG_SHUTDOWN_DRAIN seconds per
    // phase (production default 1s => ~2s total). This package spins up and tears
    // down ~77 servers, so the default would add ~150s of pure waiting. Disable
    // the drain unless an operator set it explicitly.
    if os.Getenv("I2SIG_SHUTDOWN_DRAIN") == "" {
        _ = os.Setenv("I2SIG_SHUTDOWN_DRAIN", "0")
    }
    os.Exit(m.Run())
}
