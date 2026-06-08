package main

import (
    "os"
    "testing"
)

// TestMain disables the SignalsApplication graceful-drain for the CLI tests.
// The tool-suite spins up real servers whose Shutdown() otherwise sleeps
// I2SIG_SHUTDOWN_DRAIN seconds per phase (production default 1s => ~2s total).
// An operator who sets the env explicitly is respected.
func TestMain(m *testing.M) {
    if os.Getenv("I2SIG_SHUTDOWN_DRAIN") == "" {
        _ = os.Setenv("I2SIG_SHUTDOWN_DRAIN", "0")
    }
    os.Exit(m.Run())
}
