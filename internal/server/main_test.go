package server

import (
    "os"
    "testing"
)

// TestMain disables the SignalsApplication graceful-drain for this package's
// tests. Shutdown() otherwise sleeps I2SIG_SHUTDOWN_DRAIN seconds per phase
// (production default 1s => ~2s total); these tests spin up and tear down many
// servers, so the default adds tens of seconds of pure waiting. An operator who
// sets the env explicitly is respected.
func TestMain(m *testing.M) {
    if os.Getenv("I2SIG_SHUTDOWN_DRAIN") == "" {
        _ = os.Setenv("I2SIG_SHUTDOWN_DRAIN", "0")
    }
    os.Exit(m.Run())
}
