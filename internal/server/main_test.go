package server

import (
	"os"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goroutineleak"
)

// TestMain disables the SignalsApplication graceful-drain for this package's
// tests. Shutdown() otherwise sleeps I2SIG_SHUTDOWN_DRAIN seconds per phase
// (production default 1s => ~2s total); these tests spin up and tear down many
// servers, so the default adds tens of seconds of pure waiting. An operator who
// sets the env explicitly is respected.
//
// It also hangs the package on the Go 1.27 goroutine-leak gate: this package
// owns the SSTP dialer, whose heartbeat and resume timers are exactly the shape
// that leaks a goroutine when a timer path regresses. The check is inert unless
// goroutineleak.EnvVar is set, which `make qa` does and `go test` does not.
func TestMain(m *testing.M) {
	if os.Getenv("I2SIG_SHUTDOWN_DRAIN") == "" {
		_ = os.Setenv("I2SIG_SHUTDOWN_DRAIN", "0")
	}
	os.Exit(goroutineleak.Run(m))
}
