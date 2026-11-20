package goSetPoll

import (
	"os"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goroutineleak"
)

// TestMain hangs this package on the Go 1.27 goroutine-leak gate. The check is
// inert unless goroutineleak.EnvVar is set, which `make qa` does and an
// ordinary `go test` does not.
func TestMain(m *testing.M) {
	os.Exit(goroutineleak.Run(m))
}
