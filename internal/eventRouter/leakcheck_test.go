package eventRouter

import (
	"os"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goroutineleak"
)

// TestMain hangs this package on the Go 1.27 goroutine-leak gate. The check is
// inert unless goroutineleak.EnvVar is set, which `make qa` does and an
// ordinary `go test` does not.
func TestMain(m *testing.M) {
	// Legacy fixtures here mint keys through CreateKeyPair / POST /key with no
	// alg and assume RSA with kid == issuer; pin the pre-spec-#114 default.
	// Spec #114 tests that exercise the ES256 default set I2SIG_KEY_ALG
	// themselves (t.Setenv) before building the service.
	if _, set := os.LookupEnv("I2SIG_KEY_ALG"); !set {
		_ = os.Setenv("I2SIG_KEY_ALG", "RS256")
	}
	os.Exit(goroutineleak.Run(m))
}
