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
	// Legacy fixtures here mint keys through CreateKeyPair / POST /key with no
	// alg and assume RSA with kid == issuer; pin the pre-spec-#114 default.
	// Spec #114 tests that exercise the ES256 default set I2SIG_KEY_ALG
	// themselves (t.Setenv) before building the service.
	if _, set := os.LookupEnv("I2SIG_KEY_ALG"); !set {
		_ = os.Setenv("I2SIG_KEY_ALG", "RS256")
	}
	if os.Getenv("I2SIG_SHUTDOWN_DRAIN") == "" {
		_ = os.Setenv("I2SIG_SHUTDOWN_DRAIN", "0")
	}
	os.Exit(m.Run())
}
