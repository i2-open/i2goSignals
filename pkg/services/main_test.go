package services

import (
	"os"
	"testing"
)

// TestMain pins the default key type to RS256 for this package's legacy
// fixtures, which mint keys through CreateKeyPair and assert RSA material.
// Spec #114 tests that exercise the ES256 default set KeyAlgEnvVar themselves
// (t.Setenv) before constructing the KeyService.
func TestMain(m *testing.M) {
	if _, set := os.LookupEnv(KeyAlgEnvVar); !set {
		_ = os.Setenv(KeyAlgEnvVar, "RS256")
	}
	os.Exit(m.Run())
}
