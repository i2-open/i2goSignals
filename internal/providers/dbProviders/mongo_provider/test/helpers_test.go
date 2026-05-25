package test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDbUrl is the local-dev fallback MongoDB URL for these tests. It
// points at the replica-set spun up by the project's docker-compose dev
// stack (mongo1/mongo2/mongo3). CI does not run that stack; CI exposes a
// single-node mongo:7 via the MONGO_URL env var instead — see mongoURL().
//
// The 5s serverSelectionTimeoutMS keeps a no-mongo `go test ./...`
// failing fast so the Skip path triggers within a few seconds rather
// than the driver's 30s default.
var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

// mongoURL returns the MongoDB URL these tests connect to. CI sets
// MONGO_URL (single-node mongo:7 service at mongodb://localhost:27017);
// local devs running the docker-compose cluster get TestDbUrl. When
// neither mongo is reachable, callers Skip on the Open/Check error.
func mongoURL() string {
	if u := os.Getenv("MONGO_URL"); u != "" {
		return u
	}
	return TestDbUrl
}

// setMongoResumeFileTempDir routes watchtokens' resume-file env to a
// per-test tempdir so mongo_provider.Open does not leak an artifact
// under <package>/resources/mongo_token.json. Must be called before
// mongo_provider.Open. The Go test harness deletes t.TempDir() when t
// finishes, and t.Setenv restores any prior env value.
func setMongoResumeFileTempDir(t *testing.T) {
	t.Helper()
	t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))
}
