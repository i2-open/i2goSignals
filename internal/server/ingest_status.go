package server

import (
	"os"
	"strconv"
)

// ingestRetryAfterEnv names the Retry-After (seconds) an ingest handler sends
// with a 503 when a SET could not be durably stored (#333).
const ingestRetryAfterEnv = "I2SIG_INGEST_RETRY_AFTER"

// defaultIngestRetryAfter is the Retry-After, in seconds, used when
// I2SIG_INGEST_RETRY_AFTER is unset or not a positive integer.
const defaultIngestRetryAfter = 2

// ingestRetryAfterSeconds returns the Retry-After value, in whole seconds, for
// a 503 answered because an inbound SET could not be stored. It is read per
// call so an operator change takes effect without a restart of the handler.
func ingestRetryAfterSeconds() int {
	v := os.Getenv(ingestRetryAfterEnv)
	if v == "" {
		return defaultIngestRetryAfter
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		serverLog.Warn("invalid integer env var, using default", "name", ingestRetryAfterEnv, "value", v, "default", defaultIngestRetryAfter)
		return defaultIngestRetryAfter
	}
	return n
}
