package services

import (
	"os"
	"strings"
)

// rcvManagementExerciseEnvVar opts a receiver into a one-shot self-exercise of
// the transmitter's stream-management API (read, update, replace, status-update)
// once a stream is established. It exists purely for conformance/interop testing:
// a real receiver does not spontaneously PATCH/PUT/POST-status its own stream, so
// this stays off by default. The OpenID SSF receiver conformance plan
// (happypath, stream-status-update modules) requires the suite to observe these
// receiver-initiated management calls, which this flag drives.
const rcvManagementExerciseEnvVar = "I2SIG_RCV_MANAGEMENT_EXERCISE"

// RcvManagementExerciseEnabled reports whether receivers should perform the
// one-shot management self-exercise against the transmitter on stream
// establishment. True only when I2SIG_RCV_MANAGEMENT_EXERCISE is a truthy value
// (true/1/enabled/yes, case-insensitive); unset or anything else means false.
func RcvManagementExerciseEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(rcvManagementExerciseEnvVar))) {
	case "true", "1", "enabled", "yes":
		return true
	default:
		return false
	}
}
