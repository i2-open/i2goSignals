package services

import (
	"os"
	"strconv"
	"strings"

	"github.com/i2-open/i2goSignals/pkg/logger"
)

var sfLog = logger.Sub("SUBJECT_FILTER")

// SSF subject-filtering server-wide setting. The feature is governed by the
// I2SIG_SUBJECT_FILTERING environment variable and is DISABLED unless the
// operator explicitly opts in.
const (
	subjectFilteringEnvVar        = "I2SIG_SUBJECT_FILTERING"
	SubjectFilteringEnabledValue  = "ENABLED"
	SubjectFilteringDisabledValue = "DISABLED"

	// subjectRemovalGraceEnvVar is the server-wide default for the SSF §9.3
	// removal grace period, in seconds. PRD #97 issue #98.
	subjectRemovalGraceEnvVar = "I2SIG_SUBJECT_REMOVAL_GRACE"
)

// SubjectFilteringEnabled reports whether SSF subject filtering (the
// Add/Remove Subject mechanism, SSF §8.1.3) is enabled server-wide. It returns
// true only when I2SIG_SUBJECT_FILTERING is set to ENABLED (case-insensitive);
// unset or any other value means DISABLED.
func SubjectFilteringEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(subjectFilteringEnvVar)), SubjectFilteringEnabledValue)
}

// SubjectRemovalGraceDefaultSeconds returns the server-wide default for the
// SSF §9.3 removal grace period, in seconds. Read from
// I2SIG_SUBJECT_REMOVAL_GRACE; unset, empty, non-integer, or negative values
// fall back to 0 (immediate enforcement — no behavior change). The value is a
// default; a per-transmitter-stream override on StreamStateRecord wins where
// set. No enforcement is wired up in this slice (PRD #97 issue #98).
func SubjectRemovalGraceDefaultSeconds() int {
	raw := strings.TrimSpace(os.Getenv(subjectRemovalGraceEnvVar))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		sfLog.Warn("Invalid I2SIG_SUBJECT_REMOVAL_GRACE value; falling back to immediate enforcement", "value", raw)
		return 0
	}
	return n
}
