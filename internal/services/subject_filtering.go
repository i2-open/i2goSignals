package services

import (
	"os"
	"strings"
)

// SSF subject-filtering server-wide setting. The feature is governed by the
// I2SIG_SUBJECT_FILTERING environment variable and is DISABLED unless the
// operator explicitly opts in.
const (
	subjectFilteringEnvVar        = "I2SIG_SUBJECT_FILTERING"
	SubjectFilteringEnabledValue  = "ENABLED"
	SubjectFilteringDisabledValue = "DISABLED"
)

// SubjectFilteringEnabled reports whether SSF subject filtering (the
// Add/Remove Subject mechanism, SSF §8.1.3) is enabled server-wide. It returns
// true only when I2SIG_SUBJECT_FILTERING is set to ENABLED (case-insensitive);
// unset or any other value means DISABLED.
func SubjectFilteringEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(subjectFilteringEnvVar)), SubjectFilteringEnabledValue)
}
