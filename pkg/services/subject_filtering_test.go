package services

import "testing"

// TestSubjectRemovalGraceDefaultSeconds_UnsetIsImmediate verifies the SSF §9.3
// removal-grace default is 0 when no operator opt-in is present — so a server
// upgrading to PRD #97 makes no behavioral change until grace is configured.
func TestSubjectRemovalGraceDefaultSeconds_UnsetIsImmediate(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_REMOVAL_GRACE", "")
    if got := SubjectRemovalGraceDefaultSeconds(); got != 0 {
        t.Fatalf("expected 0 when I2SIG_SUBJECT_REMOVAL_GRACE is unset, got %d", got)
    }
}

// TestSubjectRemovalGraceDefaultSeconds_ReadsPositiveInteger verifies the
// operator-supplied grace default is honored verbatim.
func TestSubjectRemovalGraceDefaultSeconds_ReadsPositiveInteger(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_REMOVAL_GRACE", "30")
    if got := SubjectRemovalGraceDefaultSeconds(); got != 30 {
        t.Fatalf("expected 30 when I2SIG_SUBJECT_REMOVAL_GRACE=30, got %d", got)
    }
}

// TestSubjectRemovalGraceDefaultSeconds_InvalidFallsBackToImmediate verifies a
// non-integer value silently degrades to immediate enforcement rather than
// blocking startup. A negative value is also rejected (immediate-only floor).
func TestSubjectRemovalGraceDefaultSeconds_InvalidFallsBackToImmediate(t *testing.T) {
    for _, raw := range []string{"abc", "-1", "  "} {
        t.Run(raw, func(t *testing.T) {
            t.Setenv("I2SIG_SUBJECT_REMOVAL_GRACE", raw)
            if got := SubjectRemovalGraceDefaultSeconds(); got != 0 {
                t.Fatalf("expected 0 for invalid value %q, got %d", raw, got)
            }
        })
    }
}
