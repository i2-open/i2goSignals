package main

import (
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/stretchr/testify/assert"
)

// TestFormatSubjectFilterStatusCounts verifies the status formatter renders the
// aggregate filter-table counts (total entries and pending removals) so an
// operator sees the size of the locally managed filter at a glance.
func TestFormatSubjectFilterStatusCounts(t *testing.T) {
    out := formatSubjectFilterStatus("sf-alias", &subjectFilterStatusWire{
        StreamId: "sid-1",
        Counts:   &subjectFilterStatusCounts{Total: 7, Pending: 3},
    })
    assert.Contains(t, out, "Subject-filter status for [sf-alias]:")
    assert.Contains(t, out, "filter-table entries:  7")
    assert.Contains(t, out, "pending removals:      3")
}

// TestFormatSubjectFilterStatusPendingList verifies the pending-removal list is
// rendered entry by entry with the canonical key, kind, and enforce-at time, so
// an operator can see which subjects are scheduled for removal and when.
func TestFormatSubjectFilterStatusPendingList(t *testing.T) {
    enforce := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
    out := formatSubjectFilterStatus("sf-alias", &subjectFilterStatusWire{
        StreamId: "sid-1",
        Counts:   &subjectFilterStatusCounts{Total: 2, Pending: 1},
        Pending: []subjectFilterStatusEntry{
            {CanonicalKey: "email:alice@example.com", Kind: "explicit", EnforceAt: enforce},
        },
    })
    assert.Contains(t, out, "pending-removal list:")
    assert.Contains(t, out, "email:alice@example.com")
    assert.Contains(t, out, "kind=explicit")
    assert.Contains(t, out, "enforce-at=2026-06-01T12:00:00Z")
}

// TestFormatSubjectFilterStatusEmptyPendingList verifies that an empty
// pending-removal list is stated as "(none)" rather than left blank, so the
// operator can tell "no pending removals" from "the field was omitted".
func TestFormatSubjectFilterStatusEmptyPendingList(t *testing.T) {
    out := formatSubjectFilterStatus("sf-alias", &subjectFilterStatusWire{
        StreamId: "sid-1",
        Counts:   &subjectFilterStatusCounts{Total: 4, Pending: 0},
    })
    assert.Contains(t, out, "pending-removal list:  (none)")
}

// TestFormatSubjectFilterStatusPointLookup verifies the optional point-lookup
// result is rendered with the found flag, kind, pending state, enforce-at, and
// delivers flag.
func TestFormatSubjectFilterStatusPointLookup(t *testing.T) {
    enforce := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
    out := formatSubjectFilterStatus("sf-alias", &subjectFilterStatusWire{
        StreamId: "sid-1",
        Counts:   &subjectFilterStatusCounts{Total: 1, Pending: 1},
        Lookup: &subjectFilterStatusLookup{
            Subject:   &goSet.SubjectIdentifier{Format: "email", EmailIdentifier: goSet.EmailIdentifier{Email: "bob@example.com"}},
            Found:     true,
            Kind:      "explicit",
            Pending:   true,
            EnforceAt: enforce,
            Delivers:  false,
        },
    })
    assert.Contains(t, out, "point lookup:")
    assert.Contains(t, out, "found:      true")
    assert.Contains(t, out, "kind:       explicit")
    assert.Contains(t, out, "pending:    true")
    assert.Contains(t, out, "enforce-at: 2026-07-01T00:00:00Z")
    assert.Contains(t, out, "delivers:   false")
}

// TestFormatSubjectFilterStatusPassthru verifies a PASSTHRU stream is reported
// as having no local filter table — an explicit statement, not an error and
// not a misleading "0 entries" count.
func TestFormatSubjectFilterStatusPassthru(t *testing.T) {
    out := formatSubjectFilterStatus("sf-alias", &subjectFilterStatusWire{
        StreamId:              "sid-1",
        PassthruNoLocalFilter: true,
    })
    assert.Contains(t, out, "PASSTHRU")
    assert.Contains(t, out, "no local subject-filter table")
    assert.NotContains(t, out, "filter-table entries:",
        "a PASSTHRU stream must not show a misleading entry count")
}
