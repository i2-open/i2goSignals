package services

import (
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

// newReceiverRecord returns a receive-side record — the direction the
// event_validation knob applies to (HasInbound() true via ReceivePoll).
func newReceiverRecord() *model.StreamStateRecord {
	rec := pollReceiverRequest()
	return &rec
}

// A mode accepted case-insensitively on the wire must be PERSISTED canonically.
// Storing the raw request string left a value Valid() rejects, so
// ResolveEventValidationMode fell through to the server default and enforcement
// was silently off while the record read back "enforce" (code-review finding on
// spec #247 #250).
func TestApplyEventValidationNormalizesCase(t *testing.T) {
	for _, tc := range []struct {
		requested model.EventValidationMode
		want      model.EventValidationMode
	}{
		{"enforce", model.EventValidationEnforce},
		{"Enforce", model.EventValidationEnforce},
		{"warn", model.EventValidationWarn},
		{"strict", model.EventValidationStrict},
		{"none", model.EventValidationNone},
		{"ENFORCE", model.EventValidationEnforce},
	} {
		rec := newReceiverRecord()
		applyEventValidation(rec, tc.requested)

		assert.Equal(t, tc.want, rec.EventValidation,
			"requested %q must persist canonically", string(tc.requested))
		assert.True(t, rec.EventValidation.Valid(),
			"persisted mode %q must satisfy Valid()", string(rec.EventValidation))
		assert.Equal(t, tc.want, ResolveEventValidationMode(rec, model.EventValidationUnset),
			"requested %q must resolve to itself, not the server default", string(tc.requested))
	}
}

// The resolver must tolerate a record whose mode was persisted un-normalized by
// an earlier build rather than degrading it to the server default.
func TestResolveEventValidationModeToleratesUnnormalizedRecord(t *testing.T) {
	rec := newReceiverRecord()
	rec.EventValidation = "enforce"

	assert.Equal(t, model.EventValidationEnforce,
		ResolveEventValidationMode(rec, model.EventValidationNone))
}

// An unrecognized stored value still falls back to the server default.
func TestResolveEventValidationModeUnrecognizedFallsBack(t *testing.T) {
	rec := newReceiverRecord()
	rec.EventValidation = "banana"

	assert.Equal(t, model.EventValidationWarn,
		ResolveEventValidationMode(rec, model.EventValidationWarn))
}
