package services

import (
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// validateEventValidationMode rejects a malformed per-stream event_validation
// mode on the request before any state is mutated (spec #247 issue #250). It
// sits alongside validateSubjectRemovalGrace in the create/update pipeline and
// is a field-shape check only — the WARN-and-drop for a transmit-only stream is
// applyEventValidation's job.
func validateEventValidationMode(mode model.EventValidationMode) error {
	if mode.Valid() {
		return nil
	}
	_, err := model.ParseEventValidationMode(string(mode))
	return err
}

// applyEventValidation copies a set event_validation mode from the request onto
// streamRec. The knob is receive-side only: on a transmit-only stream the value
// has no meaning and is dropped with a WARN so the misconfiguration is visible
// rather than silent (spec #247 issue #250, story 13), following the existing
// wrong-direction precedent in applyRemovalGraceOverride. A bidirectional SSTP
// pair record always has an inbound leg (ADR COM-0018), so the mode is honored
// there and binds to that inbound leg. The request value has already been
// shape-checked by validateEventValidationMode.
func applyEventValidation(streamRec *model.StreamStateRecord, requested model.EventValidationMode) {
	if requested == model.EventValidationUnset {
		return
	}
	if !streamRec.HasInbound() {
		ssLog.Warn("event_validation ignored on a transmit-only stream",
			"stream_id", streamRec.StreamConfiguration.Id,
			"mode", string(requested))
		return
	}
	streamRec.EventValidation = requested
}

// ResolveEventValidationMode resolves the effective event-validation mode for a
// stream record's INBOUND leg (spec #247 issue #250): the per-stream value wins
// when set, otherwise serverDefault, otherwise NONE. A transmit-only record has
// no inbound leg and always resolves to NONE. On an SSTP pair the single
// StreamStateRecord field governs the inbound leg (ADR COM-0018, story 12).
func ResolveEventValidationMode(rec *model.StreamStateRecord, serverDefault model.EventValidationMode) model.EventValidationMode {
	if rec == nil || !rec.HasInbound() {
		return model.EventValidationNone
	}
	if rec.EventValidation != model.EventValidationUnset && rec.EventValidation.Valid() {
		return rec.EventValidation
	}
	if serverDefault == model.EventValidationUnset || !serverDefault.Valid() {
		return model.EventValidationNone
	}
	return serverDefault
}

// EventValidationDefault returns the server-wide event-validation default this
// service was constructed with (from I2SIG_STREAM_EVENT_VALIDATION). It is
// always a recognized, non-empty mode — NewStreamService resolves an unset or
// unrecognized configured value to NONE with a WARN.
func (s *StreamService) EventValidationDefault() model.EventValidationMode {
	return s.eventValidationDefault
}

// ResolveEventValidation returns the effective inbound event-validation mode for
// rec, resolving an empty per-stream value against this server's default. This
// is the read-time resolution surfaced by the admin stream review path.
func (s *StreamService) ResolveEventValidation(rec *model.StreamStateRecord) model.EventValidationMode {
	return ResolveEventValidationMode(rec, s.eventValidationDefault)
}
