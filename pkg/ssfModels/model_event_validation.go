package model

import (
	"fmt"
	"strings"
)

// EventValidationMode is the per-receiver event-validation policy knob (spec
// #247, issue #250). It is a goSignals operator knob and is deliberately kept
// OFF the SSF wire-format StreamConfiguration, alongside DefaultSubjects,
// SubjectFilterMode, RetentionWindowDays and SubjectRemovalGraceSeconds — these
// are goSignals policy, not SSF wire config.
//
// The mode is receive-side only: it governs validation of events arriving on a
// stream. On a bidirectional SSTP pair record (ADR COM-0018) the single field
// governs the INBOUND leg.
//
// A named string type (rather than the plain string used by the adjacent
// SubjectFilterMode knob) is deliberate: this is a closed enum the transports
// switch on, so an invalid mode should be a parse error rather than a silent
// typo.
type EventValidationMode string

const (
	// EventValidationUnset means no per-stream value: inherit the server-wide
	// I2SIG_STREAM_EVENT_VALIDATION default.
	EventValidationUnset EventValidationMode = "" // inherit the server default

	// EventValidationNone performs no event validation.
	EventValidationNone EventValidationMode = "NONE"

	// EventValidationWarn validates and reports dispositions, delivering the
	// event regardless.
	EventValidationWarn EventValidationMode = "WARN"

	// EventValidationEnforce rejects events that fail validation.
	EventValidationEnforce EventValidationMode = "ENFORCE"

	// EventValidationStrict rejects events that fail validation and additionally
	// rejects events it cannot validate.
	EventValidationStrict EventValidationMode = "STRICT"
)

// EventValidationModes lists the accepted non-empty mode values in policy
// order. Used to build the error message ParseEventValidationMode returns.
var EventValidationModes = []EventValidationMode{
	EventValidationNone,
	EventValidationWarn,
	EventValidationEnforce,
	EventValidationStrict,
}

// ParseEventValidationMode parses an operator-supplied event-validation mode.
// Matching is case-insensitive and surrounding whitespace is ignored. An empty
// string parses to EventValidationUnset with a nil error ("inherit the server
// default"); anything unrecognized is an error naming the accepted values.
func ParseEventValidationMode(s string) (EventValidationMode, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return EventValidationUnset, nil
	}
	candidate := EventValidationMode(strings.ToUpper(trimmed))
	for _, m := range EventValidationModes {
		if candidate == m {
			return m, nil
		}
	}
	return EventValidationUnset, fmt.Errorf(
		"invalid event_validation %q: must be one of %s", s, eventValidationModeList())
}

// Valid reports whether m is a recognized mode. EventValidationUnset is valid —
// it is the "inherit the server default" state.
func (m EventValidationMode) Valid() bool {
	if m == EventValidationUnset {
		return true
	}
	for _, known := range EventValidationModes {
		if m == known {
			return true
		}
	}
	return false
}

// String renders the mode as its wire/persisted token.
func (m EventValidationMode) String() string {
	return string(m)
}

// eventValidationModeList renders the accepted values for an error message.
func eventValidationModeList() string {
	parts := make([]string, 0, len(EventValidationModes))
	for _, m := range EventValidationModes {
		parts = append(parts, string(m))
	}
	return strings.Join(parts, ", ")
}
