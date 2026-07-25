package goSetValidate

import (
	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// opaqueSubjectFormat is the RFC 9493 §3.2.2 "opaque" identifier format, which is
// the only format SSF allows for the sub_id of a stream-management event.
const opaqueSubjectFormat = "opaque"

// ssfStreamStatuses is the allowable "status" vocabulary from SSF §8.1.2.
//
// Deliberately re-declared here rather than imported: the stream-state model
// lives in pkg/ssfModels, which is outside this package's import allowlist. The
// values are spec constants, so the duplication cannot drift without the spec
// changing.
var ssfStreamStatuses = map[string]struct{}{
	"enabled":  {},
	"paused":   {},
	"disabled": {},
}

// requireOpaqueStreamSubject enforces the top-level sub_id rule both SSF
// stream-management events share: sub_id is REQUIRED, its format MUST be
// "opaque", and its id MUST be the stream id (SSF §8.1.4.1 for the Verification
// Event, §8.1.5 for the Stream Updated Event).
//
// Returns nil when the envelope satisfies the rule.
func requireOpaqueStreamSubject(eventURI string, set *goSet.SecurityEventToken) *Result {
	if set == nil || set.SubjectId == nil {
		r := malformed(eventURI, "sub_id",
			"a top-level sub_id claim is REQUIRED and MUST carry the stream id (SSF §8.1.4.1, §8.1.5)")
		return &r
	}
	if set.SubjectId.Format != opaqueSubjectFormat {
		r := malformed(eventURI, "sub_id",
			"sub_id MUST have a simple value of format \"opaque\", got \""+set.SubjectId.Format+"\" (SSF §8.1.4.1, §8.1.5)")
		return &r
	}
	if set.SubjectId.Id == "" {
		r := malformed(eventURI, "sub_id",
			"the opaque sub_id id MUST be the stream id, but it is empty (SSF §8.1.4.1, §8.1.5)")
		return &r
	}
	return nil
}

// validateVerificationEvent validates the SSF Verification Event
// (SSF §8.1.4.1). Claims:
//
//	state   OPTIONAL — an opaque value provided by the Event Receiver when the
//	        event is triggered. Absent is valid; the receiver only SHALL-confirms
//	        it when it asked for one.
//	sub_id  REQUIRED (top level) — MUST be a simple opaque value whose id is the
//	        stream_id of the stream being verified.
//
// Unknown extra claims are ignored.
func validateVerificationEvent(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireOpaqueStreamSubject(eventURI, set); bad != nil {
		return *bad
	}

	if rawState, present := payload["state"]; present {
		state, ok := rawState.(string)
		if !ok {
			return malformed(eventURI, "state",
				"state MUST be a string when present — it is echoed back to the receiver verbatim (SSF §8.1.4.1)")
		}
		if state == "" {
			return malformed(eventURI, "state",
				"state is present but empty; it MUST carry the opaque value the receiver supplied (SSF §8.1.4.1)")
		}
	}

	return valid(eventURI)
}

// validateStreamUpdatedEvent validates the SSF Stream Updated Event
// (SSF §8.1.5). Claims:
//
//	status  REQUIRED — the stream's new status, one of the SSF §8.1.2 allowable
//	        values ("enabled", "paused", "disabled").
//	reason  OPTIONAL — a short description of why the status changed.
//	sub_id  REQUIRED (top level) — MUST be format opaque, id = the stream's
//	        unique id.
//
// Unknown extra claims are ignored.
func validateStreamUpdatedEvent(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	if bad := requireOpaqueStreamSubject(eventURI, set); bad != nil {
		return *bad
	}

	rawStatus, present := payload["status"]
	if !present {
		return malformed(eventURI, "status",
			"status is REQUIRED — it defines the stream's new status (SSF §8.1.5)")
	}
	status, ok := rawStatus.(string)
	if !ok {
		return malformed(eventURI, "status",
			"status MUST be a string (SSF §8.1.2)")
	}
	if _, allowable := ssfStreamStatuses[status]; !allowable {
		return malformed(eventURI, "status",
			"status \""+status+"\" is outside the allowable values \"enabled\", \"paused\", \"disabled\" (SSF §8.1.2)")
	}

	if rawReason, present := payload["reason"]; present {
		if _, ok := rawReason.(string); !ok {
			return malformed(eventURI, "reason",
				"reason MUST be a string when present — it is a short description of the change (SSF §8.1.5)")
		}
	}

	return valid(eventURI)
}
