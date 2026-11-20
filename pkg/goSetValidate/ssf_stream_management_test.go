package goSetValidate

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
)

// setWithSubject builds a SET carrying an arbitrary top-level sub_id so the
// tables below can exercise the sub_id rule directly.
func setWithSubject(sid *goSet.SubjectIdentifier) *goSet.SecurityEventToken {
	set := goSet.CreateSet(nil, "https://transmitter.example.com", []string{"receiver.example.com"})
	set.SubjectId = sid
	return &set
}

func opaqueSubject(id string) *goSet.SubjectIdentifier {
	return &goSet.SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: goSet.OpaqueIdentifier{Id: id},
	}
}

type validatorCase struct {
	name        string
	citation    string
	set         *goSet.SecurityEventToken
	payload     map[string]any
	want        Disposition
	wantClaim   string // only checked when want == Malformed
	description string
}

func runValidatorCases(t *testing.T, eventURI string, validate ValidatorFunc, cases []validatorCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validate.Validate(eventURI, tc.payload, tc.set)

			assert.Equal(t, eventURI, got.EventURI)
			assert.Equal(t, tc.want, got.Disposition, "%s — %s (%s)", tc.name, tc.description, tc.citation)

			if tc.want == Malformed {
				assert.Equal(t, tc.wantClaim, got.Claim, "failing claim name (%s)", tc.citation)
				assert.NotEmpty(t, got.Detail, "Malformed must carry a human-readable Detail")
			} else {
				assert.Empty(t, got.Claim, "Claim is empty unless the disposition is Malformed")
				assert.Empty(t, got.Detail, "Detail is empty unless the disposition is Malformed")
			}
		})
	}
}

// TestValidateVerificationEvent covers every claim the SSF Verification Event
// defines: the OPTIONAL "state" payload claim and the REQUIRED top-level
// opaque "sub_id" (SSF §8.1.4.1).
func TestValidateVerificationEvent(t *testing.T) {
	runValidatorCases(t, SsfVerificationEventUri, validateVerificationEvent, []validatorCase{
		{
			name:        "state present as a string",
			citation:    "SSF §8.1.4.1 (state: OPTIONAL, an opaque value)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="},
			want:        Valid,
			description: "the canonical §8.1.4.1 Figure 46 shape",
		},
		{
			name:        "state absent",
			citation:    "SSF §8.1.4.1 (state: OPTIONAL)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{},
			want:        Valid,
			description: "an OPTIONAL claim must never fail a validator when absent",
		},
		{
			name:        "unknown extra claim ignored",
			citation:    "SSF §8.1.4.1",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"state": "s", "future_extension": map[string]any{"x": 1}},
			want:        Valid,
			description: "unknown claims are forward-compatibility, not an error",
		},
		{
			name:        "state present but not a string",
			citation:    "SSF §8.1.4.1 (state is an opaque value echoed back verbatim)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"state": 42},
			want:        Malformed,
			wantClaim:   "state",
			description: "a non-string state cannot be echoed back to the receiver",
		},
		{
			name:        "state present but empty",
			citation:    "SSF §8.1.4.1 (state carries the value provided by the receiver)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"state": ""},
			want:        Malformed,
			wantClaim:   "state",
			description: "an explicitly empty state cannot satisfy the receiver's SHALL-confirm check",
		},
		{
			name:        "sub_id absent",
			citation:    "SSF §8.1.4.1 (sub_id: REQUIRED)",
			set:         setWithSubject(nil),
			payload:     map[string]any{"state": "s"},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the verification event must name the stream being verified",
		},
		{
			name:        "sub_id format is not opaque",
			citation:    "SSF §8.1.4.1 (sub_id MUST have a simple value of type opaque)",
			set:         setWithSubject(&goSet.SubjectIdentifier{Format: "email", EmailIdentifier: goSet.EmailIdentifier{Email: "a@example.com"}}),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "only the opaque format can carry a stream_id",
		},
		{
			name:        "sub_id opaque but id empty",
			citation:    "SSF §8.1.4.1 (the id MUST be the stream_id of the stream being verified)",
			set:         setWithSubject(opaqueSubject("")),
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "an empty id names no stream",
		},
		{
			name:        "nil set",
			citation:    "SSF §8.1.4.1 (sub_id: REQUIRED)",
			set:         nil,
			payload:     map[string]any{},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "a missing envelope cannot satisfy a REQUIRED envelope claim",
		},
	})
}

// TestValidators_RecommendedButAbsentClaimNeverFails: RFC 8417 §2.2 makes the
// SET "aud" claim RECOMMENDED, not REQUIRED. A validator must not fail a payload
// because a RECOMMENDED claim is absent — only a REQUIRED one.
func TestValidators_RecommendedButAbsentClaimNeverFails(t *testing.T) {
	validators := map[string]ValidatorFunc{
		SsfVerificationEventUri:  validateVerificationEvent,
		SsfStreamUpdatedEventUri: validateStreamUpdatedEvent,
	}
	payloads := map[string]map[string]any{
		SsfVerificationEventUri:  {"state": "opaque-state"},
		SsfStreamUpdatedEventUri: {"status": "paused"},
	}

	for eventURI, validate := range validators {
		t.Run(eventURI, func(t *testing.T) {
			set := setWithSubject(opaqueSubject(testStreamId))
			set.Audience = nil // RFC 8417 §2.2 — aud is RECOMMENDED, not REQUIRED

			got := validate.Validate(eventURI, payloads[eventURI], set)
			assert.Equal(t, Valid, got.Disposition,
				"an absent RECOMMENDED claim (aud, RFC 8417 §2.2) must never fail a validator")
		})
	}
}

// TestValidateStreamUpdatedEvent covers every claim the SSF Stream Updated Event
// defines: REQUIRED "status", OPTIONAL "reason" (SSF §8.1.5), the allowable
// status vocabulary (SSF §8.1.2), and the REQUIRED top-level opaque "sub_id"
// (SSF §8.1.5).
func TestValidateStreamUpdatedEvent(t *testing.T) {
	cases := []validatorCase{
		{
			name:        "status paused with reason",
			citation:    "SSF §8.1.5 Figure 47",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"status": "paused", "reason": "Internal error"},
			want:        Valid,
			description: "the canonical §8.1.5 example shape",
		},
		{
			name:        "reason absent",
			citation:    "SSF §8.1.5 (reason: OPTIONAL)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"status": "enabled"},
			want:        Valid,
			description: "an OPTIONAL claim must never fail a validator when absent",
		},
		{
			name:        "unknown extra claim ignored",
			citation:    "SSF §8.1.5",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"status": "disabled", "vendor_hint": "rate-limited"},
			want:        Valid,
			description: "unknown claims are forward-compatibility, not an error",
		},
		{
			name:        "status absent",
			citation:    "SSF §8.1.5 (status: REQUIRED)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"reason": "no status"},
			want:        Malformed,
			wantClaim:   "status",
			description: "the whole point of the event is the new status",
		},
		{
			name:        "status not a string",
			citation:    "SSF §8.1.2 (status: a string whose value MUST be one of the values described)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"status": true},
			want:        Malformed,
			wantClaim:   "status",
			description: "status is a string, not a boolean",
		},
		{
			name:        "status outside the allowable vocabulary",
			citation:    "SSF §8.1.2 (allowable status values: enabled, paused, disabled)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"status": "quiesced"},
			want:        Malformed,
			wantClaim:   "status",
			description: "an unknown status leaves the receiver with no defined behaviour",
		},
		{
			name:        "reason present but not a string",
			citation:    "SSF §8.1.5 (reason: OPTIONAL, a short description)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"status": "paused", "reason": 500},
			want:        Malformed,
			wantClaim:   "reason",
			description: "reason is prose, not a code",
		},
		{
			name:        "sub_id absent",
			citation:    "SSF §8.1.5 (sub_id: REQUIRED, specifies the Stream ID)",
			set:         setWithSubject(nil),
			payload:     map[string]any{"status": "paused"},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "the event must name the stream whose status changed",
		},
		{
			name:        "sub_id format is not opaque",
			citation:    "SSF §8.1.5 (the value of sub_id MUST be of format opaque)",
			set:         setWithSubject(&goSet.SubjectIdentifier{Format: "uri", UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "urn:example:stream"}}),
			payload:     map[string]any{"status": "paused"},
			want:        Malformed,
			wantClaim:   "sub_id",
			description: "only the opaque format can carry a stream id",
		},
	}

	// Every allowable status value from SSF §8.1.2 must validate.
	for _, status := range []string{"enabled", "paused", "disabled"} {
		cases = append(cases, validatorCase{
			name:        "allowable status " + status,
			citation:    "SSF §8.1.2 (allowable status values)",
			set:         setWithSubject(opaqueSubject(testStreamId)),
			payload:     map[string]any{"status": status},
			want:        Valid,
			description: "each spec-defined status value is accepted",
		})
	}

	runValidatorCases(t, SsfStreamUpdatedEventUri, validateStreamUpdatedEvent, cases)
}
