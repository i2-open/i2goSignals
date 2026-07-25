package model

import (
	"encoding/json"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// TestParseEventValidationMode_AcceptedValues pins the closed enum: the four
// policy tokens parse case-insensitively and an empty string is the "inherit
// the server default" state rather than an error (spec #247 issue #250).
func TestParseEventValidationMode_AcceptedValues(t *testing.T) {
	cases := map[string]EventValidationMode{
		"":         EventValidationUnset,
		"   ":      EventValidationUnset,
		"NONE":     EventValidationNone,
		"none":     EventValidationNone,
		"WARN":     EventValidationWarn,
		"Warn":     EventValidationWarn,
		"ENFORCE":  EventValidationEnforce,
		"enforce":  EventValidationEnforce,
		"STRICT":   EventValidationStrict,
		" strict ": EventValidationStrict,
	}
	for in, want := range cases {
		got, err := ParseEventValidationMode(in)
		if err != nil {
			t.Fatalf("ParseEventValidationMode(%q) returned error %v, want nil", in, err)
		}
		if got != want {
			t.Errorf("ParseEventValidationMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParseEventValidationMode_RejectsUnknown verifies an unrecognized mode is
// an error whose message names the accepted values.
func TestParseEventValidationMode_RejectsUnknown(t *testing.T) {
	got, err := ParseEventValidationMode("ENFORE")
	if err == nil {
		t.Fatalf("ParseEventValidationMode(\"ENFORE\") = %q, want an error", got)
	}
	if got != EventValidationUnset {
		t.Errorf("failed parse returned %q, want the unset zero value", got)
	}
	for _, want := range []string{"NONE", "WARN", "ENFORCE", "STRICT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name accepted value %s", err.Error(), want)
		}
	}
}

// TestEventValidationMode_Valid verifies Valid() accepts the unset state and
// the four tokens and rejects anything else.
func TestEventValidationMode_Valid(t *testing.T) {
	for _, m := range []EventValidationMode{
		EventValidationUnset, EventValidationNone, EventValidationWarn,
		EventValidationEnforce, EventValidationStrict,
	} {
		if !m.Valid() {
			t.Errorf("%q.Valid() = false, want true", m)
		}
	}
	for _, m := range []EventValidationMode{"enforce", "ALL", "1"} {
		if m.Valid() {
			t.Errorf("%q.Valid() = true, want false", m)
		}
	}
}

// TestStreamStateRecord_EventValidationTags verifies the field serializes under
// `event_validation` in both JSON and BSON, and is omitted when unset.
func TestStreamStateRecord_EventValidationTags(t *testing.T) {
	rec := StreamStateRecord{EventValidation: EventValidationEnforce}

	jsonBytes, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(jsonBytes), `"event_validation":"ENFORCE"`) {
		t.Errorf("JSON %s missing \"event_validation\":\"ENFORCE\"", string(jsonBytes))
	}

	bsonBytes, err := bson.Marshal(rec)
	if err != nil {
		t.Fatalf("bson.Marshal: %v", err)
	}
	var back StreamStateRecord
	if err := bson.Unmarshal(bsonBytes, &back); err != nil {
		t.Fatalf("bson.Unmarshal: %v", err)
	}
	if back.EventValidation != EventValidationEnforce {
		t.Errorf("BSON round-trip = %q, want ENFORCE", back.EventValidation)
	}

	unset, err := json.Marshal(StreamStateRecord{})
	if err != nil {
		t.Fatalf("json.Marshal(zero): %v", err)
	}
	if strings.Contains(string(unset), "event_validation") {
		t.Errorf("unset event_validation must be omitted, got %s", string(unset))
	}
}

// TestStreamStateRecord_EventValidationCarriedByDeepCopyAndUpdate verifies the
// two methods that enumerate every field explicitly both carry the new knob.
func TestStreamStateRecord_EventValidationCarriedByDeepCopyAndUpdate(t *testing.T) {
	src := &StreamStateRecord{EventValidation: EventValidationStrict}

	copied := src.DeepCopy()
	if copied.EventValidation != EventValidationStrict {
		t.Errorf("DeepCopy dropped event_validation: got %q, want STRICT", copied.EventValidation)
	}

	target := &StreamStateRecord{EventValidation: EventValidationNone}
	target.Update(&StreamStateRecord{EventValidation: EventValidationWarn})
	if target.EventValidation != EventValidationWarn {
		t.Errorf("Update dropped event_validation: got %q, want WARN", target.EventValidation)
	}
}

// TestStreamConfiguration_HasNoEventValidation pins the off-the-wire placement:
// event_validation is a goSignals operator knob and must never appear on the
// SSF wire-format StreamConfiguration.
func TestStreamConfiguration_HasNoEventValidation(t *testing.T) {
	wire, err := json.Marshal(StreamConfiguration{EventsRequested: []string{"x"}})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(wire), "event_validation") {
		t.Errorf("StreamConfiguration must not carry event_validation, got %s", string(wire))
	}
}
