package model

import (
	"encoding/json"
	"testing"
)

// PollParameters is what the goSignals CLI marshals for its poll requests:
// an acknowledgement-only request must carry an explicit "maxEvents": 0, and
// one that leaves maxEvents out must not (#369).
func TestPollParameters_AckOnlyRoundTrip(t *testing.T) {
	body, err := json.Marshal(PollParameters{AckOnly: true, ReturnImmediately: true, Acks: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if v, ok := wire["maxEvents"]; !ok || v != float64(0) {
		t.Fatalf("ack-only request must send maxEvents 0, got %s", body)
	}
	var back PollParameters
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatal(err)
	}
	if !back.AckOnly || back.MaxEvents != 0 {
		t.Fatalf("explicit maxEvents 0 must parse as ack-only, got %+v", back)
	}

	body, err = json.Marshal(PollParameters{ReturnImmediately: true})
	if err != nil {
		t.Fatal(err)
	}
	wire = nil
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["maxEvents"]; ok {
		t.Fatalf("an unset maxEvents stays off the wire, got %s", body)
	}
	back = PollParameters{}
	if err := json.Unmarshal([]byte(`{"maxEvents":7}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.AckOnly || back.MaxEvents != 7 {
		t.Fatalf("maxEvents 7 is not ack-only, got %+v", back)
	}
}
