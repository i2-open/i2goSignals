package model

import (
	"encoding/json"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Issue #312: a poll transmitter or SSTP pair with no active signing key takes a
// key-unavailable pause, recorded by KeyUnavailableSince. Only that pause sets
// the marker, to the time of the first failure; every other status write clears
// it, so the server resumes only its own pause and never an operator's.

// TestKeyUnavailable_SetOnlyByTheKeyPause: the key-unavailable pause writes
// paused, the reason and the marker together, and every other status write
// clears the marker.
func TestKeyUnavailable_SetOnlyByTheKeyPause(t *testing.T) {
	first := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rec := &StreamStateRecord{StreamConfiguration: StreamConfiguration{Id: "poll-1"}, Status: StreamStateEnabled}

	rec.SetKeyUnavailablePause("POLL-SRV: no active signing key for issuer x (RS256)", first)
	if rec.Status != StreamStatePause || rec.ErrorMsg != "POLL-SRV: no active signing key for issuer x (RS256)" {
		t.Fatalf("status/reason not written: %q / %q", rec.Status, rec.ErrorMsg)
	}
	if rec.KeyUnavailableSince == nil || !rec.KeyUnavailableSince.Equal(first) {
		t.Fatalf("marker = %v, want %v", rec.KeyUnavailableSince, first)
	}

	rec.SetStatus(StreamStatePause, "operator pause")
	if rec.KeyUnavailableSince != nil {
		t.Error("an ordinary status write must clear the marker")
	}

	rec.SetKeyUnavailablePause("reason", first)
	rec.SetTransmitterCausedStatus(StreamStatePause, "Transmitter stream is paused: x")
	if rec.KeyUnavailableSince != nil {
		t.Error("a transmitter-caused write must clear the marker")
	}

	rec.SetKeyUnavailablePause("reason", first)
	if rec.TransmitterCaused {
		t.Error("a key-unavailable pause is not transmitter-caused")
	}
	rec.SetStatus(StreamStateEnabled, "")
	if rec.KeyUnavailableSince != nil {
		t.Error("an enabled write must clear the marker")
	}
}

// TestKeyUnavailable_RepeatFailureKeepsTheFirstTime: a repeat failure while the
// stream is still in its key-unavailable pause does not move the marker.
func TestKeyUnavailable_RepeatFailureKeepsTheFirstTime(t *testing.T) {
	first := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rec := &StreamStateRecord{}
	rec.SetKeyUnavailablePause("reason", first)
	rec.SetKeyUnavailablePause("reason", first.Add(time.Minute))
	if !rec.KeyUnavailableSince.Equal(first) {
		t.Errorf("marker moved to %v, want the first failure %v", rec.KeyUnavailableSince, first)
	}
}

// TestKeyUnavailable_PairMovesBothHalves: on an SSTP pair the pause moves both
// halves, like every pair status (#303).
func TestKeyUnavailable_PairMovesBothHalves(t *testing.T) {
	rec := &StreamStateRecord{
		StreamConfiguration: StreamConfiguration{Id: "tx"},
		SstpInbound:         &StreamConfiguration{Id: "rx"},
		SstpMethod:          &SstpMethod{Role: SstpRoleInitiator},
		Status:              StreamStateEnabled,
		InboundStatus:       StreamStateEnabled,
	}
	rec.SetKeyUnavailablePause("SSTP-CLIENT: no active signing key for issuer x (RS256)", time.Now())
	if rec.InboundStatus != StreamStatePause || rec.InboundErrorMsg != rec.ErrorMsg {
		t.Errorf("inbound half = %q / %q, want paused with the pair's reason", rec.InboundStatus, rec.InboundErrorMsg)
	}
}

// TestKeyUnavailable_SerializedOnTheStateRecord: the marker is stored and shown
// as key_unavailable_since, round-trips through BSON, and is omitted when unset.
func TestKeyUnavailable_SerializedOnTheStateRecord(t *testing.T) {
	first := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rec := &StreamStateRecord{Id: NewRecordId(), StreamConfiguration: StreamConfiguration{Id: "poll-1"}}
	rec.SetKeyUnavailablePause("reason", first)

	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["key_unavailable_since"] != first.Format(time.RFC3339) {
		t.Errorf("json key_unavailable_since = %v, want %s", doc["key_unavailable_since"], first.Format(time.RFC3339))
	}

	bsonRaw, err := bson.Marshal(rec)
	if err != nil {
		t.Fatalf("bson marshal: %v", err)
	}
	var back StreamStateRecord
	if err := bson.Unmarshal(bsonRaw, &back); err != nil {
		t.Fatalf("bson unmarshal: %v", err)
	}
	if back.KeyUnavailableSince == nil || !back.KeyUnavailableSince.Equal(first) {
		t.Errorf("bson marker = %v, want %v", back.KeyUnavailableSince, first)
	}

	rec.SetStatus(StreamStateEnabled, "")
	raw, _ = json.Marshal(rec)
	doc = map[string]any{}
	_ = json.Unmarshal(raw, &doc)
	if _, present := doc["key_unavailable_since"]; present {
		t.Error("an unset marker must be omitted from json")
	}
	bsonRaw, _ = bson.Marshal(rec)
	var bdoc bson.M
	_ = bson.Unmarshal(bsonRaw, &bdoc)
	if _, present := bdoc["key_unavailable_since"]; present {
		t.Error("an unset marker must be omitted from bson")
	}
}

// TestKeyUnavailable_OperatorWriteIsAChange: an operator repeating the status and
// reason of a key-unavailable pause still changes the record, because the write
// clears the marker and makes the pause the operator's.
func TestKeyUnavailable_OperatorWriteIsAChange(t *testing.T) {
	rec := &StreamStateRecord{}
	rec.SetKeyUnavailablePause("reason", time.Now())
	if !rec.IsStatusChange(StreamStatePause, "reason") {
		t.Error("the same status and reason on a key-unavailable pause must count as a change")
	}
}

// TestKeyUnavailable_UpdateAndDeepCopyCarryTheMarker: Update copies the status
// fields, so it carries the marker; DeepCopy gives the copy its own time.
func TestKeyUnavailable_UpdateAndDeepCopyCarryTheMarker(t *testing.T) {
	first := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	mod := &StreamStateRecord{}
	mod.SetKeyUnavailablePause("reason", first)

	stored := &StreamStateRecord{Status: StreamStateEnabled}
	stored.Update(mod)
	if stored.KeyUnavailableSince == nil || !stored.KeyUnavailableSince.Equal(first) {
		t.Error("Update must carry KeyUnavailableSince")
	}

	cp := mod.DeepCopy()
	if cp.KeyUnavailableSince == nil || cp.KeyUnavailableSince == mod.KeyUnavailableSince {
		t.Error("DeepCopy must copy the marker, not share it")
	}
}
