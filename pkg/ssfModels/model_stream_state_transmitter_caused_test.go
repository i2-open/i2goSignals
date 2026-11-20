package model

import (
	"encoding/json"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Issue #310: a poll receiver records whether its paused or disabled status was
// transmitter-caused (the transmitter's status endpoint reported it) or set by
// an operator, so the poll loop resumes only a transmitter pause by itself.

// TestTransmitterCaused_SetOnlyWithTheTransmitterStatus: the transmitter-caused
// write sets the status, the reason and the flag together, and every ordinary
// status write clears the flag again.
func TestTransmitterCaused_SetOnlyWithTheTransmitterStatus(t *testing.T) {
	rec := &StreamStateRecord{StreamConfiguration: StreamConfiguration{Id: "rcv-1"}, Status: StreamStateEnabled}

	rec.SetTransmitterCausedStatus(StreamStatePause, "Transmitter stream is paused: maintenance")
	if rec.Status != StreamStatePause || rec.ErrorMsg != "Transmitter stream is paused: maintenance" {
		t.Fatalf("status/reason not written: %q / %q", rec.Status, rec.ErrorMsg)
	}
	if !rec.TransmitterCaused {
		t.Fatal("a transmitter-caused write must set the flag")
	}

	rec.SetStatus(StreamStatePause, "operator pause")
	if rec.TransmitterCaused {
		t.Error("an ordinary status write must clear the flag")
	}

	rec.SetTransmitterCausedStatus(StreamStateDisable, "Transmitter stream is disabled: gone")
	rec.SetStatus(StreamStateEnabled, "")
	if rec.TransmitterCaused {
		t.Error("an enabled write must clear the flag")
	}
}

// TestTransmitterCaused_SerializedOnTheStateRecord: the flag is stored and shown
// on the admin stream-state JSON as transmitter_caused, and omitted when unset.
func TestTransmitterCaused_SerializedOnTheStateRecord(t *testing.T) {
	rec := &StreamStateRecord{Id: NewRecordId(), StreamConfiguration: StreamConfiguration{Id: "rcv-1"}}
	rec.SetTransmitterCausedStatus(StreamStatePause, "Transmitter stream is paused: x")

	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["transmitter_caused"] != true {
		t.Errorf("json transmitter_caused = %v, want true", doc["transmitter_caused"])
	}

	bsonRaw, err := bson.Marshal(rec)
	if err != nil {
		t.Fatalf("bson marshal: %v", err)
	}
	var back StreamStateRecord
	if err := bson.Unmarshal(bsonRaw, &back); err != nil {
		t.Fatalf("bson unmarshal: %v", err)
	}
	if !back.TransmitterCaused {
		t.Error("the flag must round-trip through BSON")
	}

	rec.SetStatus(StreamStateEnabled, "")
	raw, _ = json.Marshal(rec)
	doc = map[string]any{}
	_ = json.Unmarshal(raw, &doc)
	if _, present := doc["transmitter_caused"]; present {
		t.Error("an unset flag must be omitted")
	}
}

// TestTransmitterCaused_OperatorWriteIsAChange: POST /status judges "no change"
// with IsStatusChange. An operator repeating a transmitter-caused status still
// changes the record, because the write clears the flag and makes the status
// administrative.
func TestTransmitterCaused_OperatorWriteIsAChange(t *testing.T) {
	rec := &StreamStateRecord{}
	rec.SetTransmitterCausedStatus(StreamStatePause, "Transmitter stream is paused: x")

	if !rec.IsStatusChange(StreamStatePause, "Transmitter stream is paused: x") {
		t.Error("the same status and reason on a transmitter-caused record must count as a change")
	}

	rec.SetStatus(StreamStatePause, "Transmitter stream is paused: x")
	if rec.IsStatusChange(StreamStatePause, "Transmitter stream is paused: x") {
		t.Error("an administrative record with the same status and reason is not a change")
	}
}

// TestTransmitterCaused_UpdateCarriesTheFlag: Update copies a record's status
// fields, so it carries the flag with them.
func TestTransmitterCaused_UpdateCarriesTheFlag(t *testing.T) {
	mod := &StreamStateRecord{}
	mod.SetTransmitterCausedStatus(StreamStateDisable, "Transmitter stream is disabled: x")

	stored := &StreamStateRecord{Status: StreamStateEnabled}
	stored.Update(mod)
	if !stored.TransmitterCaused {
		t.Error("Update must carry TransmitterCaused")
	}
}
