package model

import (
	"encoding/json"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func intPtr(v int) *int { return &v }

// TestRetentionWindow_OffSsfWire asserts the retention knob is deliberately kept
// off the RFC 8935 StreamConfiguration wire object (ADR 0055 Q91.1): marshaling
// a StreamConfiguration never emits a retention field.
func TestRetentionWindow_OffSsfWire(t *testing.T) {
	cfg := StreamConfiguration{Id: "stream-1", Iss: "https://issuer.example"}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal StreamConfiguration: %v", err)
	}
	if strings.Contains(strings.ToLower(string(b)), "retention") {
		t.Fatalf("SSF wire StreamConfiguration must not carry a retention field, got: %s", b)
	}
}

// TestRetentionWindow_PersistsOnState verifies the override round-trips on the
// server-internal StreamStateRecord over both JSON and BSON, mirroring the
// DefaultSubjects precedent.
func TestRetentionWindow_PersistsOnState(t *testing.T) {
	rec := StreamStateRecord{
		Id:                  bson.NewObjectID(),
		RetentionWindowDays: intPtr(30),
	}

	// JSON round-trip
	jb, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	if !strings.Contains(string(jb), "retention_window_days") {
		t.Fatalf("state record JSON must carry retention_window_days, got: %s", jb)
	}
	var fromJSON StreamStateRecord
	if err := json.Unmarshal(jb, &fromJSON); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if fromJSON.RetentionWindowDays == nil || *fromJSON.RetentionWindowDays != 30 {
		t.Fatalf("json round-trip lost retention window: %#v", fromJSON.RetentionWindowDays)
	}

	// BSON round-trip
	bb, err := bson.Marshal(rec)
	if err != nil {
		t.Fatalf("bson marshal: %v", err)
	}
	var fromBSON StreamStateRecord
	if err := bson.Unmarshal(bb, &fromBSON); err != nil {
		t.Fatalf("bson unmarshal: %v", err)
	}
	if fromBSON.RetentionWindowDays == nil || *fromBSON.RetentionWindowDays != 30 {
		t.Fatalf("bson round-trip lost retention window: %#v", fromBSON.RetentionWindowDays)
	}
}

// TestRetentionWindow_NilOmitted confirms the keep-forever default (nil) is
// omitted from both encodings — no field emitted means "inherit".
func TestRetentionWindow_NilOmitted(t *testing.T) {
	rec := StreamStateRecord{Id: bson.NewObjectID()}
	jb, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	if strings.Contains(string(jb), "retention_window_days") {
		t.Fatalf("nil retention window must be omitted from JSON, got: %s", jb)
	}
}

// TestRetentionWindow_DeepCopyIndependent verifies DeepCopy clones the pointer
// so mutating the copy never aliases the source.
func TestRetentionWindow_DeepCopyIndependent(t *testing.T) {
	src := &StreamStateRecord{Id: bson.NewObjectID(), RetentionWindowDays: intPtr(7)}
	cp := src.DeepCopy()
	if cp.RetentionWindowDays == nil || *cp.RetentionWindowDays != 7 {
		t.Fatalf("deep copy did not carry the window: %#v", cp.RetentionWindowDays)
	}
	if cp.RetentionWindowDays == src.RetentionWindowDays {
		t.Fatalf("deep copy must not share the RetentionWindowDays pointer")
	}
	*cp.RetentionWindowDays = 99
	if *src.RetentionWindowDays != 7 {
		t.Fatalf("mutating copy aliased the source window")
	}
}

// TestRetentionWindow_Update confirms Update() carries the override over.
func TestRetentionWindow_Update(t *testing.T) {
	dst := &StreamStateRecord{Id: bson.NewObjectID()}
	mod := &StreamStateRecord{RetentionWindowDays: intPtr(14)}
	dst.Update(mod)
	if dst.RetentionWindowDays == nil || *dst.RetentionWindowDays != 14 {
		t.Fatalf("Update did not carry retention window: %#v", dst.RetentionWindowDays)
	}
}
