package model

import (
	"encoding/json"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// readinessFixture is a receiver record carrying both readiness directions.
func readinessFixture() *StreamStateRecord {
	next := time.Date(2026, 8, 19, 12, 5, 0, 0, time.UTC)
	return &StreamStateRecord{
		StreamConfiguration: StreamConfiguration{Id: "sid-1"},
		Status:              StreamStateEnabled,
		JwksReadiness: &JwksReadiness{
			State:       JwksReadinessUnresolved,
			LastError:   "connect: connection refused",
			NextRetryAt: &next,
		},
		InboundJwksReadiness: &JwksReadiness{State: JwksReadinessReady},
	}
}

// TestJwksReadiness_NeverPersisted is the ADR 0033 guarantee that readiness is
// node-local and derived: it describes THIS node's current reachability of a
// remote endpoint, not a property of the stream, so two cluster members may
// legitimately disagree and neither is stale. Persisting it would make one
// node's outage look like a stream attribute and would survive a restart that
// has already invalidated it.
func TestJwksReadiness_NeverPersisted(t *testing.T) {
	raw, err := bson.Marshal(readinessFixture())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var doc bson.M
	if err := bson.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"jwks_readiness", "jwksreadiness", "inbound_jwks_readiness", "inboundjwksreadiness"} {
		if _, present := doc[key]; present {
			t.Errorf("BSON document must not carry %q: readiness is derived and node-local", key)
		}
	}

	var round StreamStateRecord
	if err := bson.Unmarshal(raw, &round); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if round.JwksReadiness != nil || round.InboundJwksReadiness != nil {
		t.Error("readiness must not survive a storage round trip")
	}
}

// TestJwksReadiness_SerializedForOperators: readiness is invisible in storage
// but must reach the operator-facing admin stream-state JSON, since stream
// Status is deliberately NOT its carrier — an unresolvable stream keeps
// reporting "enabled" (ADR 0033).
func TestJwksReadiness_SerializedForOperators(t *testing.T) {
	raw, err := json.Marshal(readinessFixture())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	readiness, ok := doc["jwks_readiness"].(map[string]any)
	if !ok {
		t.Fatalf("jwks_readiness missing from admin JSON: %s", raw)
	}
	if readiness["state"] != JwksReadinessUnresolved {
		t.Errorf("state = %v, want %q", readiness["state"], JwksReadinessUnresolved)
	}
	if readiness["last_error"] != "connect: connection refused" {
		t.Errorf("last_error = %v, want the failure reason", readiness["last_error"])
	}
	if _, present := readiness["next_retry_at"]; !present {
		t.Error("an unresolved direction with a scheduled retry must publish next_retry_at")
	}
	if _, present := doc["inbound_jwks_readiness"]; !present {
		t.Error("the inbound twin must be serialized too")
	}

	// A record with no readiness overlaid must not grow empty keys.
	bare, err := json.Marshal(&StreamStateRecord{StreamConfiguration: StreamConfiguration{Id: "sid-2"}})
	if err != nil {
		t.Fatalf("marshal bare: %v", err)
	}
	var bareDoc map[string]any
	if err := json.Unmarshal(bare, &bareDoc); err != nil {
		t.Fatalf("unmarshal bare: %v", err)
	}
	if _, present := bareDoc["jwks_readiness"]; present {
		t.Error("a record with no readiness overlaid must omit the field")
	}
}

// TestJwksReadiness_DeepCopyIsIndependent: MaskCredentials (and every other
// caller) works on a DeepCopy, so readiness must be copied rather than aliased —
// otherwise mutating a serialization copy would reach back into the cached
// record.
func TestJwksReadiness_DeepCopyIsIndependent(t *testing.T) {
	original := readinessFixture()
	clone := original.DeepCopy()

	if clone.JwksReadiness == original.JwksReadiness {
		t.Error("JwksReadiness must be deep-copied, not aliased")
	}
	if clone.JwksReadiness.NextRetryAt == original.JwksReadiness.NextRetryAt {
		t.Error("NextRetryAt must be deep-copied, not aliased")
	}
	clone.JwksReadiness.State = JwksReadinessReady
	if original.JwksReadiness.State != JwksReadinessUnresolved {
		t.Error("mutating the copy must not reach the original")
	}
	if clone.InboundJwksReadiness == original.InboundJwksReadiness {
		t.Error("InboundJwksReadiness must be deep-copied, not aliased")
	}
}
