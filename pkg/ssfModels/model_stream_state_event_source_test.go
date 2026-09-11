package model

import (
	"encoding/json"
	"testing"
)

// InboundEventSource is the inbound twin of EventSource, carrying the receive
// direction's ADR 0004 routing descriptor on an SSTP pair record because one
// record-level field cannot describe two logical streams (issue #296). It
// follows the InboundStatus / InboundErrorMsg / InboundJwksReadiness convention,
// so it owes the same obligations: deep-copied rather than aliased, carried by
// Update, and omitted from the wire when unset.

func eventSourcePairFixture() *StreamStateRecord {
	return &StreamStateRecord{
		PairId:      "pair-1",
		EventSource: &EventSource{Type: EventSourceExplicit, SourceStreamIds: []string{"sid-out"}},
		InboundEventSource: &EventSource{
			Type:            EventSourceExplicit,
			SourceStreamIds: []string{"sid-in"},
		},
	}
}

// Every serialization path works on a DeepCopy, so an aliased descriptor would
// let a mutation of the copy reach back into the cached record.
func TestInboundEventSource_DeepCopyIsIndependent(t *testing.T) {
	original := eventSourcePairFixture()
	clone := original.DeepCopy()

	if clone.InboundEventSource == original.InboundEventSource {
		t.Error("InboundEventSource must be deep-copied, not aliased")
	}
	clone.InboundEventSource.Type = EventSourceAudience
	clone.InboundEventSource.SourceStreamIds[0] = "mutated"

	if original.InboundEventSource.Type != EventSourceExplicit {
		t.Error("mutating the copy's type must not reach the original")
	}
	if original.InboundEventSource.SourceStreamIds[0] != "sid-in" {
		t.Error("SourceStreamIds must be deep-copied, not aliased")
	}
	// The two halves stay distinct through the copy.
	if clone.EventSource.SourceStreamIds[0] != "sid-out" {
		t.Error("the primary descriptor must not be disturbed by the inbound one")
	}
}

func TestInboundEventSource_DeepCopyOfNilStaysNil(t *testing.T) {
	clone := (&StreamStateRecord{PairId: "pair-1"}).DeepCopy()
	if clone.InboundEventSource != nil {
		t.Error("a record with no inbound descriptor must copy to nil, not an empty struct")
	}
}

// Update is the in-place merge used to preserve live handles on a stored record.
// A field it forgets is silently discarded on every update of that record.
func TestInboundEventSource_UpdateCarriesTheTwin(t *testing.T) {
	stored := &StreamStateRecord{PairId: "pair-1"}
	stored.Update(eventSourcePairFixture())

	if stored.InboundEventSource == nil {
		t.Fatal("Update must carry InboundEventSource")
	}
	if stored.InboundEventSource.Type != EventSourceExplicit {
		t.Errorf("got type %q", stored.InboundEventSource.Type)
	}
	if stored.EventSource == nil || stored.EventSource.SourceStreamIds[0] != "sid-out" {
		t.Error("Update must still carry the primary descriptor")
	}
}

// A plain RFC8935/RFC8936 record has no inbound leg, so the field must not
// appear on its wire shape at all.
func TestInboundEventSource_OmittedWhenUnset(t *testing.T) {
	raw, err := json.Marshal(&StreamStateRecord{PairId: "pair-1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := doc["inbound_event_source"]; present {
		t.Error("a record with no inbound descriptor must omit the field")
	}
}
