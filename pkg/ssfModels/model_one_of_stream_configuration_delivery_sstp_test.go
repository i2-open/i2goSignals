package model

import (
	"encoding/json"
	"testing"
)

// TestOneOfDelivery_SstpTransmitMarker_Unmarshal proves the OneOf dispatcher
// recognizes the SSTP transmit URN and routes it to SstpTransmitMarker, with
// GetMethod() reporting DeliverySstp.
func TestOneOfDelivery_SstpTransmitMarker_Unmarshal(t *testing.T) {
	var d OneOfStreamConfigurationDelivery
	if err := json.Unmarshal([]byte(`{"method":"`+DeliverySstp+`"}`), &d); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if d.SstpTransmitMarker == nil {
		t.Fatal("expected SstpTransmitMarker to be non-nil")
	}
	if d.SstpReceiveMarker != nil {
		t.Fatal("expected SstpReceiveMarker to be nil")
	}
	if got := d.GetMethod(); got != DeliverySstp {
		t.Errorf("GetMethod() = %q, want %q", got, DeliverySstp)
	}
}

// TestOneOfDelivery_SstpReceiveMarker_Unmarshal proves the receive URN routes
// to SstpReceiveMarker and GetMethod() reports ReceiveSstp. The receive URN is
// a superstring of the transmit URN, so this also guards substring ordering.
func TestOneOfDelivery_SstpReceiveMarker_Unmarshal(t *testing.T) {
	var d OneOfStreamConfigurationDelivery
	if err := json.Unmarshal([]byte(`{"method":"`+ReceiveSstp+`"}`), &d); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if d.SstpReceiveMarker == nil {
		t.Fatal("expected SstpReceiveMarker to be non-nil")
	}
	if d.SstpTransmitMarker != nil {
		t.Fatal("expected SstpTransmitMarker to be nil")
	}
	if got := d.GetMethod(); got != ReceiveSstp {
		t.Errorf("GetMethod() = %q, want %q", got, ReceiveSstp)
	}
}

// TestOneOfDelivery_SstpMarker_RoundTrip proves a marker survives a
// marshal/unmarshal round-trip and never leaks anything beyond the method URN.
func TestOneOfDelivery_SstpMarker_RoundTrip(t *testing.T) {
	orig := OneOfStreamConfigurationDelivery{SstpTransmitMarker: &SstpTransmitMarker{Method: DeliverySstp}}
	raw, err := json.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got OneOfStreamConfigurationDelivery
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.SstpTransmitMarker == nil || got.SstpTransmitMarker.Method != DeliverySstp {
		t.Errorf("round-trip lost the transmit marker; raw=%s", raw)
	}
}

// TestOneOfDelivery_SstpMarker_DeepCopy proves DeepCopy duplicates the marker
// pointers independently.
func TestOneOfDelivery_SstpMarker_DeepCopy(t *testing.T) {
	orig := &OneOfStreamConfigurationDelivery{SstpReceiveMarker: &SstpReceiveMarker{Method: ReceiveSstp}}
	cp := orig.DeepCopy()
	if cp.SstpReceiveMarker == nil {
		t.Fatal("DeepCopy dropped SstpReceiveMarker")
	}
	if cp.SstpReceiveMarker == orig.SstpReceiveMarker {
		t.Error("DeepCopy did not allocate an independent SstpReceiveMarker")
	}
	cp.SstpReceiveMarker.Method = "mutated"
	if orig.SstpReceiveMarker.Method != ReceiveSstp {
		t.Error("DeepCopy is not independent: mutating the copy changed the original")
	}
}
