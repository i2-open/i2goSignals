package model

import (
	"encoding/json"
	"testing"
)

// newSstpPairRecord builds a representative bidirectional SSTP StreamStateRecord:
// transmit side in the primary StreamConfiguration, receive side in SstpInbound,
// connectivity in SstpMethod, with per-direction status fields populated.
func newSstpPairRecord() *StreamStateRecord {
	rec := &StreamStateRecord{
		PairId: "pair-abc123",
		StreamConfiguration: StreamConfiguration{
			Id:       "tx-sid-1",
			Iss:      "https://tx.example",
			Delivery: &OneOfStreamConfigurationDelivery{SstpTransmitMarker: &SstpTransmitMarker{Method: DeliverySstp}},
		},
		Status:   StreamStateEnabled,
		ErrorMsg: "",
		SstpInbound: &StreamConfiguration{
			Id:       "rx-sid-1",
			Iss:      "https://rx.example",
			Delivery: &OneOfStreamConfigurationDelivery{SstpReceiveMarker: &SstpReceiveMarker{Method: ReceiveSstp}},
		},
		SstpMethod: &SstpMethod{
			Role:                SstpRoleInitiator,
			EndpointUrl:         "https://peer.example/sstp/pair-peer999",
			AuthorizationHeader: "Bearer secret-token",
			PeerPairId:          "pair-peer999",
		},
		InboundStatus:   StreamStatePause,
		InboundErrorMsg: "peer unreachable",
	}
	return rec
}

// TestStreamStateRecord_Sstp_GetType proves an SSTP pair record reports the
// DeliverySstpPair discriminator.
func TestStreamStateRecord_Sstp_GetType(t *testing.T) {
	rec := newSstpPairRecord()
	if got := rec.GetType(); got != DeliverySstpPair {
		t.Errorf("GetType() = %q, want %q", got, DeliverySstpPair)
	}
}

// TestStreamStateRecord_Sstp_HasInboundOutbound proves both directions report
// true for an SSTP pair.
func TestStreamStateRecord_Sstp_HasInboundOutbound(t *testing.T) {
	rec := newSstpPairRecord()
	if !rec.HasInbound() {
		t.Error("HasInbound() = false, want true for SSTP pair")
	}
	if !rec.HasOutbound() {
		t.Error("HasOutbound() = false, want true for SSTP pair")
	}
}

// TestStreamStateRecord_HasInboundOutbound_Push proves HasInbound/HasOutbound
// fall through to IsReceiver/IsTransmitter for RFC8935 push records.
func TestStreamStateRecord_HasInboundOutbound_Push(t *testing.T) {
	tx := &StreamStateRecord{StreamConfiguration: StreamConfiguration{
		Delivery: &OneOfStreamConfigurationDelivery{PushTransmitMethod: &PushTransmitMethod{Method: DeliveryPush}},
	}}
	if !tx.HasOutbound() {
		t.Error("push transmitter HasOutbound() = false, want true")
	}
	if tx.HasInbound() {
		t.Error("push transmitter HasInbound() = true, want false")
	}

	rx := &StreamStateRecord{StreamConfiguration: StreamConfiguration{
		Delivery: &OneOfStreamConfigurationDelivery{PushReceiveMethod: &PushReceiveMethod{Method: ReceivePush}},
	}}
	if !rx.HasInbound() {
		t.Error("push receiver HasInbound() = false, want true")
	}
	if rx.HasOutbound() {
		t.Error("push receiver HasOutbound() = true, want false")
	}
}

// TestStreamStateRecord_HasInboundOutbound_Poll proves the same fall-through for
// RFC8936 poll records.
func TestStreamStateRecord_HasInboundOutbound_Poll(t *testing.T) {
	tx := &StreamStateRecord{StreamConfiguration: StreamConfiguration{
		Delivery: &OneOfStreamConfigurationDelivery{PollTransmitMethod: &PollTransmitMethod{Method: DeliveryPoll}},
	}}
	if !tx.HasOutbound() || tx.HasInbound() {
		t.Errorf("poll transmitter HasOutbound=%v HasInbound=%v, want true/false", tx.HasOutbound(), tx.HasInbound())
	}

	rx := &StreamStateRecord{StreamConfiguration: StreamConfiguration{
		Delivery: &OneOfStreamConfigurationDelivery{PollReceiveMethod: &PollReceiveMethod{Method: ReceivePoll}},
	}}
	if !rx.HasInbound() || rx.HasOutbound() {
		t.Errorf("poll receiver HasInbound=%v HasOutbound=%v, want true/false", rx.HasInbound(), rx.HasOutbound())
	}
}

// TestStreamStateRecord_Sstp_JSONRoundTrip proves the new bidirectional fields
// survive a JSON marshal/unmarshal cycle with values populated.
func TestStreamStateRecord_Sstp_JSONRoundTrip(t *testing.T) {
	orig := newSstpPairRecord()
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got StreamStateRecord
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if got.PairId != orig.PairId {
		t.Errorf("PairId = %q, want %q", got.PairId, orig.PairId)
	}
	if got.InboundStatus != orig.InboundStatus {
		t.Errorf("InboundStatus = %q, want %q", got.InboundStatus, orig.InboundStatus)
	}
	if got.InboundErrorMsg != orig.InboundErrorMsg {
		t.Errorf("InboundErrorMsg = %q, want %q", got.InboundErrorMsg, orig.InboundErrorMsg)
	}
	if got.SstpInbound == nil {
		t.Fatal("SstpInbound lost in round-trip")
	}
	if got.SstpInbound.Id != orig.SstpInbound.Id {
		t.Errorf("SstpInbound.Id = %q, want %q", got.SstpInbound.Id, orig.SstpInbound.Id)
	}
	if got.SstpInbound.Delivery.GetMethod() != ReceiveSstp {
		t.Errorf("SstpInbound delivery method = %q, want %q", got.SstpInbound.Delivery.GetMethod(), ReceiveSstp)
	}
	if got.SstpMethod == nil {
		t.Fatal("SstpMethod lost in round-trip")
	}
	if got.SstpMethod.Role != orig.SstpMethod.Role {
		t.Errorf("SstpMethod.Role = %q, want %q", got.SstpMethod.Role, orig.SstpMethod.Role)
	}
	if got.SstpMethod.AuthorizationHeader != orig.SstpMethod.AuthorizationHeader {
		t.Errorf("SstpMethod.AuthorizationHeader = %q, want %q", got.SstpMethod.AuthorizationHeader, orig.SstpMethod.AuthorizationHeader)
	}
	if got.SstpMethod.PeerPairId != orig.SstpMethod.PeerPairId {
		t.Errorf("SstpMethod.PeerPairId = %q, want %q", got.SstpMethod.PeerPairId, orig.SstpMethod.PeerPairId)
	}
}

// TestStreamStateRecord_Sstp_JSONOmitEmpty proves the new fields are absent from
// the JSON when unset (a non-SSTP record pays no marshaling cost).
func TestStreamStateRecord_Sstp_JSONOmitEmpty(t *testing.T) {
	rec := &StreamStateRecord{StreamConfiguration: StreamConfiguration{Id: "plain"}}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(raw)
	for _, frag := range []string{"sstp_inbound", "sstp_method", "pair_id", "inbound_status", "inbound_error_msg"} {
		if containsField(s, frag) {
			t.Errorf("expected %q absent from JSON of empty record, got %s", frag, s)
		}
	}
}

func containsField(s, frag string) bool {
	return len(s) > 0 && (indexOf(s, `"`+frag+`"`) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestStreamStateRecord_Sstp_DeepCopy proves DeepCopy clones the new pointer
// fields independently.
func TestStreamStateRecord_Sstp_DeepCopy(t *testing.T) {
	orig := newSstpPairRecord()
	cp := orig.DeepCopy()
	if cp.SstpInbound == nil || cp.SstpInbound == orig.SstpInbound {
		t.Fatal("DeepCopy did not allocate an independent SstpInbound")
	}
	if cp.SstpMethod == nil || cp.SstpMethod == orig.SstpMethod {
		t.Fatal("DeepCopy did not allocate an independent SstpMethod")
	}
	cp.SstpMethod.AuthorizationHeader = "mutated"
	if orig.SstpMethod.AuthorizationHeader == "mutated" {
		t.Error("DeepCopy SstpMethod is not independent")
	}
}
