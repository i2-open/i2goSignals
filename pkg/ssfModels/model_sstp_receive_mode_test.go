package model

import (
	"encoding/json"
	"testing"
)

// Per-direction receive_mode on an SSTP bootstrap (issue #306, Part 1).
//
// A direction's mode is read one way by its transmitter (== FW: relay or
// re-sign) and another by its receiver (== IM: import or route on), so one value
// per direction cannot say "relay verbatim, and import only at the far end".
// receive_mode is the receiving end's half of that choice. It is optional, and
// when it is absent every byte and every stored route mode is what it was
// before the field existed.

func TestSstpReceiveModeToRouteMode(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		valid bool
	}{
		{SstpModeImport, RouteModeImport, true},
		{SstpModeForward, RouteModeForward, true},
		// A receiver cannot tell PUBLISH from FORWARD (ADR 0031 D2), so it is
		// not a receive-side choice.
		{SstpModePublish, "", false},
		// Absent is not a value: the direction falls back to mode instead.
		{"", "", false},
		// Case-sensitive, like SstpModeToRouteMode.
		{"import", "", false},
		{"bogus", "", false},
	}
	for _, c := range cases {
		got, ok := SstpReceiveModeToRouteMode(c.in)
		if ok != c.valid {
			t.Fatalf("receive_mode %q: valid=%v want %v", c.in, ok, c.valid)
		}
		if got != c.want {
			t.Fatalf("receive_mode %q: got %q want %q", c.in, got, c.want)
		}
	}
}

// ReceiveRouteMode is the route mode the RECEIVING end of a direction stores.
func TestSstpDirectionReceiveRouteMode(t *testing.T) {
	cases := []struct {
		name string
		dir  SstpDirection
		want string
	}{
		{"absent receive_mode mirrors mode, as before", SstpDirection{Mode: SstpModeForward}, RouteModeForward},
		{"absent receive_mode and absent mode keeps the PUBLISH default", SstpDirection{}, RouteModePublish},
		{"absent receive_mode mirrors IMPORT", SstpDirection{Mode: SstpModeImport}, RouteModeImport},
		{"the inexpressible row: relay verbatim, import only", SstpDirection{Mode: SstpModeForward, ReceiveMode: SstpModeImport}, RouteModeImport},
		{"re-sign, then route on", SstpDirection{Mode: SstpModePublish, ReceiveMode: SstpModeForward}, RouteModeForward},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.dir.ReceiveRouteMode(); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// A bootstrap that does not carry the field must marshal exactly as it did
// before the field existed, so the mirror sent to a peer — which may predate
// #306 — is unchanged.
func TestSstpDirectionOmitsAbsentReceiveMode(t *testing.T) {
	raw, err := json.Marshal(SstpDirection{
		Iss:  "https://alpha.example.com",
		Aud:  []string{"https://beta.example.com"},
		Mode: SstpModeImport,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"iss":"https://alpha.example.com","aud":["https://beta.example.com"],"mode":"IMPORT"}`
	if string(raw) != want {
		t.Fatalf("bytes changed:\n got %s\nwant %s", raw, want)
	}
}

func TestSstpDirectionDecodesReceiveMode(t *testing.T) {
	var boot SstpPairBootstrap
	body := []byte(`{"role":"responder",
		"primary":{"iss":"a","aud":["b"],"mode":"FORWARD","receive_mode":"IMPORT"},
		"inbound":{"iss":"b","aud":["a"],"mode":"PUBLISH"}}`)
	if !IsSstpBootstrapBody(body) {
		t.Fatal("the discriminator must still recognize the body")
	}
	if err := json.Unmarshal(body, &boot); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if boot.Primary.ReceiveMode != SstpModeImport {
		t.Errorf("primary.receive_mode: got %q", boot.Primary.ReceiveMode)
	}
	if boot.Inbound.ReceiveMode != "" {
		t.Errorf("an omitted receive_mode must decode empty, got %q", boot.Inbound.ReceiveMode)
	}
}

// The record carries each direction's receive_mode as bootstrapped, on the
// record-level twins that follow the EventSource / InboundEventSource
// convention, so the pair read can echo it.
func TestStreamStateRecordReceiveModeTwins(t *testing.T) {
	t.Run("omitted from the wire when unset", func(t *testing.T) {
		raw, err := json.Marshal(&StreamStateRecord{PairId: "pair-1"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, key := range []string{"receive_mode", "inbound_receive_mode"} {
			if _, present := doc[key]; present {
				t.Errorf("a record with no receive_mode must omit %q", key)
			}
		}
	})

	t.Run("serialized under their own names", func(t *testing.T) {
		raw, err := json.Marshal(&StreamStateRecord{
			PairId:             "pair-1",
			ReceiveMode:        SstpModeImport,
			InboundReceiveMode: SstpModeForward,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if doc["receive_mode"] != SstpModeImport {
			t.Errorf("receive_mode: got %v", doc["receive_mode"])
		}
		if doc["inbound_receive_mode"] != SstpModeForward {
			t.Errorf("inbound_receive_mode: got %v", doc["inbound_receive_mode"])
		}
	})

	// Update is the in-place merge that preserves live handles; a field it
	// forgets is discarded on every update of the record.
	t.Run("Update carries both twins", func(t *testing.T) {
		stored := &StreamStateRecord{PairId: "pair-1"}
		stored.Update(&StreamStateRecord{
			PairId:             "pair-1",
			ReceiveMode:        SstpModeImport,
			InboundReceiveMode: SstpModeForward,
		})
		if stored.ReceiveMode != SstpModeImport || stored.InboundReceiveMode != SstpModeForward {
			t.Errorf("got receive_mode=%q inbound_receive_mode=%q", stored.ReceiveMode, stored.InboundReceiveMode)
		}
	})
}
