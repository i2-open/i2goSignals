package model

import (
	"encoding/json"
	"testing"
)

// PollParameters is also a stream's stored poll configuration. Decoding one
// is plain struct decoding: an explicit "maxEvents": 0 never marks it
// acknowledgement-only, which is detected only on the RFC 8936 wire request
// (goSetPoll.PollRequest) (#369).
func TestPollParameters_StoredConfigMaxEventsZeroIsNotAckOnly(t *testing.T) {
	var cfg PollParameters
	if err := json.Unmarshal([]byte(`{"maxEvents":0,"returnImmediately":true,"timeoutSecs":30}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AckOnly || cfg.MaxEvents != 0 || !cfg.ReturnImmediately || cfg.TimeoutSecs != 30 {
		t.Fatalf("stored config must decode as plain fields, got %+v", cfg)
	}

	var method PollReceiveMethod
	if err := json.Unmarshal([]byte(`{"method":"urn:ietf:rfc:8936:receive","endpoint_url":"https://tx.example.com/poll","poll_config":{"maxEvents":0}}`), &method); err != nil {
		t.Fatal(err)
	}
	if method.PollConfig == nil || method.PollConfig.AckOnly {
		t.Fatalf("a receive method's poll_config is never ack-only, got %+v", method.PollConfig)
	}
}

// A stored config marshals exactly as the plain struct did before #369:
// a zero maxEvents is omitted and AckOnly is never serialized.
func TestPollParameters_StoredConfigRoundTripIsPlain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`{"maxEvents":0,"returnImmediately":true}`, `{"returnImmediately":true}`},
		{`{"maxEvents":7,"timeoutSecs":5}`, `{"maxEvents":7,"timeoutSecs":5}`},
		{`{"maxEvents":3,"returnImmediately":true,"ack":["a"],"setErrs":{"b":{"err":"x"}},"timeoutSecs":9}`,
			`{"maxEvents":3,"returnImmediately":true,"ack":["a"],"setErrs":{"b":{"err":"x"}},"timeoutSecs":9}`},
	}
	for _, c := range cases {
		var cfg PollParameters
		if err := json.Unmarshal([]byte(c.in), &cfg); err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != c.want {
			t.Fatalf("round trip of %s: got %s, want %s", c.in, out, c.want)
		}
	}

	out, err := json.Marshal(PollParameters{AckOnly: true, ReturnImmediately: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"returnImmediately":true}` {
		t.Fatalf("AckOnly is in-process only and never serialized, got %s", out)
	}
}
