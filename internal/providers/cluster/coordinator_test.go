package cluster

import "testing"

// ParseResource inverts LeaseKind.Resource for every kind, and splits an
// unknown kind without vouching for it.
func TestParseResource_RoundTripsEveryKind(t *testing.T) {
	for _, k := range []LeaseKind{PushTransmitter, PollReceiver, SstpClient, PollTransmitter, SstpServer} {
		kind, id, ok := ParseResource(k.Resource("s1"))
		if !ok || kind != k || id != "s1" {
			t.Errorf("ParseResource(%q) = %q, %q, %v", k.Resource("s1"), kind, id, ok)
		}
	}
	if kind, id, ok := ParseResource("other:s1"); ok || kind != "other" || id != "s1" {
		t.Errorf("unknown kind: got %q, %q, %v", kind, id, ok)
	}
	if _, _, ok := ParseResource("push-transmitter:"); ok {
		t.Error("an empty id is not a resource")
	}
}
