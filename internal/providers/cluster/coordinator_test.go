package cluster

import "testing"

// Every lease kind the cluster takes names a stream or pair, so the
// cluster-row GC can drop its row once that stream is deleted (#365).
func TestResourceId_KnowsEveryLeaseKind(t *testing.T) {
	for _, resource := range []string{
		PushTransmitterResource("s1"),
		PollReceiverResource("s1"),
		SstpClientResource("s1"),
		PollTransmitterResource("s1"),
		SstpServerResource("s1"),
	} {
		_, id, ok := ResourceId(resource)
		if !ok || id != "s1" {
			t.Errorf("ResourceId(%q) = %q, %v; want s1, true", resource, id, ok)
		}
	}
	if _, _, ok := ResourceId("other:s1"); ok {
		t.Error("an unknown kind is reported as known")
	}
}

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
