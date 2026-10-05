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
