package eventRouter

import (
	"testing"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #347 review: the outbound wake coalesced on the leading edge only, so the
// wake for a SET written just after the first one of a burst was dropped and
// the owner waited for its backfill tick. A wake suppressed inside the window
// arms one trailing wake at the window's end.
func TestSendWakeup_BurstTailArmsOneTrailingWake(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	h := newClusterFilterHarness(t, "node-A")

	wakes := make(chan capturedSstpWake, 8)
	peer := stubWakePeer(t, wakes)
	require.NoError(t, h.router.coordinator.RegisterNode(model.ClusterNode{Id: "node-B", Address: peer.URL}))

	const sid = "sid-burst-tail"
	for i := 0; i < 3; i++ {
		h.router.sendWakeup(sid, "push", "node-B", "")
	}

	first := waitForWake(t, wakes, "/_cluster/wake-transmitter")
	assert.Equal(t, sid, first.body["sid"])
	second := waitForWake(t, wakes, "/_cluster/wake-transmitter")
	assert.Equal(t, sid, second.body["sid"], "the burst's tail is followed by a trailing wake")

	select {
	case got := <-wakes:
		t.Fatalf("the suppressed wakes share one trailing wake, got another: %+v", got)
	case <-time.After(400 * time.Millisecond):
	}
}
