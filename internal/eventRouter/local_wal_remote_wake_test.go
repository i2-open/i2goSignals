package eventRouter

import (
	"fmt"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #347: in ring-fed local-durability mode the targets were all woken at WAL
// append. The overlay that serves a SET before the drain stores it is local
// to this node, so a remote owner woken then found nothing in the store, and
// the 250 ms wake coalescing made a second wake at commit a no-op. The remote
// wake must wait until the drain has stored the SET.
func TestLocalWal_RingFedRemoteOwnerWokenAfterDrain(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	p := openMemPersistence(t)
	gate := make(chan struct{})
	s := newWalRouterWith(t, p, t.TempDir(), &gatedEventDAO{EventDAO: p.EventDAO, gate: gate}, ringFed)
	r := s.router

	pairId := "pair-rf-remote"
	pair := sstpClientPairForMatch("sstp-tx-rf-remote", pairId)
	r.mu.Lock()
	r.sstpClientStreams[pairId] = *pair
	r.sstpBuffers[pairId] = buffer.CreateEventPollBuffer(nil, 1, 1)
	r.mu.Unlock()

	wakes := make(chan capturedSstpWake, 4)
	peer := stubWakePeer(t, wakes)
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-B", Address: peer.URL, LastSeenAt: time.Now().UTC()}))
	acquired, _, err := r.coordinator.TryAcquireOrRenewLease(fmt.Sprintf("sstp-client:%s", pairId), "node-B", 30*time.Second)
	require.NoError(t, err)
	require.True(t, acquired)

	require.NoError(t, r.HandleEvent(newRiscToken("rf-remote-1", dupTestIssuer, s.audience), `{"raw":true}`, s.streamID))
	select {
	case got := <-wakes:
		t.Fatalf("remote owner woken before the drain stored the SET: %+v", got)
	case <-time.After(400 * time.Millisecond):
	}
	assert.False(t, s.stored("rf-remote-1"))

	close(gate)
	s.waitDrained(t)
	got := waitForWake(t, wakes, "/_cluster/wake-sstp-client")
	assert.Equal(t, pairId, got.body["sid"], "the remote owner is woken once the SET is stored")
}
