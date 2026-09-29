package eventRouter

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
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

// countingLeaseReads counts GetLeaseOwner calls on the wrapped coordinator.
type countingLeaseReads struct {
	cluster.ClusterCoordinator
	reads atomic.Int64
}

func (c *countingLeaseReads) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
	c.reads.Add(1)
	return c.ClusterCoordinator.GetLeaseOwner(resource)
}

// #347 review: the commit-time remote wake runs on the WAL drain path for
// every committed entry. For an SSTP-client target it must not add a second
// uncached cluster_leases read on top of the one made at append; the wake is
// a coalesced broadcast that every node but the owner ignores.
func TestLocalWal_RingFedCommitWakeReadsNoLease(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	p := openMemPersistence(t)
	gate := make(chan struct{})
	counting := &countingLeaseReads{ClusterCoordinator: p.Coordinator}
	s := newWalRouterWith(t, p, t.TempDir(), &gatedEventDAO{EventDAO: p.EventDAO, gate: gate}, func(d *RouterDeps) {
		ringFed(d)
		d.Coordinator = counting
	})
	r := s.router

	pairId := "pair-rf-noread"
	pair := sstpClientPairForMatch("sstp-tx-rf-noread", pairId)
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

	require.NoError(t, r.HandleEvent(newRiscToken("rf-noread-1", dupTestIssuer, s.audience), `{"raw":true}`, s.streamID))
	require.Eventually(t, func() bool { return counting.reads.Load() >= 1 }, time.Second, time.Millisecond,
		"the append-time local wake reads the owner")
	atAppend := counting.reads.Load()

	close(gate)
	s.waitDrained(t)
	got := waitForWake(t, wakes, "/_cluster/wake-sstp-client")
	assert.Equal(t, pairId, got.body["sid"], "the remote owner is still woken once the SET is stored")
	assert.Equal(t, atAppend, counting.reads.Load(), "the commit-time wake adds no lease read")
}
