package memory_provider

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

// TestMemoryCoordinator_MutualExclusion proves the lease seam holds the
// invariant the production cluster relies on: at most one caller acquires
// when N goroutines race for the same free resource.
func TestMemoryCoordinator_MutualExclusion(t *testing.T) {
	c := NewMemoryCoordinator()

	const goroutines = 50
	var wg sync.WaitGroup
	var winners int64

	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		nodeId := "node-" + string(rune('A'+i%26)) + "-" + time.Now().Format("150405.000000")
		wg.Add(1)
		go func(nid string) {
			defer wg.Done()
			<-start
			ok, _, _, err := c.TryAcquireOrRenewLease("push-transmitter:s1", nid, 5*time.Second)
			assert.NoError(t, err)
			if ok {
				atomic.AddInt64(&winners, 1)
			}
		}(nodeId)
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), atomic.LoadInt64(&winners), "exactly one node should acquire")
}

// TestMemoryCoordinator_TakeoverAfterExpiry proves a different node can
// acquire once the previous owner's lease has elapsed without an explicit
// release. This is the recovery path when a node crashes mid-task.
func TestMemoryCoordinator_TakeoverAfterExpiry(t *testing.T) {
	c := NewMemoryCoordinator()
	resource := "push-transmitter:s2"

	ok, _, _, err := c.TryAcquireOrRenewLease(resource, "node-A", 50*time.Millisecond)
	assert.NoError(t, err)
	assert.True(t, ok)

	// Before expiry, node-B is locked out.
	ok, _, _, _ = c.TryAcquireOrRenewLease(resource, "node-B", 5*time.Second)
	assert.False(t, ok, "lease still held by node-A")

	time.Sleep(80 * time.Millisecond)

	// After expiry, node-B takes over.
	ok, _, _, err = c.TryAcquireOrRenewLease(resource, "node-B", 5*time.Second)
	assert.NoError(t, err)
	assert.True(t, ok, "node-B should acquire after node-A's lease expires")

	owner, _, _, _ := c.GetLeaseOwner(resource)
	assert.Equal(t, "node-B", owner)
}

// TestMemoryCoordinator_FencingTokenMonotonic proves the fencing token
// strictly increases on every new tenure (a first acquire, a takeover after
// expiry, a re-acquire after release) and is kept by the holder's own renewal
// of a live lease, so the holder's acks stay valid across heartbeats (#334).
// Receivers downstream of the lease holder use this token to reject stale writes.
func TestMemoryCoordinator_FencingTokenMonotonic(t *testing.T) {
	c := NewMemoryCoordinator()
	resource := "push-transmitter:s3"

	_, t1, _, err := c.TryAcquireOrRenewLease(resource, "node-A", 200*time.Millisecond)
	assert.NoError(t, err)

	// Renew by same owner of a live lease — token is kept.
	_, t2, _, _ := c.TryAcquireOrRenewLease(resource, "node-A", 200*time.Millisecond)
	assert.Equal(t, t1, t2)

	// Wait for expiry, takeover by another node — token increments.
	time.Sleep(220 * time.Millisecond)
	_, t3, _, _ := c.TryAcquireOrRenewLease(resource, "node-B", 200*time.Millisecond)
	assert.Greater(t, t3, t2)

	// Concurrent failed-acquire attempts must NOT advance the token.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _ = c.TryAcquireOrRenewLease(resource, "node-C", 200*time.Millisecond)
		}()
	}
	wg.Wait()
	_, _, t4, _ := c.GetLeaseOwner(resource)
	assert.Equal(t, t3, t4, "failed acquires must not change the fencing token")
}

// TestMemoryCoordinator_ExpiredLeaseReadsUnowned proves an elapsed lease
// reads as unowned without any release, and that a re-acquire of an expired
// lease by its former owner starts a new tenure with a higher token (#334).
func TestMemoryCoordinator_ExpiredLeaseReadsUnowned(t *testing.T) {
	c := NewMemoryCoordinator()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return clock })
	resource := "push-transmitter:s5"

	ok, t1, leaseUntil, err := c.TryAcquireOrRenewLease(resource, "node-A", 30*time.Second)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, clock.Add(30*time.Second), leaseUntil, "acquire returns the lease's expiry (#364)")
	held, _, otherUntil, err := c.TryAcquireOrRenewLease(resource, "node-B", 30*time.Second)
	assert.NoError(t, err)
	assert.False(t, held)
	assert.True(t, otherUntil.IsZero(), "a lease held elsewhere returns no expiry")
	owner, _, tok, _ := c.GetLeaseOwner(resource)
	assert.Equal(t, "node-A", owner)
	assert.Equal(t, t1, tok)

	clock = clock.Add(30 * time.Second)
	owner, until, tok, err := c.GetLeaseOwner(resource)
	assert.NoError(t, err)
	assert.Equal(t, "", owner, "an expired lease has no owner")
	assert.True(t, until.IsZero())
	assert.Equal(t, int64(0), tok)

	ok, t2, _, _ := c.TryAcquireOrRenewLease(resource, "node-A", 30*time.Second)
	assert.True(t, ok)
	assert.Greater(t, t2, t1, "re-acquiring an expired lease is a new tenure")
}

// TestMemoryCoordinator_ReleasedLeaseReadsUnowned proves a released lease
// reads as unowned at once.
func TestMemoryCoordinator_ReleasedLeaseReadsUnowned(t *testing.T) {
	c := NewMemoryCoordinator()
	resource := "push-transmitter:s6"
	_, _, _, _ = c.TryAcquireOrRenewLease(resource, "node-A", 30*time.Second)
	assert.NoError(t, c.ReleaseLeaseIfOwned(resource, "node-A"))
	owner, _, _, _ := c.GetLeaseOwner(resource)
	assert.Equal(t, "", owner)
}

// TestMemoryCoordinator_ReleaseIfOwned proves only the current owner can
// release, and a fresh acquire is possible immediately after a successful
// release.
func TestMemoryCoordinator_ReleaseIfOwned(t *testing.T) {
	c := NewMemoryCoordinator()
	resource := "push-transmitter:s4"

	_, _, _, _ = c.TryAcquireOrRenewLease(resource, "node-A", 5*time.Second)

	// Non-owner attempts to release — no-op.
	err := c.ReleaseLeaseIfOwned(resource, "node-B")
	assert.NoError(t, err)
	owner, _, _, _ := c.GetLeaseOwner(resource)
	assert.Equal(t, "node-A", owner, "non-owner release must not change the owner")

	// Owner releases — lease is now free.
	err = c.ReleaseLeaseIfOwned(resource, "node-A")
	assert.NoError(t, err)

	// Another node can acquire immediately.
	ok, _, _, err := c.TryAcquireOrRenewLease(resource, "node-B", 5*time.Second)
	assert.NoError(t, err)
	assert.True(t, ok, "node-B should acquire immediately after node-A releases")
}

// TestMemoryCoordinator_NodeRegistryActiveFiltering proves the active-window
// (60s) filter agrees with the Mongo-side definition of "alive": stale
// heartbeats drop off both the count and the listing; fresh heartbeats are
// included; GetNode returns the latest registration regardless of freshness.
func TestMemoryCoordinator_NodeRegistryActiveFiltering(t *testing.T) {
	c := NewMemoryCoordinator()

	now := time.Now().UTC()
	fresh := model.ClusterNode{Id: "node-fresh", Address: "http://h:1", LastSeenAt: now}
	stale := model.ClusterNode{Id: "node-stale", Address: "http://h:2", LastSeenAt: now.Add(-90 * time.Second)}

	assert.NoError(t, c.RegisterNode(fresh))
	assert.NoError(t, c.RegisterNode(stale))

	count, err := c.GetActiveNodeCount()
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count, "only the fresh node is active")

	nodes, err := c.GetActiveNodes()
	assert.NoError(t, err)
	assert.Len(t, nodes, 1)
	assert.Equal(t, "node-fresh", nodes[0].Id)

	// GetNode returns either node, regardless of staleness.
	n, err := c.GetNode("node-stale")
	assert.NoError(t, err)
	assert.NotNil(t, n)
	assert.Equal(t, "node-stale", n.Id)

	miss, err := c.GetNode("nope")
	assert.NoError(t, err)
	assert.Nil(t, miss)

	// Re-registering with a fresher heartbeat moves the node into "active".
	fresher := stale
	fresher.LastSeenAt = now
	assert.NoError(t, c.RegisterNode(fresher))

	count, _ = c.GetActiveNodeCount()
	assert.Equal(t, int64(2), count)
}
