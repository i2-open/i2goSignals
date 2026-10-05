package eventRouter

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingLeaseStore is a coordinator that grants every acquire-or-renew for
// lease and counts every lease call. Any other coordinator call panics on the
// nil embedded interface.
type countingLeaseStore struct {
	cluster.ClusterCoordinator
	mu    sync.Mutex
	lease time.Duration
	held  bool
	now   func() time.Time
	calls atomic.Int64
	reads atomic.Int64
}

func (c *countingLeaseStore) TryAcquireOrRenewLease(_, _ string, d time.Duration) (bool, int64, time.Time, error) {
	c.calls.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.held {
		return false, 0, time.Time{}, nil
	}
	return true, c.calls.Load(), c.now().Add(d), nil
}

func (c *countingLeaseStore) GetLeaseOwner(string) (string, time.Time, int64, error) {
	c.reads.Add(1)
	return "node-a", c.now().Add(c.lease), 1, nil
}

func (c *countingLeaseStore) setHeld(held bool) {
	c.mu.Lock()
	c.held = held
	c.mu.Unlock()
}

// manualClock is a settable clock for the lease manager.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestLeaseSafetyMargin_Env(t *testing.T) {
	t.Setenv(leaseSafetyMarginEnv, "")
	assert.Equal(t, 5*time.Second, leaseSafetyMargin(), "default margin")
	t.Setenv(leaseSafetyMarginEnv, "2s")
	assert.Equal(t, 2*time.Second, leaseSafetyMargin())
	t.Setenv(leaseSafetyMarginEnv, "soon")
	assert.Equal(t, defaultLeaseSafetyMargin, leaseSafetyMargin(), "an unparsable value falls back")
	t.Setenv(leaseSafetyMarginEnv, "-1s")
	assert.Equal(t, time.Duration(0), leaseSafetyMargin())
}

// The tenure ends margin before the earlier of the store's leaseUntil and
// callStart + leaseDuration; a renewal extends it again; a lost lease ends it
// at once.
func TestLeaseManager_StillOwnerFollowsTenure(t *testing.T) {
	clock := &manualClock{t: time.Now()}
	store := &countingLeaseStore{lease: 30 * time.Second, held: true, now: clock.now}
	m := newLeaseManager(store)
	m.margin = 5 * time.Second
	m.now = clock.now
	resource := cluster.PushTransmitterResource("s1")

	assert.False(t, m.StillOwner(resource), "never acquired")
	held, token, err := m.acquire(resource, "node-a", 30*time.Second)
	require.NoError(t, err)
	require.True(t, held)
	assert.Positive(t, token)
	assert.True(t, m.StillOwner(resource))

	calls := store.calls.Load()
	clock.advance(24 * time.Second)
	assert.True(t, m.StillOwner(resource), "inside the tenure")
	clock.advance(2 * time.Second)
	assert.False(t, m.StillOwner(resource), "past leaseUntil - margin")
	assert.Equal(t, calls, store.calls.Load(), "StillOwner makes no lease call")
	assert.Zero(t, store.reads.Load(), "StillOwner reads no lease")

	held, _, err = m.acquire(resource, "node-a", 30*time.Second)
	require.NoError(t, err)
	require.True(t, held)
	assert.True(t, m.StillOwner(resource), "a renewal restores the tenure")

	store.setHeld(false)
	held, _, err = m.acquire(resource, "node-a", 30*time.Second)
	require.NoError(t, err)
	assert.False(t, held)
	assert.False(t, m.StillOwner(resource), "a lost lease ends the tenure at once")
}

// A store leaseUntil earlier than callStart + leaseDuration bounds the tenure,
// and so does a call start earlier than the store's clock; a margin wider than
// half the lease is clamped so a short lease keeps some tenure.
func TestLeaseManager_DeadlineBounds(t *testing.T) {
	clock := &manualClock{t: time.Now()}
	m := newLeaseManager(&countingLeaseStore{now: clock.now})
	m.margin = 5 * time.Second
	m.now = clock.now
	start := clock.now()

	m.note("a", start, true, start.Add(20*time.Second), 30*time.Second)
	clock.advance(15*time.Second - time.Millisecond)
	assert.True(t, m.StillOwner("a"))
	clock.advance(time.Millisecond)
	assert.False(t, m.StillOwner("a"), "the store's leaseUntil bounds the tenure")

	start = clock.now()
	m.note("b", start, true, start.Add(time.Hour), 30*time.Second)
	clock.advance(25 * time.Second)
	assert.False(t, m.StillOwner("b"), "callStart + leaseDuration bounds the tenure")

	start = clock.now()
	m.note("c", start, true, start.Add(2*time.Second), 2*time.Second)
	clock.advance(time.Second - time.Millisecond)
	assert.True(t, m.StillOwner("c"), "the margin is clamped to half the lease")
	clock.advance(time.Millisecond)
	assert.False(t, m.StillOwner("c"))

	m.note("c", clock.now(), false, time.Time{}, 0)
	assert.False(t, m.StillOwner("c"))
}

// With no coordinator a node is always the owner and makes no lease call; a
// nil manager (a router test literal) answers the same.
func TestLeaseManager_NoCoordinatorAlwaysOwner(t *testing.T) {
	assert.True(t, newLeaseManager(nil).StillOwner("anything"))
	var m *leaseManager
	assert.True(t, m.StillOwner("anything"))
	m.note("anything", time.Now(), true, time.Now(), time.Second)
	m.forget("anything")

	r, dao, sid := ackRouter(t, nil, nil)
	r.leases = newLeaseManager(nil)
	require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid))
	list, err := dao.ListDeliveredForStream(context.Background(), sid)
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

// A stream's DeliveryQueue skips an acknowledgement batch once the tenure has
// run out, without a lease call or a store read, and keeps the reference held;
// after a heartbeat renewal the same batch drains. The ack region reads
// nothing: goSignals_router_reads_before_ack_total stays where it was.
func TestDeliveryQueue_AckSkippedPastTenureResumesAfterRenewal(t *testing.T) {
	clock := &manualClock{t: time.Now()}
	store := &countingLeaseStore{lease: 30 * time.Second, held: true, now: clock.now}
	r, dao, sid := ackRouter(t, services.DefaultEffectiveWindow, windowDays(3))
	r.nodeId = "node-a"
	var ackReads atomic.Int64
	r.locks.onAckRead = func() { ackReads.Add(1) }
	r.coordinator = &trackedCoordinator{ClusterCoordinator: store, locks: &r.locks}
	r.leases = newLeaseManager(r.coordinator)
	r.leases.margin = 5 * time.Second
	r.leases.now = clock.now
	resource := cluster.PushTransmitterResource(sid)

	held, _, err := r.tryLease(resource, 30*time.Second)
	require.NoError(t, err)
	require.True(t, held)
	readsBefore := testutil.ToFloat64(readsBeforeAckTotal)
	calls := store.calls.Load()

	clock.advance(26 * time.Second)
	_, err = r.queueFor(sid).AckInbound(context.Background(), []string{"j1"}, true)
	require.ErrorIs(t, err, errNotLeaseOwner)
	list, err := dao.ListDeliveredForStream(context.Background(), sid)
	require.NoError(t, err)
	assert.Empty(t, list, "a skipped batch writes nothing")
	assert.Equal(t, calls, store.calls.Load(), "the ack path makes no lease call")
	assert.Zero(t, store.reads.Load(), "the ack path reads no lease")

	hb := leaseHeartbeat{Coordinator: r.coordinator, Manager: r.leaseRenewer(), Resource: resource, NodeId: r.nodeId}
	renewed, err := hb.renew(30 * time.Second)
	require.NoError(t, err)
	require.True(t, renewed)
	calls = store.calls.Load()

	_, err = r.queueFor(sid).AckInbound(context.Background(), []string{"j1"}, true)
	require.NoError(t, err)
	list, err = dao.ListDeliveredForStream(context.Background(), sid)
	require.NoError(t, err)
	assert.Len(t, list, 1, "the batch drains after the renewal")
	assert.Equal(t, calls, store.calls.Load(), "the ack path makes no lease call")
	assert.Zero(t, store.reads.Load())
	assert.Zero(t, ackReads.Load(), "no coordinator read inside an ack region")
	assert.Equal(t, readsBefore, testutil.ToFloat64(readsBeforeAckTotal))

	// The instrument counts a read made inside an ack region.
	r.locks.enterAck()
	_, _, _, _ = r.coordinator.TryAcquireOrRenewLease(resource, r.nodeId, time.Second)
	r.locks.exitAck()
	assert.Equal(t, int64(1), ackReads.Load())
	assert.Equal(t, readsBefore+1, testutil.ToFloat64(readsBeforeAckTotal))
}
