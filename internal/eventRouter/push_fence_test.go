package eventRouter

import (
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clockSetter is the test hook the memory coordinator exposes.
type clockSetter interface {
	SetClock(now func() time.Time)
}

// leaseClock is a settable clock for the coordinator.
type leaseClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *leaseClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *leaseClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// waitLeaseOwner waits until resource is owned by owner and returns its token.
func waitLeaseOwner(t *testing.T, coord cluster.ClusterCoordinator, resource, owner string) int64 {
	t.Helper()
	var token int64
	require.Eventually(t, func() bool {
		o, _, tok, err := coord.GetLeaseOwner(resource)
		token = tok
		return err == nil && o == owner
	}, 10*time.Second, 5*time.Millisecond, "lease %s never owned by %s", resource, owner)
	return token
}

// A lease that expired and was taken by another node carries a higher
// fencing token, and the old owner's recorded tenure has run out: its ack
// writes nothing and makes no lease call (#364). A runner that loses its lease
// releases nothing it does not own.
func TestPushFence_AckRefusedAfterTakeover(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	coord := unwrapCoordinator(h.router.coordinator)
	setter, ok := coord.(clockSetter)
	require.True(t, ok, "memory coordinator exposes SetClock")
	clock := &leaseClock{t: time.Now().UTC()}
	setter.SetClock(clock.now)
	t.Cleanup(func() { setter.SetClock(nil) })
	require.NotNil(t, h.router.leases)
	h.router.leases.now = clock.now

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 3)
	resource := cluster.PushTransmitterResource(sid)

	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)
	oldToken := waitLeaseOwner(t, coord, resource, "node-restart")
	require.Greater(t, oldToken, int64(0))
	require.True(t, h.router.leases.StillOwner(resource))

	// The lease lapses and node-b takes it over.
	clock.advance(time.Minute)
	took, newToken, _, err := coord.TryAcquireOrRenewLease(resource, "node-b", time.Hour)
	require.NoError(t, err)
	require.True(t, took)
	require.Greater(t, newToken, oldToken)

	before := h.pendingCount(sid)
	err = h.router.ackEvents(t.Context(), jtis, sid)
	require.ErrorIs(t, err, errNotLeaseOwner)
	assert.Equal(t, before, h.pendingCount(sid), "an ack past the tenure writes nothing")

	// The runner stopping must not release node-b's lease.
	runner := h.runnerFor(sid)
	rx.release()
	h.router.RemoveStream(sid)
	waitFinished(t, runner, "push runner did not stop")
	owner, _, token, err := coord.GetLeaseOwner(resource)
	require.NoError(t, err)
	assert.Equal(t, "node-b", owner)
	assert.Equal(t, newToken, token)
}

// A push runner that stops releases its lease at once, so it reads as unowned
// without waiting out the TTL.
func TestPushFence_RunnerReleasesLeaseOnStop(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	coord := unwrapCoordinator(h.router.coordinator)

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 2)
	resource := cluster.PushTransmitterResource(sid)

	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)
	waitLeaseOwner(t, coord, resource, "node-restart")

	runner := h.runnerFor(sid)
	rx.release()
	h.router.RemoveStream(sid)
	waitFinished(t, runner, "push runner did not stop")

	owner, _, token, err := coord.GetLeaseOwner(resource)
	require.NoError(t, err)
	assert.Empty(t, owner, "a stopped runner leaves its lease unowned")
	assert.Equal(t, int64(0), token)
}

// ackResource names the push lease for a push stream and nothing for a stream
// the router holds no lease for; the push runner's acquisition records a
// tenure the lease manager answers from.
func TestPushFence_AckResourceAndTenure(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)

	assert.Empty(t, h.router.ackResource("no-such-stream"))
	assert.True(t, h.router.stillOwnsAck("no-such-stream"), "an unleased stream is not checked")

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 1)
	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)
	waitLeaseOwner(t, h.router.coordinator, cluster.PushTransmitterResource(sid), "node-restart")

	assert.Equal(t, cluster.PushTransmitterResource(sid), h.router.ackResource(sid))
	assert.True(t, h.router.stillOwnsAck(sid))
	rx.release()
}
