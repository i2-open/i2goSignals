package eventRouter

import (
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/services"
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

// An ack carrying the token of a lease that expired and was taken by another
// node is refused before any write, and a runner that loses its lease releases
// nothing it does not own.
func TestPushFence_StaleTokenAckRejectedAfterTakeover(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	coord := h.router.coordinator
	setter, ok := coord.(clockSetter)
	require.True(t, ok, "memory coordinator exposes SetClock")
	clock := &leaseClock{t: time.Now().UTC()}
	setter.SetClock(clock.now)
	t.Cleanup(func() { setter.SetClock(nil) })

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 3)
	resource := cluster.PushTransmitterResource(sid)

	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)
	oldToken := waitLeaseOwner(t, coord, resource, "node-restart")
	require.Greater(t, oldToken, services.NoFencingToken)

	// The lease lapses and node-b takes it over.
	clock.advance(time.Minute)
	took, newToken, err := coord.TryAcquireOrRenewLease(resource, "node-b", time.Hour)
	require.NoError(t, err)
	require.True(t, took)
	require.Greater(t, newToken, oldToken)

	before := h.pendingCount(sid)
	err = h.eventService.AckEvents(t.Context(), jtis, sid, oldToken)
	require.ErrorIs(t, err, services.ErrStaleFencingToken)
	err = h.eventService.AckEvent(t.Context(), jtis[0], sid, oldToken)
	require.ErrorIs(t, err, services.ErrStaleFencingToken)
	assert.Equal(t, before, h.pendingCount(sid), "a stale ack writes nothing")
	// Token 0 is never accepted on a leased stream once a coordinator is wired.
	err = h.eventService.AckEvent(t.Context(), jtis[0], sid, services.NoFencingToken)
	require.ErrorIs(t, err, services.ErrStaleFencingToken)
	assert.Equal(t, before, h.pendingCount(sid), "a zero-token ack writes nothing")

	// The current holder's token is accepted.
	require.NoError(t, h.eventService.AckEvent(t.Context(), jtis[0], sid, newToken))

	// The old runner's own in-flight batch ack is refused too, and the runner
	// stopping must not release node-b's lease.
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
	coord := h.router.coordinator

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
	assert.Equal(t, services.NoFencingToken, token)
}

// CurrentFence reports the push lease for a push stream and nothing for a
// stream the router holds no lease for.
func TestPushFence_CurrentFence(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)

	_, _, leased, err := h.router.CurrentFence("no-such-stream")
	require.NoError(t, err)
	assert.False(t, leased)

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 1)
	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)
	want := waitLeaseOwner(t, h.router.coordinator, cluster.PushTransmitterResource(sid), "node-restart")

	resource, token, leased, err := h.router.CurrentFence(sid)
	require.NoError(t, err)
	assert.True(t, leased)
	assert.Equal(t, cluster.PushTransmitterResource(sid), resource)
	assert.Equal(t, want, token)
}
