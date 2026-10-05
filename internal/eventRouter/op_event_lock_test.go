package eventRouter

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/stretchr/testify/require"
)

// gatedOwnerReads blocks push-transmitter GetLeaseOwner calls while armed,
// standing in for a slow cluster_leases round trip.
type gatedOwnerReads struct {
	cluster.ClusterCoordinator
	armed   atomic.Bool
	entered atomic.Int64
	gate    chan struct{}
}

func (g *gatedOwnerReads) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
	if g.armed.Load() && strings.HasPrefix(resource, "push-transmitter:") {
		g.entered.Add(1)
		<-g.gate
	}
	return g.ClusterCoordinator.GetLeaseOwner(resource)
}

// SubmitOperationalEvent must not hold r.mu across a lease-owner read: a slow
// coordinator would stall every stream-table writer behind one request.
func TestSubmitOperationalEvent_PushOwnerReadHoldsNoRouterLock(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	p, err := dbProviders.OpenPersistence("memorydb:", "op_event_lock_test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Storage.Close() })
	gated := &gatedOwnerReads{ClusterCoordinator: p.Coordinator, gate: make(chan struct{})}
	r := NewRouter(RouterDeps{
		StreamService: p.StreamService,
		KeyService:    p.KeyService,
		EventService:  p.EventService,
		Coordinator:   gated,
		ServesClaims:  true,
	}, "node-test").(*router)
	t.Cleanup(r.Shutdown)
	var once sync.Once
	release := func() { once.Do(func() { close(gated.gate) }) }
	t.Cleanup(release)

	h := &testHarness{router: r, streamService: p.StreamService, keyService: p.KeyService}
	stream := mustCreateTestStream(t, h, projectIdFromHarness(t, h))
	sid := stream.StreamConfiguration.Id
	r.UpdateStreamState(stream)
	require.NotNil(t, h.pushBufferFor(sid))
	r.leaseOwners.forget(cluster.PushTransmitterResource(sid))

	gated.armed.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.SubmitOperationalEvent(sid, newRiscToken("op-lock-1", "DEFAULT", "https://receiver.example.com"), `{"raw":true}`)
	}()
	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return gated.entered.Load() > 0
		}
	}, 5*time.Second, time.Millisecond, "the submission reached the owner read")

	locked := make(chan struct{})
	go func() {
		r.mu.Lock()
		r.mu.Unlock()
		close(locked)
	}()
	require.Eventually(t, func() bool {
		select {
		case <-locked:
			return true
		default:
			return false
		}
	}, 2*time.Second, time.Millisecond, "a router writer is not held behind the owner read")
	release()
	<-done
}
