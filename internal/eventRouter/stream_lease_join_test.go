package eventRouter

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orderedLeaseStore logs renewals and releases in order; a renewal blocks on
// gate while armed.
type orderedLeaseStore struct {
	fakeLeaseStore
	mu    sync.Mutex
	armed bool
	gate  chan struct{}
	ops   []string
}

func (s *orderedLeaseStore) TryAcquireOrRenewLease(resource, nodeId string, ttl time.Duration) (bool, int64, time.Time, error) {
	s.mu.Lock()
	armed := s.armed
	s.mu.Unlock()
	if armed {
		<-s.gate
	}
	s.mu.Lock()
	s.ops = append(s.ops, "renew")
	s.mu.Unlock()
	return true, 1, time.Now().Add(ttl), nil
}

func (s *orderedLeaseStore) ReleaseLeaseIfOwned(string, string) error {
	s.mu.Lock()
	s.ops = append(s.ops, "release")
	s.mu.Unlock()
	return nil
}

func (s *orderedLeaseStore) opsCopy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ops...)
}

// Giving a stream lease back waits for a renewal in flight: one landing after
// the release would re-take the lease and hold it until it expires.
func TestReleaseStreamLease_WaitsForInFlightRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &orderedLeaseStore{gate: make(chan struct{})}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		r := newBareRouter(RouterDeps{Coordinator: store})
		r.ctx = ctx
		r.nodeId = "node-a"
		resource := cluster.PollTransmitter.Resource("sid-join")

		store.mu.Lock()
		store.armed = true
		store.mu.Unlock()
		r.adoptStreamLease(resource)
		time.Sleep(leaseRenewInterval)
		synctest.Wait() // the renewal is blocked on the gate

		released := make(chan struct{})
		go func() { r.releaseStreamLease(resource); close(released) }()
		synctest.Wait()
		assert.NotContains(t, store.opsCopy(), "release", "released while a renewal was in flight")

		close(store.gate)
		<-released
		ops := store.opsCopy()
		require.NotEmpty(t, ops)
		assert.Equal(t, "release", ops[len(ops)-1], "nothing renews after the release: %v", ops)
	})
}
