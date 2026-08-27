package eventRouter

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// This file is the deterministic-time suite for the cluster lease heartbeat —
// one of the four timer paths spec 101 names. Running inside a synctest bubble
// makes the cadence an equality assertion ("the third renewal happened at
// exactly 30s") rather than a sleep-and-hope, and makes a 6-minute scenario
// cost microseconds. The bubble also proves the heartbeat goroutine is
// reclaimed on every exit path: synctest.Test does not return until every
// goroutine in the bubble has finished, so a heartbeat that failed to notice a
// cancelled context would be reported as a deadlock rather than silently
// surviving the test.

// fakeLeaseStore is the fake collection behind the coordinator seam. It records
// every renewal and answers from a script, so a test can say "the fourth renewal
// finds the lease gone" without waiting for a real lease to expire.
type fakeLeaseStore struct {
	// answers[i] is the reply to the i'th call; the last entry repeats.
	answers []leaseAnswer
	calls   []leaseCall
}

type leaseAnswer struct {
	held bool
	err  error
}

type leaseCall struct {
	at       time.Time
	resource string
	nodeId   string
	ttl      time.Duration
}

func (f *fakeLeaseStore) TryAcquireOrRenewLease(resource, nodeId string, ttl time.Duration) (bool, int64, error) {
	f.calls = append(f.calls, leaseCall{at: time.Now(), resource: resource, nodeId: nodeId, ttl: ttl})
	idx := len(f.calls) - 1
	if idx >= len(f.answers) {
		idx = len(f.answers) - 1
	}
	a := f.answers[idx]
	return a.held, int64(len(f.calls)), a.err
}

func (f *fakeLeaseStore) ReleaseLeaseIfOwned(string, string) error { return nil }
func (f *fakeLeaseStore) GetLeaseOwner(string) (string, time.Time, int64, error) {
	return "", time.Time{}, 0, nil
}
func (f *fakeLeaseStore) RegisterNode(model.ClusterNode) error         { return nil }
func (f *fakeLeaseStore) GetActiveNodeCount() (int64, error)           { return 0, nil }
func (f *fakeLeaseStore) GetActiveNodes() ([]model.ClusterNode, error) { return nil, nil }
func (f *fakeLeaseStore) GetNode(string) (*model.ClusterNode, error)   { return nil, nil }

// TestLeaseHeartbeat_RenewsOnTheInterval pins the cadence and the renewal
// arguments. The first renewal is one interval in, not immediate: acquisition
// already happened before the heartbeat started, so an immediate renewal would
// be a wasted round-trip on every stream start.
func TestLeaseHeartbeat_RenewsOnTheInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &fakeLeaseStore{answers: []leaseAnswer{{held: true}}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		start := time.Now()
		go leaseHeartbeat{
			Coordinator:   store,
			Resource:      "push:stream-1",
			NodeId:        "node-a",
			Interval:      leaseRenewInterval,
			LeaseDuration: leaseTTL,
		}.run(ctx)

		time.Sleep(35 * time.Second)
		synctest.Wait()

		if len(store.calls) != 3 {
			t.Fatalf("got %d renewals in 35s, want 3 at a %v cadence", len(store.calls), leaseRenewInterval)
		}
		for i, c := range store.calls {
			wantAt := start.Add(time.Duration(i+1) * leaseRenewInterval)
			if !c.at.Equal(wantAt) {
				t.Errorf("renewal %d at %v, want %v", i+1, c.at.Sub(start), wantAt.Sub(start))
			}
			if c.resource != "push:stream-1" || c.nodeId != "node-a" {
				t.Errorf("renewal %d renewed %q for %q, want push:stream-1 / node-a", i+1, c.resource, c.nodeId)
			}
			if c.ttl != leaseTTL {
				t.Errorf("renewal %d asked for a %v lease, want %v", i+1, c.ttl, leaseTTL)
			}
		}

		cancel()
	})
}

// TestLeaseHeartbeat_StopsTheInstantTheLeaseIsGone is the loss-of-lease path:
// the first renewal that does not confirm ownership must fire OnLost and end the
// heartbeat, with no further renewals. Continuing to renew after a loss is how a
// node ends up pushing from a stream another node has taken over.
func TestLeaseHeartbeat_StopsTheInstantTheLeaseIsGone(t *testing.T) {
	cases := []struct {
		name   string
		answer leaseAnswer
	}{
		{name: "another node took the lease", answer: leaseAnswer{held: false}},
		{name: "the lease store errored", answer: leaseAnswer{held: false, err: errors.New("mongo unreachable")}},
		{name: "ownership unproven despite no error", answer: leaseAnswer{held: false, err: nil}},
		{name: "held but errored is still unproven", answer: leaseAnswer{held: true, err: errors.New("write concern not met")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := &fakeLeaseStore{answers: []leaseAnswer{{held: true}, {held: true}, tc.answer}}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				var lost int
				var lostAt time.Time
				var outcomes []bool

				start := time.Now()
				go leaseHeartbeat{
					Coordinator:   store,
					Resource:      "push:stream-1",
					NodeId:        "node-a",
					Interval:      leaseRenewInterval,
					LeaseDuration: leaseTTL,
					OnRenew:       func(renewed bool) { outcomes = append(outcomes, renewed) },
					OnLost: func() {
						lost++
						lostAt = time.Now()
						cancel()
					},
				}.run(ctx)

				// Well past the loss, to prove the heartbeat really stopped
				// rather than merely reporting and carrying on.
				time.Sleep(2 * time.Minute)
				synctest.Wait()

				if lost != 1 {
					t.Fatalf("OnLost fired %d times, want exactly 1", lost)
				}
				if want := start.Add(3 * leaseRenewInterval); !lostAt.Equal(want) {
					t.Errorf("loss reported at %v, want the third renewal at %v",
						lostAt.Sub(start), want.Sub(start))
				}
				if len(store.calls) != 3 {
					t.Errorf("made %d renewals, want 3 — the heartbeat kept going after losing the lease", len(store.calls))
				}
				if got := []bool{true, true, false}; len(outcomes) != 3 ||
					outcomes[0] != got[0] || outcomes[1] != got[1] || outcomes[2] != got[2] {
					t.Errorf("OnRenew saw %v, want %v", outcomes, got)
				}
			})
		})
	}
}

// TestLeaseHeartbeat_StopsOnContextCancellation covers clean shutdown: the
// heartbeat exits without calling OnLost, because a cancelled context is the
// caller stopping, not the cluster taking the lease away. Firing OnLost here
// would log a spurious "lease lost" on every graceful stream teardown.
func TestLeaseHeartbeat_StopsOnContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &fakeLeaseStore{answers: []leaseAnswer{{held: true}}}
		ctx, cancel := context.WithCancel(t.Context())

		lost := 0
		done := make(chan struct{})
		go func() {
			defer close(done)
			leaseHeartbeat{
				Coordinator:   store,
				Resource:      "push:stream-1",
				NodeId:        "node-a",
				Interval:      leaseRenewInterval,
				LeaseDuration: leaseTTL,
				OnLost:        func() { lost++ },
			}.run(ctx)
		}()

		time.Sleep(25 * time.Second) // two renewals
		cancel()
		<-done

		if lost != 0 {
			t.Fatalf("OnLost fired %d times on a clean shutdown, want 0", lost)
		}
		if len(store.calls) != 2 {
			t.Fatalf("made %d renewals before cancellation, want 2", len(store.calls))
		}

		// Nothing further may happen after cancellation.
		before := len(store.calls)
		time.Sleep(time.Minute)
		synctest.Wait()
		if len(store.calls) != before {
			t.Fatalf("renewals continued after cancellation: %d -> %d", before, len(store.calls))
		}
	})
}

// TestLeaseHeartbeat_LosesTheLeaseToARealCoordinator runs the loss against
// MemoryCoordinator — the reference implementation of the seam, with real
// expiry and fencing semantics — instead of a scripted fake. It is the check
// that the heartbeat's notion of "lost" matches a coordinator's, rather than
// only matching the fake above.
//
// The fake clock is what makes this practical: the scenario spans two lease
// lifetimes, which against a real clock would be a minute of waiting.
func TestLeaseHeartbeat_LosesTheLeaseToARealCoordinator(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		coord := memory_provider.NewMemoryCoordinator()
		const resource = "push:stream-1"

		held, _, err := coord.TryAcquireOrRenewLease(resource, "node-a", leaseTTL)
		if err != nil || !held {
			t.Fatalf("node-a could not take a free lease: held=%v err=%v", held, err)
		}

		// Phase 1: node-a heartbeats normally. Its renewals keep the lease alive,
		// so node-b is locked out.
		healthy, stopHealthy := context.WithCancel(t.Context())
		go leaseHeartbeat{
			Coordinator:   coord,
			Resource:      resource,
			NodeId:        "node-a",
			Interval:      leaseRenewInterval,
			LeaseDuration: leaseTTL,
			OnLost:        func() { t.Error("node-a lost a lease it was renewing on time") },
		}.run(healthy)

		time.Sleep(25 * time.Second)
		synctest.Wait()
		if stolen, _, _ := coord.TryAcquireOrRenewLease(resource, "node-b", leaseTTL); stolen {
			t.Fatal("node-b took a lease node-a still holds and keeps renewing")
		}

		// Phase 2: node-a stalls — the process is paused, the network is gone,
		// whatever it is, the renewals stop. Stopping the heartbeat is exactly
		// that from the coordinator's point of view.
		stopHealthy()
		synctest.Wait()

		// Once the TTL lapses, node-b legitimately takes over.
		time.Sleep(leaseTTL + time.Second)
		stolen, bToken, err := coord.TryAcquireOrRenewLease(resource, "node-b", leaseTTL)
		if err != nil || !stolen {
			t.Fatalf("node-b could not take the expired lease: stolen=%v err=%v", stolen, err)
		}

		// Phase 3: node-a comes back and resumes heartbeating, unaware. Its very
		// first renewal must come back unowned and end the heartbeat — this is
		// the split-brain guard.
		revived, stopRevived := context.WithCancel(t.Context())
		defer stopRevived()

		lostAt := make(chan time.Time, 1)
		resumed := time.Now()
		go leaseHeartbeat{
			Coordinator:   coord,
			Resource:      resource,
			NodeId:        "node-a",
			Interval:      leaseRenewInterval,
			LeaseDuration: leaseTTL,
			OnLost: func() {
				lostAt <- time.Now()
				stopRevived()
			},
		}.run(revived)

		time.Sleep(time.Minute)
		synctest.Wait()

		select {
		case at := <-lostAt:
			if want := resumed.Add(leaseRenewInterval); !at.Equal(want) {
				t.Errorf("loss reported at %v, want the first renewal at %v",
					at.Sub(resumed), want.Sub(resumed))
			}
		default:
			t.Fatal("node-a kept heartbeating a lease node-b owns — split brain")
		}

		// node-b still owns it, with a strictly higher fencing token than the
		// one node-a last saw.
		owner, _, token, err := coord.GetLeaseOwner(resource)
		if err != nil {
			t.Fatalf("GetLeaseOwner: %v", err)
		}
		if owner != "node-b" {
			t.Errorf("lease owner is %q, want node-b", owner)
		}
		if token < bToken {
			t.Errorf("fencing token went backwards: %d < %d", token, bToken)
		}
	})
}
