package eventRouter

import (
	"context"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
)

// leaseRenewInterval is how often a lease holder re-asserts its claim, and
// leaseTTL is how long each assertion is good for. The TTL is deliberately
// three intervals wide: a holder that misses two consecutive renewals (a GC
// pause, a Mongo hiccup) keeps the lease, while a holder that has genuinely
// stopped loses it within a bounded window rather than pinning the resource
// until an operator intervenes.
const (
	leaseRenewInterval = 10 * time.Second
	leaseTTL           = 30 * time.Second
)

// leaseHeartbeat re-asserts one node's claim on one resource on a fixed cadence
// and reports the moment the claim is gone.
//
// It is separated from runPushLoop, whose lease it maintains, for one reason:
// as an anonymous goroutine inside a 200-line function it could only be
// exercised by standing up a router, a provider, a stream and a receiver, which
// meant its actual subject — *when* it renews and what it does the first time a
// renewal comes back false — was never tested at all. As a value with two
// callbacks it is a synctest bubble away from a deterministic test; see
// lease_heartbeat_test.go.
//
// Failure and non-ownership are the same outcome by design. A renewal that
// errors has not proved this node still owns the lease, and a lease holder that
// cannot prove ownership must stop acting like one immediately — continuing to
// push while another node may have taken over is precisely the split-brain the
// lease exists to prevent.
type leaseHeartbeat struct {
	// Coordinator is the lease store. The interface, not the Mongo type: the
	// heartbeat's contract is the seam's contract.
	Coordinator cluster.ClusterCoordinator

	// Resource and NodeId identify the claim being renewed.
	Resource string
	NodeId   string

	// Interval is the renewal cadence; LeaseDuration is the TTL each renewal
	// asks for. Zero values fall back to leaseRenewInterval / leaseTTL.
	Interval      time.Duration
	LeaseDuration time.Duration

	// OnRenew observes every renewal attempt's outcome (metrics). May be nil.
	OnRenew func(renewed bool)

	// OnLost fires exactly once, on the first renewal that does not confirm
	// ownership, immediately before run returns. May be nil.
	OnLost func()
}

// run maintains the lease until it is lost or ctx is done, then returns. It is
// meant to be called with `go`; it holds no locks and touches no router state,
// so a caller may equally run it inline in a test.
//
// The ticker is owned and stopped rather than re-derived from time.Tick, which
// leaks its underlying ticker for the life of the process.
func (h leaseHeartbeat) run(ctx context.Context) {
	interval := h.Interval
	if interval <= 0 {
		interval = leaseRenewInterval
	}
	ttl := h.LeaseDuration
	if ttl <= 0 {
		ttl = leaseTTL
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			held, _, err := h.Coordinator.TryAcquireOrRenewLease(h.Resource, h.NodeId, ttl)
			renewed := held && err == nil
			if h.OnRenew != nil {
				h.OnRenew(renewed)
			}
			if !renewed {
				if h.OnLost != nil {
					h.OnLost()
				}
				return
			}
		case <-ctx.Done():
			// Shutdown, or the caller already gave the lease up elsewhere.
			// Deliberately silent: this is not a loss, and firing OnLost here
			// would cancel a context that is already cancelled and log a
			// spurious "lease lost" on every clean stream teardown.
			return
		}
	}
}
