package eventRouter

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
)

// leaseSafetyMarginEnv names the environment key that sets how long before a
// lease's recorded expiry this node stops treating itself as the owner. The
// value is a Go duration; an unset or unparsable value means
// defaultLeaseSafetyMargin.
const leaseSafetyMarginEnv = "I2SIG_LEASE_SAFETY_MARGIN"

// defaultLeaseSafetyMargin is the margin used when leaseSafetyMarginEnv is not
// set. It covers clock drift between this node and the lease store plus the
// time an acknowledgement batch takes to reach the store.
const defaultLeaseSafetyMargin = 5 * time.Second

// leaseSafetyMargin reads leaseSafetyMarginEnv. A negative value is treated as
// zero and reported at WARN.
func leaseSafetyMargin() time.Duration {
	v := os.Getenv(leaseSafetyMarginEnv)
	if v == "" {
		return defaultLeaseSafetyMargin
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		eventLogger.Warn("Invalid lease safety margin, using default", "key", leaseSafetyMarginEnv, "value", v, "default", defaultLeaseSafetyMargin)
		return defaultLeaseSafetyMargin
	}
	if d < 0 {
		eventLogger.Warn("Negative lease safety margin, using 0", "key", leaseSafetyMarginEnv, "value", v)
		return 0
	}
	return d
}

// leaseManager answers "does this node still own resource X" from memory
// (#364). It replaces the per-acknowledgement fence check, which read the lease
// row before every acknowledgement batch: a slow replica set then stalled the
// delivery of SETs that had already been sent.
//
// Every acquire-or-renew call this node makes goes through acquire (or, for
// leases held outside the router, through note), and each successful one
// records a deadline:
//
//	min(leaseUntil returned by the coordinator, renewCallStart + leaseDuration) - margin
//
// Taking the earlier of the two bounds means neither a store clock ahead of
// this node nor a slow round trip can stretch this node's tenure. The margin
// makes the node stop acknowledging before any peer can take the lease over,
// so a takeover can duplicate a send but never lose one: an acknowledgement
// batch skipped here leaves its SETs pending in the store, and the next owner
// redelivers them.
//
// One manager exists per router. The router's lease heartbeats are its
// renewal loop.
type leaseManager struct {
	// coord is the lease store. Nil means the node runs without cluster
	// coordination, and StillOwner always answers true.
	coord  cluster.ClusterCoordinator
	margin time.Duration
	// now is the clock deadlines are recorded and compared with; tests inject
	// one.
	now func() time.Time

	mu        sync.Mutex
	deadlines map[string]time.Time
	// capWarned records that a capped margin has been reported.
	capWarned atomic.Bool
}

// newLeaseManager returns a manager for coord, using the margin from the
// environment and the wall clock.
func newLeaseManager(coord cluster.ClusterCoordinator) *leaseManager {
	return &leaseManager{
		coord:     coord,
		margin:    leaseSafetyMargin(),
		now:       time.Now,
		deadlines: make(map[string]time.Time),
	}
}

// clock returns the manager's clock, defaulting to the wall clock.
func (m *leaseManager) clock() time.Time {
	if m.now == nil {
		return time.Now()
	}
	return m.now()
}

// acquire calls the coordinator's acquire-or-renew for resource and records
// the outcome. Its results are the coordinator's. A failed call or a lease
// held elsewhere forgets the resource, so StillOwner turns false at once.
func (m *leaseManager) acquire(resource, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
	start := m.clock()
	held, token, leaseUntil, err := m.coord.TryAcquireOrRenewLease(resource, nodeId, leaseDuration)
	m.note(resource, start, held && err == nil, leaseUntil, leaseDuration)
	return held, token, err
}

// note records the outcome of an acquire-or-renew call made outside the
// manager, for leases whose holder lives elsewhere (the SSTP dialer). start is
// when the call began. held false forgets the resource.
func (m *leaseManager) note(resource string, start time.Time, held bool, leaseUntil time.Time, leaseDuration time.Duration) {
	if m == nil {
		return
	}
	if !held {
		m.forget(resource)
		return
	}
	deadline := start.Add(leaseDuration)
	if !leaseUntil.IsZero() && leaseUntil.Before(deadline) {
		deadline = leaseUntil
	}
	// A margin as wide as the lease itself would leave no tenure at all. The
	// production leases (30s) are far wider than the default margin; this
	// only keeps a short test lease usable.
	margin := m.margin
	if half := leaseDuration / 2; margin > half {
		margin = half
		if m.capWarned.CompareAndSwap(false, true) {
			eventLogger.Warn("Lease safety margin capped at half the lease duration", "key", leaseSafetyMarginEnv, "configured", m.margin, "effective", margin, "leaseDuration", leaseDuration)
		}
	}
	deadline = deadline.Add(-margin)

	m.mu.Lock()
	m.deadlines[resource] = deadline
	m.mu.Unlock()
}

// forget drops the recorded tenure for resource: the lease was lost, given
// up, or never held.
func (m *leaseManager) forget(resource string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.deadlines, resource)
	m.mu.Unlock()
}

// StillOwner reports whether this node may act as the owner of resource. It
// makes no store or coordinator call. With no coordinator it is always true; a
// resource this node never acquired, or whose deadline has passed, is false.
func (m *leaseManager) StillOwner(resource string) bool {
	if m == nil || m.coord == nil {
		return true
	}
	m.mu.Lock()
	deadline, ok := m.deadlines[resource]
	m.mu.Unlock()
	if !ok {
		return false
	}
	return m.clock().Before(deadline)
}

// resolveOwner returns the node that holds resource and whether it is this
// node. When nobody holds it, this node acquires it, unless ServesClaims is
// false for the two claim-served kinds, in which case ownerNode is empty.
// Never called with r.mu held (#365).
//
// Steps, in order: (1) StillOwner: this node. (2) the owner leaseOwners names
// (a live lease read from the coordinator, cached 2 seconds); another node:
// that node. (3) no live lease: one acquire. Acquired, the resource joins the
// renewal loop and this node builds the stream's queue with one pending read;
// refused, the cache entry is forgotten and step 2 runs once more. With no
// coordinator every resource is this node's and no lease is taken.
func (r *router) resolveOwner(resource string) (ownerNode string, self bool) {
	ownerNode, self, _ = r.resolveOwnerSeeded(resource)
	return ownerNode, self
}

// resolveOwnerSeeded is resolveOwner that also reports whether the call
// built this node's queue from a pending read (see ensureOwnerQueueSeeded).
func (r *router) resolveOwnerSeeded(resource string) (ownerNode string, self, seeded bool) {
	if r.leaseRenewer() == nil {
		known, seeded := r.ensureOwnerQueueSeeded(resource)
		if !known {
			return "", false, false
		}
		return r.nodeId, true, seeded
	}
	if r.leases.StillOwner(resource) {
		if known, seeded := r.ensureOwnerQueueSeeded(resource); known {
			return r.nodeId, true, seeded
		}
		return "", false, false
	}
	load := func() (string, error) {
		owner, _, _, err := r.coordinator.GetLeaseOwner(resource)
		return owner, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		owner := r.leaseOwners.owner(resource, load)
		if owner != "" && owner != r.nodeId {
			return owner, false, false
		}
		if !r.servesClaims && isClaimServedResource(resource) {
			return "", false, false
		}
		if attempt > 0 {
			break
		}
		held, _, err := r.tryLease(resource, leaseTTL)
		if err == nil && held {
			r.leaseOwners.note(resource, r.nodeId)
			r.adoptStreamLease(resource)
			if known, seeded := r.ensureOwnerQueueSeeded(resource); known {
				return r.nodeId, true, seeded
			}
			// The stream went away under the acquire: give the lease back.
			r.releaseStreamLease(resource)
			return "", false, false
		}
		if err != nil {
			eventLogger.Warn("ROUTER: stream lease acquire failed", "resource", resource, "error", err)
		}
		r.leaseOwners.forget(resource)
	}
	return "", false, false
}
