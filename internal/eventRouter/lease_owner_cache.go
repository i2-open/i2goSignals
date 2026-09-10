package eventRouter

import (
	"sync"
	"time"
)

// leaseOwnerCacheTTL bounds how long a cached push-transmitter lease owner may
// be stale before it is re-read from the coordinator (issue #287).
//
// It is the BACKSTOP, not the mechanism. The owner of a push lease is this
// node's own push lifecycle, so every transition it drives — acquire, renew,
// loss, exit — pushes the truth into the cache the instant it happens (see
// noteLeaseOwner / forgetLeaseOwner below). The TTL exists only for the
// transitions this node does not drive: a PEER acquiring a lease this node
// never held. Two seconds is well inside leaseTTL (30s), so a handover is
// observed long before the lease it describes could expire, while still
// collapsing the per-event lookup that profiler level 2 counted at 5000
// cluster_leases queries per 5000 ingested events.
const leaseOwnerCacheTTL = 2 * time.Second

// leaseOwnerCache memoises "who owns this resource" for the fan-out wake-up
// decision.
//
// WHY A CACHE IS SAFE HERE, precisely. GetLeaseOwner is read on the ingest path
// for ONE purpose: choosing where to send a wake-up — submit the JTIs into this
// node's own delivery buffer, or fire a wake-up at the node that owns the
// lease. It never authorises delivery. Delivery is gated separately, by the
// lease the delivering node's push loop holds and renews (PushStreamHandler /
// runPushLoop), so a stale answer here cannot produce a second transmitter or a
// duplicate push:
//
//   - Stale "we own it" when a peer has taken over: the JTIs land in a local
//     buffer whose push loop is not running, and the real owner still delivers
//     them, because the delivery intents were written to the pending list and
//     the owner drains that list, not this node's buffer.
//   - Stale "the peer owns it" when ownership has moved here: the wake-up goes
//     to a node that ignores it, and this node's own push loop picks the events
//     up on its next cycle.
//
// Both cost latency on a lease handover, never correctness, and both are
// bounded by leaseOwnerCacheTTL.
type leaseOwnerCache struct {
	mu      sync.Mutex
	entries map[string]leaseOwnerEntry
	ttl     time.Duration

	// now is the clock the TTL is measured against. A field rather than a
	// direct time.Now call so expiry can be driven deterministically from
	// tests without sleeping. Always non-nil after newLeaseOwnerCache.
	now func() time.Time
}

type leaseOwnerEntry struct {
	owner   string
	expires time.Time
}

func newLeaseOwnerCache() *leaseOwnerCache {
	return &leaseOwnerCache{
		entries: make(map[string]leaseOwnerEntry),
		ttl:     leaseOwnerCacheTTL,
		now:     time.Now,
	}
}

// owner returns the cached owner of resource, calling load on a miss or an
// expired entry. A load error is NOT cached: an unavailable coordinator must
// not pin an empty owner for the whole TTL, and returning "" is already the
// caller's "no owner — deliver locally and let backfill sort it out" branch.
func (c *leaseOwnerCache) owner(resource string, load func() (string, error)) string {
	if c == nil {
		owner, _ := load()
		return owner
	}
	now := c.now()

	c.mu.Lock()
	entry, ok := c.entries[resource]
	c.mu.Unlock()
	if ok && now.Before(entry.expires) {
		return entry.owner
	}

	owner, err := load()
	if err != nil {
		return owner
	}
	c.note(resource, owner)
	return owner
}

// note records an owner this node observed first-hand — its own successful
// acquire or renew. This is the invalidation hook that matters: it makes the
// cache correct at the instant of the transition rather than TTL later.
func (c *leaseOwnerCache) note(resource string, owner string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries[resource] = leaseOwnerEntry{owner: owner, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
}

// forget drops the entry for resource. Called when this node stops being able
// to speak for it — a lease it failed to acquire, lost, or gave up — so the
// next wake-up decision re-reads the coordinator rather than repeating a claim
// that is no longer this node's to make.
func (c *leaseOwnerCache) forget(resource string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, resource)
	c.mu.Unlock()
}
