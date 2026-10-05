package memory_provider

import (
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// activeWindow matches the Mongo-side convention: a node is "active" if it
// has heartbeated in the last 60 seconds.
const activeWindow = 60 * time.Second

// MemoryCoordinator implements cluster.ClusterCoordinator with real lease
// semantics — atomic acquire/renew/release, time-based expiry, and strict
// fencing-token monotonicity. It is the canonical reference implementation
// for the seam: the Mongo coordinator is expected to honour the same
// invariants under the same tests.
type MemoryCoordinator struct {
	mu     sync.Mutex
	leases map[string]*leaseEntry
	nodes  map[string]model.ClusterNode
	now    func() time.Time
}

type leaseEntry struct {
	ownerNodeId  string
	leaseUntil   time.Time
	fencingToken int64
	createdAt    time.Time
	updatedAt    time.Time
}

// NewMemoryCoordinator constructs a MemoryCoordinator with empty state.
func NewMemoryCoordinator() *MemoryCoordinator {
	return &MemoryCoordinator{
		leases: make(map[string]*leaseEntry),
		nodes:  make(map[string]model.ClusterNode),
		now:    time.Now,
	}
}

// SetClock replaces the clock the lease operations read, so a test can expire
// a lease without sleeping. A nil clock restores time.Now.
func (c *MemoryCoordinator) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	c.now = now
}

// Compile-time check.
var _ cluster.ClusterCoordinator = (*MemoryCoordinator)(nil)

func (c *MemoryCoordinator) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now().UTC()
	leaseUntil := now.Add(leaseDuration)

	entry, ok := c.leases[resource]
	if !ok {
		entry = &leaseEntry{createdAt: now}
		c.leases[resource] = entry
	}

	expired := !entry.leaseUntil.After(now)
	isOwner := entry.ownerNodeId == nodeId

	if !expired && !isOwner {
		return false, 0, time.Time{}, nil
	}

	// A renewal by the holder of a live lease keeps its fencing token, so the
	// holder's acks stay valid across heartbeats. Any acquisition of an expired
	// or unowned lease, by the same node or another, starts a new tenure with
	// the next token (#334).
	if expired || !isOwner {
		entry.fencingToken++
	}
	entry.ownerNodeId = nodeId
	entry.leaseUntil = leaseUntil
	entry.updatedAt = now
	return true, entry.fencingToken, leaseUntil, nil
}

func (c *MemoryCoordinator) ReleaseLeaseIfOwned(resource string, nodeId string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.leases[resource]
	if !ok || entry.ownerNodeId != nodeId {
		return nil
	}
	// Match Mongo semantics: shorten the lease to "now" instead of deleting.
	entry.leaseUntil = c.now().UTC()
	entry.updatedAt = entry.leaseUntil
	return nil
}

func (c *MemoryCoordinator) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.leases[resource]
	if !ok || !entry.leaseUntil.After(c.now().UTC()) {
		// An expired (or released) lease has no owner.
		return "", time.Time{}, 0, nil
	}
	return entry.ownerNodeId, entry.leaseUntil, entry.fencingToken, nil
}

func (c *MemoryCoordinator) RegisterNode(node model.ClusterNode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.nodes[node.Id]; ok && node.StartedAt.IsZero() {
		node.StartedAt = existing.StartedAt
	}
	c.nodes[node.Id] = node
	return nil
}

func (c *MemoryCoordinator) GetActiveNodeCount() (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	threshold := time.Now().UTC().Add(-activeWindow)
	count := int64(0)
	for _, n := range c.nodes {
		if n.LastSeenAt.After(threshold) {
			count++
		}
	}
	return count, nil
}

func (c *MemoryCoordinator) GetActiveNodes() ([]model.ClusterNode, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	threshold := time.Now().UTC().Add(-activeWindow)
	var out []model.ClusterNode
	for _, n := range c.nodes {
		if n.LastSeenAt.After(threshold) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (c *MemoryCoordinator) GetNode(nodeId string) (*model.ClusterNode, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[nodeId]
	if !ok {
		return nil, nil
	}
	return &n, nil
}

var _ cluster.Reaper = (*MemoryCoordinator)(nil)

func (c *MemoryCoordinator) PurgeStaleNodes(before time.Time) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for id, node := range c.nodes {
		if node.LastSeenAt.Before(before) {
			delete(c.nodes, id)
			n++
		}
	}
	return n, nil
}

func (c *MemoryCoordinator) PurgeExpiredLeases(before time.Time, keep func(resource string) bool) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for resource, entry := range c.leases {
		if !entry.leaseUntil.Before(before) || (keep != nil && keep(resource)) {
			continue
		}
		delete(c.leases, resource)
		n++
	}
	return n, nil
}
