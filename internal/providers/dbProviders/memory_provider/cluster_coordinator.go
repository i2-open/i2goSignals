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
    }
}

// Compile-time check.
var _ cluster.ClusterCoordinator = (*MemoryCoordinator)(nil)

func (c *MemoryCoordinator) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    now := time.Now().UTC()
    leaseUntil := now.Add(leaseDuration)

    entry, ok := c.leases[resource]
    if !ok {
        entry = &leaseEntry{createdAt: now}
        c.leases[resource] = entry
    }

    expired := !entry.leaseUntil.After(now)
    isOwner := entry.ownerNodeId == nodeId

    if !expired && !isOwner {
        return false, 0, nil
    }

    entry.ownerNodeId = nodeId
    entry.leaseUntil = leaseUntil
    entry.updatedAt = now
    entry.fencingToken++
    return true, entry.fencingToken, nil
}

func (c *MemoryCoordinator) ReleaseLeaseIfOwned(resource string, nodeId string) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    entry, ok := c.leases[resource]
    if !ok || entry.ownerNodeId != nodeId {
        return nil
    }
    // Match Mongo semantics: shorten the lease to "now" instead of deleting.
    entry.leaseUntil = time.Now().UTC()
    entry.updatedAt = entry.leaseUntil
    return nil
}

func (c *MemoryCoordinator) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    entry, ok := c.leases[resource]
    if !ok {
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
