package eventRouter

import (
	"errors"
	"testing"
	"time"
)

// loadCounter is a stand-in for the coordinator read the fan-out used to make
// once per ingested SET.
type loadCounter struct {
	owner string
	err   error
	calls int
}

func (l *loadCounter) load() (string, error) {
	l.calls++
	return l.owner, l.err
}

func newTestLeaseOwnerCache() (*leaseOwnerCache, *time.Time) {
	c := newLeaseOwnerCache()
	base := time.Now()
	c.now = func() time.Time { return base }
	return c, &base
}

// TestLeaseOwnerCacheCollapsesPerEventReads is the #287 claim for the
// cluster_leases column: one wake-up decision per SET became one coordinator
// round trip per SET.
func TestLeaseOwnerCacheCollapsesPerEventReads(t *testing.T) {
	c, _ := newTestLeaseOwnerCache()
	loader := &loadCounter{owner: "node-a"}

	for i := 0; i < 100; i++ {
		if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
			t.Fatalf("owner = %q, want node-a", got)
		}
	}
	if loader.calls != 1 {
		t.Errorf("coordinator reads = %d, want 1", loader.calls)
	}
}

// TestLeaseOwnerCacheExpires is the backstop for the transition this node does
// not drive: a peer acquiring a lease this node never held.
func TestLeaseOwnerCacheExpires(t *testing.T) {
	c, now := newTestLeaseOwnerCache()
	loader := &loadCounter{owner: "node-a"}
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
		t.Fatalf("owner = %q, want node-a", got)
	}

	loader.owner = "node-b"
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
		t.Errorf("inside the TTL the cached owner should still stand, got %q", got)
	}

	*now = now.Add(leaseOwnerCacheTTL)
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-b" {
		t.Errorf("after the TTL the handover must be visible, got %q", got)
	}
	if loader.calls != 2 {
		t.Errorf("coordinator reads = %d, want 2", loader.calls)
	}

	// The TTL must be comfortably inside the lease it describes, or a cached
	// owner could outlive the lease that made it true.
	if leaseOwnerCacheTTL >= leaseTTL {
		t.Errorf("leaseOwnerCacheTTL %v must be well below leaseTTL %v", leaseOwnerCacheTTL, leaseTTL)
	}
}

// TestLeaseOwnerCacheHooks covers the invalidation that makes the TTL a
// backstop rather than the mechanism: this node's own acquire/renew and its own
// loss are both observed first-hand.
func TestLeaseOwnerCacheHooks(t *testing.T) {
	c, now := newTestLeaseOwnerCache()
	loader := &loadCounter{owner: "node-b"}

	// An acquire by this node is authoritative immediately — no coordinator
	// read, and the stale "node-b" never surfaces.
	c.note("push-transmitter:s1", "node-a")
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
		t.Errorf("owner after note = %q, want node-a", got)
	}
	if loader.calls != 0 {
		t.Errorf("note must not require a coordinator read, got %d", loader.calls)
	}

	// A renew refreshes the entry rather than letting it lapse.
	*now = now.Add(leaseOwnerCacheTTL - time.Millisecond)
	c.note("push-transmitter:s1", "node-a")
	*now = now.Add(leaseOwnerCacheTTL - time.Millisecond)
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
		t.Errorf("owner after renew = %q, want node-a", got)
	}
	if loader.calls != 0 {
		t.Errorf("a renewed entry must not be re-read, got %d calls", loader.calls)
	}

	// Losing the lease drops the claim: the next decision re-reads.
	c.forget("push-transmitter:s1")
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-b" {
		t.Errorf("owner after forget = %q, want node-b", got)
	}
	if loader.calls != 1 {
		t.Errorf("coordinator reads after forget = %d, want 1", loader.calls)
	}
}

// TestLeaseOwnerCacheDoesNotCacheErrors keeps an unreachable coordinator from
// pinning an empty owner for the whole TTL.
func TestLeaseOwnerCacheDoesNotCacheErrors(t *testing.T) {
	c, _ := newTestLeaseOwnerCache()
	loader := &loadCounter{owner: "", err: errors.New("coordinator unavailable")}

	for i := 0; i < 3; i++ {
		if got := c.owner("push-transmitter:s1", loader.load); got != "" {
			t.Fatalf("owner = %q, want empty on error", got)
		}
	}
	if loader.calls != 3 {
		t.Errorf("coordinator reads = %d, want 3 (errors must not be cached)", loader.calls)
	}

	// Once it answers, the answer sticks.
	loader.err = nil
	loader.owner = "node-a"
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
		t.Fatalf("owner = %q, want node-a", got)
	}
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
		t.Fatalf("owner = %q, want node-a", got)
	}
	if loader.calls != 4 {
		t.Errorf("coordinator reads = %d, want 4", loader.calls)
	}
}

// TestLeaseOwnerCacheNilIsPassThrough keeps a router constructed without the
// cache (a test double, a future embedder) reading straight through.
func TestLeaseOwnerCacheNilIsPassThrough(t *testing.T) {
	var c *leaseOwnerCache
	loader := &loadCounter{owner: "node-a"}
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
		t.Fatalf("owner = %q, want node-a", got)
	}
	if got := c.owner("push-transmitter:s1", loader.load); got != "node-a" {
		t.Fatalf("owner = %q, want node-a", got)
	}
	if loader.calls != 2 {
		t.Errorf("a nil cache must not memoise, got %d calls", loader.calls)
	}
	c.note("push-transmitter:s1", "node-a")
	c.forget("push-transmitter:s1")
}
