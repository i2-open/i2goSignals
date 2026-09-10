package services

import (
	"sync"
	"time"
)

// revocationCacheTTL is how long TokenService.IsRevoked may reuse a revocation
// decision before re-reading the token store (issue #287).
//
// WHY A TTL IS ACCEPTABLE HERE. Every authenticated request checked revocation
// with its own FindByJTI: profiler level 2 counted 5009 `tokens` queries for
// 5000 ingested events, all of them re-asking the same question about the same
// long-lived stream token. Revocation is rare next to ingest, so the answer is
// worth remembering — but a stale "not revoked" is a SECURITY defect, not a
// slow path, so the window is deliberately small and has two exact edges:
//
//   - A revoke issued through this node (RevokeToken / RevokeTokenAt) drops the
//     entry as part of the revoke, so it takes effect immediately, not in two
//     seconds. That is the path an operator or the rotation machinery takes.
//   - A DEFERRED revocation (ADR 0022 §2, the rotate-on-GET grace window) is
//     exact rather than approximate: a "not yet revoked" answer for a token
//     whose revoked_at is in the future is cached only until that instant, so
//     the grace window ends when it says it does.
//
// The TTL is therefore the bound on exactly one case: a peer node revoking a
// token this node has recently validated. Two seconds is the documented
// worst-case propagation delay for that case.
const revocationCacheTTL = 2 * time.Second

// revocationCacheMaxEntries bounds the memo. The working set is tiny — a
// handful of live stream tokens re-presented thousands of times — but JTIs are
// unbounded over a process lifetime, so the map is swept and, if that is not
// enough, dropped wholesale. Dropping costs a re-read, never a wrong answer.
const revocationCacheMaxEntries = 4096

type revocationEntry struct {
	revoked bool
	expires time.Time
}

type revocationCache struct {
	mu      sync.Mutex
	entries map[string]revocationEntry
	ttl     time.Duration
	max     int

	// gen counts invalidations. A reader captures it before its store read and
	// hands it back to putIfCurrent, which refuses to install a decision that
	// an intervening forget has already superseded. Without it a revoke can be
	// straddled: a reader loads a not-yet-revoked record, the revoke runs both
	// its forgets against an empty map, and the reader then installs "not
	// revoked" for the full TTL — the exact stale-accept the TTL is bounded to
	// prevent. One counter for the whole cache rather than one per JTI: revokes
	// are rare, so over-invalidating in-flight reads costs a re-read, never a
	// wrong answer, and it keeps no per-JTI state alive after a forget.
	gen uint64

	// now is the clock the TTL is measured against. A field rather than a
	// direct time.Now call so expiry and the deferred-revocation boundary can
	// be driven deterministically from tests without sleeping.
	now func() time.Time
}

func newRevocationCache() *revocationCache {
	return &revocationCache{
		entries: make(map[string]revocationEntry),
		ttl:     revocationCacheTTL,
		max:     revocationCacheMaxEntries,
		now:     time.Now,
	}
}

// get returns a cached decision for jti, or ok=false when there is none or it
// has expired.
func (c *revocationCache) get(jti string) (bool, bool) {
	if c == nil {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[jti]
	if !ok || !c.now().Before(entry.expires) {
		return false, false
	}
	return entry.revoked, true
}

// generation reads the current invalidation counter. Callers capture it BEFORE
// the store read whose result they intend to cache.
func (c *revocationCache) generation() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// putIfCurrent records a decision unless the cache was invalidated after gen
// was captured, in which case the decision is dropped and the next caller
// re-reads the store. It is the only writer: a put that sampled gen itself
// would sample it AFTER the caller's store read, reopening exactly the
// straddle the counter exists to close.
//
// revokedAt is the token's stored revoked_at, and it shortens the entry when it
// names a FUTURE instant: the cached "not revoked" then lapses exactly when the
// grace window does (ADR 0022 §2) instead of running the full TTL past it. A
// zero or past revoked_at imposes no such cap — a past one is already the
// reason the decision is `true`, which cannot become stale in the other
// direction.
func (c *revocationCache) putIfCurrent(jti string, revoked bool, revokedAt time.Time, gen uint64) {
	if c == nil || jti == "" {
		return
	}
	now := c.now()
	expires := now.Add(c.ttl)
	if !revokedAt.IsZero() && revokedAt.After(now) && revokedAt.Before(expires) {
		expires = revokedAt
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return
	}
	if len(c.entries) >= c.max {
		c.sweepLocked(now)
		if len(c.entries) >= c.max {
			clear(c.entries)
		}
	}
	c.entries[jti] = revocationEntry{revoked: revoked, expires: expires}
}

// forget drops jti. This is the invalidation hook: a revoke performed through
// this node calls it, so the revocation is effective on the next request rather
// than after the TTL.
func (c *revocationCache) forget(jti string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, jti)
	// Bump AFTER the delete so any read still in flight is superseded too.
	c.gen++
}

func (c *revocationCache) sweepLocked(now time.Time) {
	for jti, entry := range c.entries {
		if !now.Before(entry.expires) {
			delete(c.entries, jti)
		}
	}
}
