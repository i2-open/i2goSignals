package services

import (
    "sync"
    "time"
)

// Match-result cache defaults. The cache is deliberately short-lived: it
// absorbs bursts of events about the same subject without pinning the whole
// filter table in memory, and a short TTL bounds staleness on nodes that did
// not originate a filter change (ADR-0003, PRD #89).
const (
    defaultMatchCacheTTL     = 5 * time.Second
    defaultMatchCacheMaxKeys = 50000
)

// matchCacheEntry is one cached subject-match decision and its expiry. For a
// matched entry the SSF §9.3 EnforceAt is carried alongside so the
// delivery-time predicate re-evaluates the grace boundary on every call
// without re-reading the DAO (PRD #97 issue #99).
type matchCacheEntry struct {
    matched   bool
    enforceAt time.Time
    expiry    time.Time
}

// matchCache is a bounded, short-TTL per-node cache of subject match results,
// keyed by (stream_id, subject canonical key). It lets a burst of events about
// one subject pay a single filter lookup. Entries are invalidated per stream
// when that stream's filter changes; a coarse drop-all on overflow keeps the
// cache bounded.
type matchCache struct {
    mu      sync.Mutex
    ttl     time.Duration
    maxKeys int
    size    int
    streams map[string]map[string]matchCacheEntry
}

// newMatchCache constructs a matchCache with the given TTL and key cap.
func newMatchCache(ttl time.Duration, maxKeys int) *matchCache {
    return &matchCache{
        ttl:     ttl,
        maxKeys: maxKeys,
        streams: map[string]map[string]matchCacheEntry{},
    }
}

// get returns the cached match decision for (streamID, key) and whether it was
// a live cache hit. An expired entry is evicted and reported as a miss.
func (c *matchCache) get(streamID, key string) (entry matchCacheEntry, hit bool) {
    c.mu.Lock()
    defer c.mu.Unlock()
    s, ok := c.streams[streamID]
    if !ok {
        return matchCacheEntry{}, false
    }
    e, ok := s[key]
    if !ok {
        return matchCacheEntry{}, false
    }
    if time.Now().After(e.expiry) {
        delete(s, key)
        c.size--
        return matchCacheEntry{}, false
    }
    return e, true
}

// put records a match decision for (streamID, key) along with the entry's
// §9.3 EnforceAt (zero when matched is false or the entry is fully active).
// When the key cap is reached the whole cache is dropped — coarse, but it
// keeps memory bounded without per-entry bookkeeping.
func (c *matchCache) put(streamID, key string, matched bool, enforceAt time.Time) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.size >= c.maxKeys {
        c.streams = map[string]map[string]matchCacheEntry{}
        c.size = 0
    }
    s, ok := c.streams[streamID]
    if !ok {
        s = map[string]matchCacheEntry{}
        c.streams[streamID] = s
    }
    if _, existed := s[key]; !existed {
        c.size++
    }
    s[key] = matchCacheEntry{matched: matched, enforceAt: enforceAt, expiry: time.Now().Add(c.ttl)}
}

// invalidateStream drops every cached decision for streamID. It is called
// whenever that stream's subject filter changes so a subsequent lookup is
// recomputed against the updated filter.
func (c *matchCache) invalidateStream(streamID string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if s, ok := c.streams[streamID]; ok {
        c.size -= len(s)
        delete(c.streams, streamID)
    }
}
