package services

import (
    "testing"
    "time"
)

// TestMatchCache_HitAfterPut verifies a stored decision is returned as a hit.
func TestMatchCache_HitAfterPut(t *testing.T) {
    c := newMatchCache(time.Minute, 100)
    c.put("stream-1", "email:alice@example.com", true)

    matched, hit := c.get("stream-1", "email:alice@example.com")
    if !hit {
        t.Fatal("a stored decision must be a cache hit")
    }
    if !matched {
        t.Fatal("the cached match decision must be returned intact")
    }
}

// TestMatchCache_InvalidateStreamDropsEntries verifies invalidateStream removes
// a stream's cached decisions while leaving other streams untouched.
func TestMatchCache_InvalidateStreamDropsEntries(t *testing.T) {
    c := newMatchCache(time.Minute, 100)
    c.put("stream-1", "email:alice@example.com", true)
    c.put("stream-2", "email:bob@example.com", true)

    c.invalidateStream("stream-1")

    if _, hit := c.get("stream-1", "email:alice@example.com"); hit {
        t.Fatal("invalidateStream must drop the stream's cached decisions")
    }
    if _, hit := c.get("stream-2", "email:bob@example.com"); !hit {
        t.Fatal("invalidateStream must not affect other streams")
    }
}

// TestMatchCache_EntryExpiresAfterTTL verifies a cached decision becomes a miss
// once its TTL elapses — the short TTL that bounds cross-node staleness.
func TestMatchCache_EntryExpiresAfterTTL(t *testing.T) {
    c := newMatchCache(10*time.Millisecond, 100)
    c.put("stream-1", "email:alice@example.com", true)

    time.Sleep(25 * time.Millisecond)

    if _, hit := c.get("stream-1", "email:alice@example.com"); hit {
        t.Fatal("a cached decision must expire after its TTL")
    }
}
