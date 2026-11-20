package services

import (
	"context"
	"sync"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// This file holds the request-scoped stream memo (issue #287).
//
// WHY IT EXISTS. Ingesting one SET drove the stream store twice or more. On the
// RFC8935 push path receivePushForStream resolves the stream to check iss/aud
// and the signing posture, then hands the SET to the router, whose
// resolveIngressStream resolves the very same SID again — two identical
// FindByID round trips inside one request. On the SSTP-server path it is worse:
// the inbound SID is the pair's rx-side SID and NOT the document _id, so
// resolveIngressStream misses on FindByID and falls through to
// GetStreamStateBySID, which probes FindByID a second time before reaching
// FindByInboundSID. Profiler level 2 counted 10012 `streams` queries for 5000
// ingested events.
//
// THE INVALIDATION STORY. A stale stream configuration is a correctness defect,
// not a slow path, so this memo is deliberately the weakest cache that solves
// the problem:
//
//   - It has NO TTL and needs none. It is created when a request starts and is
//     unreachable the moment that request's handler returns, so it can never
//     outlive the request that built it. A stream configuration change is
//     therefore visible to the very next request — never deferred by a timer.
//   - Within a request, every StreamService entry point that WRITES a stream
//     clears the whole memo (invalidateRequestStreams), so a handler that
//     mutates a stream and then re-reads it observes its own write.
//   - It is opt-in. Only a caller that wrapped its context in
//     WithRequestStreamCache gets one; on every other context the helpers below
//     are pass-throughs and read behaviour is byte-for-byte what it was before
//     this file existed. Today the opt-in is the two ingest request paths.
//
// SHARING. A memo hit returns the SAME record pointer to every reader in the
// request rather than a fresh decode per call. That is safe on the opted-in
// paths, which treat the resolved record as read-only (the SSTP counter view
// copies the struct before relabelling it), and a write path clears the memo
// rather than mutating through it.

// requestStreamCacheKey is the private context key the memo is filed under. An
// unexported struct{} type cannot collide with any other package's key.
type requestStreamCacheKey struct{}

// streamLookupKind names which stream-store index a memo entry belongs to. The
// same string can be a valid key in more than one index (a pair's tx SID is a
// document _id; its rx SID is an inbound SID), so entries are never shared
// between them.
type streamLookupKind int

const (
	lookupByID streamLookupKind = iota
	lookupByInboundSID
)

// streamLookup is one memoised stream-store answer. Negative results are
// remembered too: resolveIngressStream's SSTP fall-through deliberately probes
// an id it expects to miss, and re-issuing that miss is exactly the round trip
// this memo exists to remove.
type streamLookup struct {
	rec *model.StreamStateRecord
	err error
}

type requestStreamCache struct {
	mu           sync.Mutex
	byID         map[string]streamLookup
	byInboundSID map[string]streamLookup
}

// WithRequestStreamCache returns a context carrying a fresh, empty stream memo
// scoped to the caller's request. It is idempotent: a context that already
// carries a memo is returned unchanged, so nesting cannot silently split one
// request across two memos.
func WithRequestStreamCache(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if requestStreamCacheFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, requestStreamCacheKey{}, &requestStreamCache{
		byID:         make(map[string]streamLookup, 2),
		byInboundSID: make(map[string]streamLookup, 2),
	})
}

// SeedRequestStream primes the memo with a record the caller already resolved
// through some other index, so a downstream resolver keyed on a different SID
// does not fetch it again. It states only facts the store would return anyway:
// the record IS the document whose _id is its tx-side SID, and IS the record
// FindByInboundSID returns for its rx-side SID. Nothing is asserted about a SID
// the record does not carry. A no-op when the context carries no memo.
func SeedRequestStream(ctx context.Context, rec *model.StreamStateRecord) {
	c := requestStreamCacheFrom(ctx)
	if c == nil || rec == nil {
		return
	}
	if id := rec.StreamConfiguration.Id; id != "" {
		c.put(lookupByID, id, streamLookup{rec: rec})
	}
	if rec.SstpInbound != nil && rec.SstpInbound.Id != "" {
		c.put(lookupByInboundSID, rec.SstpInbound.Id, streamLookup{rec: rec})
	}
}

func requestStreamCacheFrom(ctx context.Context) *requestStreamCache {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(requestStreamCacheKey{}).(*requestStreamCache)
	return c
}

// invalidateRequestStreams drops every memoised answer on ctx. It is called by
// each StreamService write, and clears the whole memo rather than one key
// because a single write can change what more than one index returns: naming a
// pair's tx SID also changes what its rx SID resolves to. Stream writes are
// rare next to ingest reads, so the blunt clear costs nothing worth measuring
// and removes any question of which keys a write reached.
func invalidateRequestStreams(ctx context.Context) {
	if c := requestStreamCacheFrom(ctx); c != nil {
		c.clear()
	}
}

// cachedStreamLookup serves key from the request memo when one is installed,
// otherwise it simply calls load. It is the only way entries are created.
func cachedStreamLookup(ctx context.Context, kind streamLookupKind, key string, load func() (*model.StreamStateRecord, error)) (*model.StreamStateRecord, error) {
	c := requestStreamCacheFrom(ctx)
	if c == nil {
		return load()
	}
	if hit, ok := c.get(kind, key); ok {
		return hit.rec, hit.err
	}
	rec, err := load()
	c.put(kind, key, streamLookup{rec: rec, err: err})
	return rec, err
}

func (c *requestStreamCache) bucket(kind streamLookupKind) map[string]streamLookup {
	if kind == lookupByInboundSID {
		return c.byInboundSID
	}
	return c.byID
}

func (c *requestStreamCache) get(kind streamLookupKind, key string) (streamLookup, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hit, ok := c.bucket(kind)[key]
	return hit, ok
}

func (c *requestStreamCache) put(kind streamLookupKind, key string, l streamLookup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bucket(kind)[key] = l
}

func (c *requestStreamCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.byID)
	clear(c.byInboundSID)
}
