package eventRouter

import (
	"crypto"
	"errors"
	"strings"
	"sync"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

// signingKeyCacheTTL is how long a node signs with a cached signing key before
// it reads the key store again (issue #313). It is the bound on how long a node
// keeps signing with a key suspended, revoked or replaced through another node,
// or keeps an old key after a rotation made there. A key change made through
// this node clears the issuer's entries at once, so the bound covers exactly the
// changes this node did not handle. Fixed, like the token revocation and
// lease-owner caches.
const signingKeyCacheTTL = 2 * time.Second

// signingKeyCache is the router's key cache: the active signing key and kid per
// issuer and signature algorithm (signingCacheKey), shared by every signing
// transmitter on the node (push, poll and both SSTP ends).
//
// An entry expires signingKeyCacheTTL after it was loaded. The first use after
// that re-reads the key store, and the outcome decides the entry:
//
//   - an active key: it replaces the entry, which may be a new key;
//   - no active key (ErrKeyNotFound): the entry goes, and the caller gets no key,
//     so its transmitter follows the missing-key rule. The absence is not cached:
//     the rule's own retries pace the reads, and a key made active through
//     another node is seen at the next one (#312);
//   - the read fails: the current key stays for another TTL and a WARN is logged,
//     so a key store outage does not pause every transmitter.
//
// One read per entry is in flight at a time: while an expired entry is re-read,
// other callers keep signing with its current key; on a cold miss they wait for
// the read and share its answer. The store is read without the router's lock.
type signingKeyCache struct {
	mu      sync.Mutex
	entries map[string]*signingKeyEntry
	ttl     time.Duration

	// now is the clock the TTL is measured against, a field so tests can drive
	// expiry without sleeping. Read under mu.
	now func() time.Time
}

type signingKeyEntry struct {
	key     crypto.Signer
	kid     string
	expires time.Time
	// loading is the key store read in flight for this entry, nil when none is.
	loading *signingKeyLoad
}

// signingKeyLoad is one key store read. done is closed once key and kid hold its
// answer.
type signingKeyLoad struct {
	done chan struct{}
	key  crypto.Signer
	kid  string
}

func newSigningKeyCache() *signingKeyCache {
	return &signingKeyCache{
		entries: map[string]*signingKeyEntry{},
		ttl:     signingKeyCacheTTL,
		now:     time.Now,
	}
}

// signer returns the cached key and kid for issuer and alg, calling load to read
// the key store on a miss or once the entry has expired. It returns an untyped
// nil signer when there is no key to sign with.
func (c *signingKeyCache) signer(streamID, issuer, alg string, load func() (crypto.Signer, string, error)) (crypto.Signer, string) {
	if c == nil {
		key, kid, err := load()
		if err != nil {
			return nil, ""
		}
		return key, kid
	}
	cacheKey := signingCacheKey(issuer, alg)
	c.mu.Lock()
	entry := c.entries[cacheKey]
	switch {
	case entry == nil:
		entry = &signingKeyEntry{}
		c.entries[cacheKey] = entry
	case entry.loading != nil && entry.key == nil:
		// The first read for this key is in flight: share its answer.
		inFlight := entry.loading
		c.mu.Unlock()
		<-inFlight.done
		return inFlight.key, inFlight.kid
	case entry.loading != nil || c.now().Before(entry.expires):
		// Fresh, or being re-read by another caller: sign with the current key.
		key, kid := entry.key, entry.kid
		c.mu.Unlock()
		return key, kid
	}
	inFlight := &signingKeyLoad{done: make(chan struct{})}
	entry.loading = inFlight
	c.mu.Unlock()

	key, kid, err := load()

	c.mu.Lock()
	defer c.mu.Unlock()
	defer close(inFlight.done)
	entry.loading = nil
	current := c.entries[cacheKey] == entry
	switch {
	case err == nil:
		if current {
			entry.key, entry.kid, entry.expires = key, kid, c.now().Add(c.ttl)
		}
	case entry.key != nil && !errors.Is(err, interfaces.ErrKeyNotFound):
		eventLogger.Warn("Could not re-read the signing key; signing with the current key until the next try",
			"streamID", streamID, "issuer", issuer, "alg", alg, "retryIn", c.ttl, "error", err)
		key, kid = entry.key, entry.kid
		if current {
			entry.expires = c.now().Add(c.ttl)
		}
	default:
		// WARN only when this read takes a cached key away or the store failed.
		// A read that again finds no active key is DEBUG: the entry was already
		// gone, and the transmitter's missing-key rule logs the one ERROR per
		// key-unavailable pause (#312), so a WARN per retry would only add noise.
		if entry.key != nil || !errors.Is(err, interfaces.ErrKeyNotFound) {
			eventLogger.Warn("Unable to locate key for issuer, retrying...", "streamID", streamID, "issuer", issuer, "alg", alg, "error", err)
		} else {
			eventLogger.Debug("Still no active signing key for issuer", "streamID", streamID, "issuer", issuer, "alg", alg)
		}
		key, kid = nil, ""
		if current {
			delete(c.entries, cacheKey)
		}
	}
	// An entry dropped during the read (a key change on this node) is not
	// refilled: the read may predate the change, so the next use reads again.
	inFlight.key, inFlight.kid = key, kid
	return key, kid
}

// forgetIssuer drops the issuer's entries for every signature algorithm. A key
// change is an issuer-level event: an issuer signing one stream RS256 and
// another ES256 must lose both entries.
func (c *signingKeyCache) forgetIssuer(issuer string) {
	if c == nil {
		return
	}
	prefix := issuer + "\x00"
	c.mu.Lock()
	for cacheKey := range c.entries {
		if strings.HasPrefix(cacheKey, prefix) {
			delete(c.entries, cacheKey)
		}
	}
	c.mu.Unlock()
}

// forget drops the entry for one issuer and algorithm.
func (c *signingKeyCache) forget(issuer, alg string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, signingCacheKey(issuer, alg))
	c.mu.Unlock()
}
