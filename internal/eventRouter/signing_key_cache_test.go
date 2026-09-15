package eventRouter

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #313: the key cache expires. A node picks up a key change made through
// any node within signingKeyCacheTTL of the change, reads the key store at most
// once per issuer and algorithm per expiry, and keeps its current key through a
// key store outage.

const cacheIssuer = "https://key-cache.example"

// setClock points the key cache at now, so expiry is driven without sleeping.
func (c *signingKeyCache) setClock(now func() time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

// put installs key as the cached key for issuer and alg, freshly loaded.
func (c *signingKeyCache) put(issuer, alg string, key crypto.Signer, kid string) {
	c.mu.Lock()
	c.entries[signingCacheKey(issuer, alg)] = &signingKeyEntry{key: key, kid: kid, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
}

// holds reports whether the cache has an entry for issuer and alg.
func (c *signingKeyCache) holds(issuer, alg string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[signingCacheKey(issuer, alg)]
	return ok
}

// keyCacheRouter is a router over src whose key cache runs on a fake clock.
func keyCacheRouter(src signerSource) (*router, *fakeClock) {
	r := newKeyCacheRouter(src)
	clk := newFakeClock(time.Now())
	r.signingKeys.setClock(clk.Now)
	return r, clk
}

// gatedSignerSource answers GetSigner with whatever key it holds when the call
// arrives, but only once the test lets the call finish, so a read can be kept in
// flight while other callers run.
type gatedSignerSource struct {
	stubSignerSource
	entered chan struct{}
	gate    chan struct{}
}

func newGatedSignerSource(key crypto.Signer, kid string) *gatedSignerSource {
	return &gatedSignerSource{
		stubSignerSource: stubSignerSource{key: key, kid: kid},
		entered:          make(chan struct{}, 128),
	}
}

// hold makes the next reads wait until release is called.
func (s *gatedSignerSource) hold() {
	s.mu.Lock()
	s.gate = make(chan struct{})
	s.mu.Unlock()
}

func (s *gatedSignerSource) release() {
	s.mu.Lock()
	if s.gate != nil {
		close(s.gate)
		s.gate = nil
	}
	s.mu.Unlock()
}

func (s *gatedSignerSource) set(key crypto.Signer, kid string) {
	s.mu.Lock()
	s.key, s.kid = key, kid
	s.mu.Unlock()
}

func (s *gatedSignerSource) GetSigner(ctx context.Context, issuer string, alg string) (crypto.Signer, string, error) {
	key, kid, err := s.stubSignerSource.GetSigner(ctx, issuer, alg)
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	s.entered <- struct{}{}
	if gate != nil {
		<-gate
	}
	return key, kid, err
}

// waitGroupWithin waits for wg, failing the test (and releasing src so nothing
// is left blocked) when that takes more than a few seconds.
func waitGroupWithin(t *testing.T, wg *sync.WaitGroup, src *gatedSignerSource, msg string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		src.release()
		t.Fatal(msg)
	}
}

func TestKeyCache_EntryExpiresTwoSecondsAfterItWasLoaded(t *testing.T) {
	assert.Equal(t, 2*time.Second, signingKeyCacheTTL, "the bound is a fixed 2s")
	first, rotated := testSigner(t), testSigner(t)
	src := &stubSignerSource{key: first, kid: "kid-1"}
	r, clk := keyCacheRouter(src)
	r.checkAndLoadKey("sid-1", cacheIssuer, "")

	src.key, src.kid = rotated, "kid-2"
	clk.Advance(signingKeyCacheTTL - time.Millisecond)
	got, kid := r.checkAndLoadKey("sid-1", cacheIssuer, "")
	assert.Same(t, first, got, "an entry younger than 2s is served from the cache")
	assert.Equal(t, "kid-1", kid)
	assert.Equal(t, 1, src.callCount())

	clk.Advance(time.Millisecond)
	got, kid = r.checkAndLoadKey("sid-1", cacheIssuer, "")
	assert.Same(t, rotated, got, "the first use after expiry re-reads the key store and uses the new key")
	assert.Equal(t, "kid-2", kid)
	assert.Equal(t, 2, src.callCount())

	got, _ = r.checkAndLoadKey("sid-2", cacheIssuer, "")
	assert.Same(t, rotated, got)
	assert.Equal(t, 2, src.callCount(), "the re-read key is cached for another 2s")
}

func TestKeyCache_NoActiveKeyOnReReadDropsTheKey(t *testing.T) {
	src := &stubSignerSource{key: testSigner(t), kid: "kid-1"}
	r, clk := keyCacheRouter(src)
	r.checkAndLoadKey("sid-1", cacheIssuer, "")

	src.err = interfaces.ErrKeyNotFound // revoked through another node
	clk.Advance(signingKeyCacheTTL)
	got, kid := r.checkAndLoadKey("sid-1", cacheIssuer, "")

	assert.True(t, got == nil, "no active key is an untyped nil, so the transmitter takes the missing-key rule")
	assert.Empty(t, kid)
	assert.False(t, r.signingKeys.holds(cacheIssuer, ""), "the entry is dropped")

	replacement := testSigner(t)
	src.err = nil
	src.key, src.kid = replacement, "kid-2"
	got, _ = r.checkAndLoadKey("sid-1", cacheIssuer, "")
	assert.Same(t, replacement, got, "a missing key is not remembered: the next use reads the store again")
}

func TestKeyCache_StoreFailureKeepsTheCurrentKey(t *testing.T) {
	logs := captureLogs(t)
	current := testSigner(t)
	src := &stubSignerSource{key: current, kid: "kid-1"}
	r, clk := keyCacheRouter(src)
	r.checkAndLoadKey("sid-1", cacheIssuer, "")

	src.err = errors.New("server selection error: context deadline exceeded")
	clk.Advance(signingKeyCacheTTL)
	got, kid := r.checkAndLoadKey("sid-1", cacheIssuer, "")

	assert.Same(t, current, got, "a store outage must not take the key away")
	assert.Equal(t, "kid-1", kid)
	assert.Equal(t, 2, src.callCount())
	warned := false
	for _, line := range logs.lines() {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, cacheIssuer) && strings.Contains(line, "server selection error") {
			warned = true
		}
	}
	assert.True(t, warned, "the failed re-read is logged at WARN")

	got, _ = r.checkAndLoadKey("sid-2", cacheIssuer, "")
	assert.Same(t, current, got)
	assert.Equal(t, 2, src.callCount(), "the store is not retried on every use")

	clk.Advance(signingKeyCacheTTL)
	r.checkAndLoadKey("sid-1", cacheIssuer, "")
	assert.Equal(t, 3, src.callCount(), "it is retried after another 2s")

	recovered := testSigner(t)
	src.err = nil
	src.key, src.kid = recovered, "kid-2"
	clk.Advance(signingKeyCacheTTL)
	got, kid = r.checkAndLoadKey("sid-1", cacheIssuer, "")
	assert.Same(t, recovered, got)
	assert.Equal(t, "kid-2", kid)
}

// Many streams signing with one issuer's key share one re-read per expiry. While
// it is in flight the others keep signing with the current key.
func TestKeyCache_ManyStreamsReadTheStoreOncePerExpiry(t *testing.T) {
	first, rotated := testSigner(t), testSigner(t)
	src := newGatedSignerSource(first, "kid-1")
	r, clk := keyCacheRouter(src)
	r.checkAndLoadKey("sid-0", cacheIssuer, "")
	<-src.entered

	src.set(rotated, "kid-2")
	src.hold()
	clk.Advance(signingKeyCacheTTL)
	loaded := make(chan crypto.Signer, 1)
	go func() {
		key, _ := r.checkAndLoadKey("sid-loader", cacheIssuer, "")
		loaded <- key
	}()
	<-src.entered // the re-read is in flight

	var wg sync.WaitGroup
	served := make(chan crypto.Signer, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, _ := r.checkAndLoadKey("sid-other", cacheIssuer, "")
			served <- key
		}()
	}
	waitGroupWithin(t, &wg, src, "other streams must not wait for the re-read in flight")
	close(served)
	for key := range served {
		assert.Same(t, first, key, "other streams sign with the current key while the re-read is in flight")
	}

	src.release()
	assert.Same(t, rotated, <-loaded)
	assert.Equal(t, 2, src.callCount(), "fifty-one uses after the expiry read the store once")
	got, _ := r.checkAndLoadKey("sid-other", cacheIssuer, "")
	assert.Same(t, rotated, got)
	assert.Equal(t, 2, src.callCount())
}

// On a cold cache every caller waits for the one read in flight and gets its
// answer.
func TestKeyCache_FirstLoadIsSharedByConcurrentCallers(t *testing.T) {
	key := testSigner(t)
	src := newGatedSignerSource(key, "kid-1")
	r, _ := keyCacheRouter(src)
	src.hold()

	var wg sync.WaitGroup
	got := make(chan crypto.Signer, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, _ := r.checkAndLoadKey("sid", cacheIssuer, "")
			got <- k
		}()
	}
	<-src.entered
	src.release()
	wg.Wait()
	close(got)
	for k := range got {
		assert.Same(t, key, k)
	}
	assert.Equal(t, 1, src.callCount())
}

// A key change on this node while a re-read is in flight: the read may predate
// the change, so its answer is not cached and the next use reads again.
func TestKeyCache_KeyChangeDuringAReadIsNotStraddled(t *testing.T) {
	old, replacement := testSigner(t), testSigner(t)
	src := newGatedSignerSource(old, "kid")
	r, clk := keyCacheRouter(src)
	r.checkAndLoadKey("sid-1", cacheIssuer, "")
	<-src.entered

	src.hold()
	clk.Advance(signingKeyCacheTTL)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.checkAndLoadKey("sid-1", cacheIssuer, "") // reads the old key, then waits
	}()
	<-src.entered

	src.set(replacement, "kid") // replace keeps the kid
	r.InvalidateIssuerKey(cacheIssuer)
	src.release()
	<-done

	got, _ := r.checkAndLoadKey("sid-1", cacheIssuer, "")
	assert.Same(t, replacement, got, "the stale read did not repopulate the cache after the change")
	assert.Equal(t, 3, src.callCount())
}

func TestKeyCache_EachAlgorithmExpires(t *testing.T) {
	src := &stubSignerSource{key: testSigner(t), kid: "kid-1"}
	r, clk := keyCacheRouter(src)
	r.checkAndLoadKey("sid-rs", cacheIssuer, "RS256")
	r.checkAndLoadKey("sid-es", cacheIssuer, "ES256")
	require.Equal(t, 2, src.callCount())

	src.err = interfaces.ErrKeyNotFound
	clk.Advance(signingKeyCacheTTL)
	rs, _ := r.checkAndLoadKey("sid-rs", cacheIssuer, "RS256")
	es, _ := r.checkAndLoadKey("sid-es", cacheIssuer, "ES256")

	assert.True(t, rs == nil)
	assert.True(t, es == nil)
	assert.Equal(t, 4, src.callCount())
}
