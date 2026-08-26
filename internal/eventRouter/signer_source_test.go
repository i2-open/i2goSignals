package eventRouter

// The transmitter's key-acquisition path (i2goSignals#277, Slice Contract rev 1
// Seam S2).
//
// The router caches issuer signing keys, so which KeyService method it calls is
// visible exactly once — on a cache miss, deep inside checkAndLoadKey. That is
// precisely the kind of detail an unrelated refactor can quietly re-point at
// GetPrivateKeyWithKeyname, and nothing would fail: both return the same key
// today. It stops being the same key the moment RFC 9964 ML-DSA lands behind
// GetSigner, and the failure then would be a transmitter still signing RS256
// long after it was told not to. These tests pin the call now, while the two
// paths are still equivalent and the pin is cheap.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubSignerSource stands in for KeyService and counts the resolutions it is
// asked for, so a cache hit is distinguishable from a re-resolve.
type stubSignerSource struct {
	mu      sync.Mutex
	calls   int
	issuers []string
	key     crypto.Signer
	kid     string
	err     error
}

func (s *stubSignerSource) GetSigner(_ context.Context, issuer string) (crypto.Signer, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.issuers = append(s.issuers, issuer)
	if s.err != nil {
		return nil, "", s.err
	}
	return s.key, s.kid, nil
}

func (s *stubSignerSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// newKeyCacheRouter builds the minimum router the issuer-key cache needs: the
// two cache maps, a context, and the signer source under test.
func newKeyCacheRouter(src signerSource) *router {
	return &router{
		ctx:        context.Background(),
		issuerKeys: map[string]crypto.Signer{},
		issuerKids: map[string]string{},
		keyService: src,
	}
}

func testSigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func TestCheckAndLoadKey_ResolvesTheIssuerKeyThroughGetSigner(t *testing.T) {
	key := testSigner(t)
	src := &stubSignerSource{key: key, kid: "kid-1"}
	r := newKeyCacheRouter(src)

	got, kid := r.checkAndLoadKey("sid-1", "https://issuer.example.com")

	require.Equal(t, 1, src.callCount(), "the router must acquire its signing key through GetSigner")
	assert.Equal(t, []string{"https://issuer.example.com"}, src.issuers)
	assert.Same(t, key, got)
	assert.Equal(t, "kid-1", kid)
}

func TestCheckAndLoadKey_SecondLookupIsServedFromTheCache(t *testing.T) {
	key := testSigner(t)
	src := &stubSignerSource{key: key, kid: "kid-1"}
	r := newKeyCacheRouter(src)

	first, _ := r.checkAndLoadKey("sid-1", "https://issuer.example.com")
	second, kid := r.checkAndLoadKey("sid-2", "https://issuer.example.com")

	assert.Equal(t, 1, src.callCount(), "a cached issuer key must not be re-resolved per stream")
	assert.Same(t, first, second)
	assert.Equal(t, "kid-1", kid)
}

func TestInvalidateAndReload_GoesBackToGetSigner(t *testing.T) {
	src := &stubSignerSource{key: testSigner(t), kid: "kid-1"}
	r := newKeyCacheRouter(src)
	r.checkAndLoadKey("sid-1", "https://issuer.example.com")

	rotated := testSigner(t)
	src.key, src.kid = rotated, "kid-2"
	got, kid := r.InvalidateAndReload("sid-1", "https://issuer.example.com")

	// RFC 8935 §2.4: a receiver reporting jws_signature_failed must cause a
	// genuine re-read, not a second serve of the key it just rejected.
	assert.Equal(t, 2, src.callCount())
	assert.Same(t, rotated, got)
	assert.Equal(t, "kid-2", kid)
}

func TestCheckAndLoadKey_UnavailableKeyIsAnUntypedNil(t *testing.T) {
	src := &stubSignerSource{err: errors.New("no active signing key")}
	r := newKeyCacheRouter(src)

	got, kid := r.checkAndLoadKey("sid-1", "https://issuer.example.com")

	// Every caller decides whether to sign by comparing this against nil. A
	// typed-nil pointer boxed into the crypto.Signer interface would compare
	// non-nil and send the router on to panic inside the signer instead.
	assert.True(t, got == nil, "an unavailable key must be an untyped nil, not a boxed nil pointer")
	assert.Empty(t, kid)
}

func TestCheckAndLoadKey_FailedLookupIsNotCached(t *testing.T) {
	src := &stubSignerSource{err: errors.New("mongo unavailable")}
	r := newKeyCacheRouter(src)

	r.checkAndLoadKey("sid-1", "https://issuer.example.com")
	src.err = nil
	src.key, src.kid = testSigner(t), "kid-1"
	got, kid := r.checkAndLoadKey("sid-1", "https://issuer.example.com")

	// A transient store failure must not poison the cache with a permanent
	// "this issuer has no key", or the stream never recovers without a restart.
	require.NotNil(t, got)
	assert.Equal(t, "kid-1", kid)
}
