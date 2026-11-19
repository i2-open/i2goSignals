package test

// goSet.JWKS is the family-owned verification set that replaced keyfunc/v2's
// *keyfunc.JWKS in this module's exported API (i2goSignals#399). These tests pin
// its behaviour at the public seams: keys built in memory, static JWK Sets,
// remote JWK Sets with refresh, and Close.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptomldsa "crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

func TestNewJwksFromKeys_EachKeyVerifiesOnlyItsOwnAlg(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pqKey, err := mldsa.GenerateKey()
	require.NoError(t, err)

	var jwks *goSet.JWKS = goSet.NewJwksFromKeys(map[string]goSet.VerificationKey{
		"rsa-1": {Key: &rsaKey.PublicKey, Alg: "RS256"},
		"ec-1":  {Key: &ecKey.PublicKey, Alg: "ES256"},
		"pq-1":  {Key: pqKey.PublicKey(), Alg: mldsa.Alg},
	})
	assert.ElementsMatch(t, []string{"rsa-1", "ec-1", "pq-1"}, jwks.KIDs())
	assert.Equal(t, 3, jwks.Len())

	for _, tc := range []struct {
		kid    string
		method jwt.SigningMethod
		key    any
	}{
		{"rsa-1", jwt.SigningMethodRS256, rsaKey},
		{"ec-1", jwt.SigningMethodES256, ecKey},
		{"pq-1", mldsa.SigningMethodMLDSA65, pqKey},
	} {
		set, err := goSet.Parse(signSET(t, tc.method, tc.key, tc.kid), jwks)
		require.NoError(t, err, "kid %s must verify a %s SET", tc.kid, tc.method.Alg())
		assert.Equal(t, "https://tx.example.com", set.Issuer)
	}

	// A token naming the RSA kid but claiming ES256 must be refused at the key,
	// even though ES256 is an allowed alg — the pinned alg is the guard.
	_, err = goSet.Parse(signSET(t, jwt.SigningMethodES256, ecKey, "rsa-1"), jwks)
	assert.Error(t, err, "an RS256-pinned key must not be handed to an ES256 token")
}

// rotatingIssuer serves a JWK Set over HTTP that a test can swap out, as a
// transmitter does when it rotates keys.
type rotatingIssuer struct {
	mu   sync.Mutex
	doc  json.RawMessage
	hits int
}

func (r *rotatingIssuer) serve(doc json.RawMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.doc = doc
}

func (r *rotatingIssuer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits++
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(r.doc)
}

// issuerKeys is one generation of an issuer's keys: an RS256 key and an
// ML-DSA-65 key, published together.
type issuerKeys struct {
	rsaKid, pqKid string
	rsa           *rsa.PrivateKey
	pq            *cryptomldsa.PrivateKey
}

func newIssuerKeys(t *testing.T, generation string) issuerKeys {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pq, err := mldsa.GenerateKey()
	require.NoError(t, err)
	return issuerKeys{rsaKid: "rsa-" + generation, pqKid: "pq-" + generation, rsa: r, pq: pq}
}

func (k issuerKeys) jwks(t *testing.T) json.RawMessage {
	t.Helper()
	akp, err := mldsa.NewAKPPublicKey(k.pqKid, k.pq.PublicKey())
	require.NoError(t, err)
	akpJSON, err := json.Marshal(akp)
	require.NoError(t, err)
	rsaJSON, err := json.Marshal(map[string]string{
		"kty": "RSA", "kid": k.rsaKid, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(k.rsa.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.rsa.PublicKey.E)).Bytes()),
	})
	require.NoError(t, err)
	doc, err := json.Marshal(map[string]any{"keys": []json.RawMessage{rsaJSON, akpJSON}})
	require.NoError(t, err)
	return doc
}

func TestFetchJwks_UnknownKidRefreshPicksUpRotatedRSAAndAKPKeys(t *testing.T) {
	gen1, gen2 := newIssuerKeys(t, "1"), newIssuerKeys(t, "2")
	issuer := &rotatingIssuer{}
	issuer.serve(gen1.jwks(t))
	srv := httptest.NewServer(issuer)
	defer srv.Close()

	jwks, err := goSet.FetchJwks(srv.URL, goSet.JwksOptions{
		Client:           srv.Client(),
		RefreshInterval:  -1, // no background refresh: only the unknown-kid path
		RefreshRateLimit: time.Nanosecond,
	})
	require.NoError(t, err)
	defer jwks.Close()
	assert.ElementsMatch(t, []string{"rsa-1", "pq-1"}, jwks.KIDs())

	_, err = goSet.Parse(signSET(t, jwt.SigningMethodRS256, gen1.rsa, gen1.rsaKid), jwks)
	require.NoError(t, err)
	_, err = goSet.Parse(signSET(t, mldsa.SigningMethodMLDSA65, gen1.pq, gen1.pqKid), jwks)
	require.NoError(t, err)

	// The transmitter rotates both keys.
	issuer.serve(gen2.jwks(t))

	_, err = goSet.Parse(signSET(t, mldsa.SigningMethodMLDSA65, gen2.pq, gen2.pqKid), jwks)
	require.NoError(t, err, "a rotated AKP key must be fetched on its first unknown kid")
	_, err = goSet.Parse(signSET(t, jwt.SigningMethodRS256, gen2.rsa, gen2.rsaKid), jwks)
	require.NoError(t, err, "the rotated RSA key arrived in the same refresh")
	assert.ElementsMatch(t, []string{"rsa-2", "pq-2"}, jwks.KIDs(), "retired keys leave with the refresh")
	assert.JSONEq(t, string(gen2.jwks(t)), string(jwks.RawJWKS()))
}

func TestFetchJwks_UnknownKidRefreshIsRateLimited(t *testing.T) {
	gen1, gen2 := newIssuerKeys(t, "1"), newIssuerKeys(t, "2")
	issuer := &rotatingIssuer{}
	issuer.serve(gen1.jwks(t))
	srv := httptest.NewServer(issuer)
	defer srv.Close()

	jwks, err := goSet.FetchJwks(srv.URL, goSet.JwksOptions{
		Client: srv.Client(), RefreshInterval: -1, RefreshRateLimit: time.Hour,
	})
	require.NoError(t, err)
	defer jwks.Close()
	issuer.serve(gen2.jwks(t))

	for i := 0; i < 5; i++ {
		_, err = goSet.Parse(signSET(t, jwt.SigningMethodRS256, gen2.rsa, gen2.rsaKid), jwks)
		assert.Error(t, err)
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	assert.Equal(t, 1, issuer.hits, "a flood of unknown kids must not become a flood of fetches")
}

func TestFetchJwks_BackgroundRefreshPicksUpRotation(t *testing.T) {
	gen1, gen2 := newIssuerKeys(t, "1"), newIssuerKeys(t, "2")
	issuer := &rotatingIssuer{}
	issuer.serve(gen1.jwks(t))
	srv := httptest.NewServer(issuer)
	defer srv.Close()

	jwks, err := goSet.FetchJwks(srv.URL, goSet.JwksOptions{
		Client: srv.Client(), RefreshInterval: 10 * time.Millisecond, RefreshRateLimit: time.Hour,
	})
	require.NoError(t, err)
	defer jwks.Close()
	issuer.serve(gen2.jwks(t))

	assert.Eventually(t, func() bool {
		kids := jwks.KIDs()
		return len(kids) == 2 && kids[0] == "pq-2" && kids[1] == "rsa-2"
	}, 5*time.Second, 10*time.Millisecond, "the background refresh must replace both keys")
}

func TestFetchJwks_FailedInitialFetchIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	jwks, err := goSet.FetchJwks(srv.URL, goSet.JwksOptions{Client: srv.Client()})
	assert.Error(t, err)
	assert.Nil(t, jwks)
}

// jwksRefresherFrame is the stack frame of the goroutine FetchJwks starts for a
// set with background refresh. Counting it is the GH #290 measurement.
const jwksRefresherFrame = "github.com/i2-open/i2goSignals/pkg/goSet.(*jwksRemote).loop"

func jwksRefresherCount() int {
	buf := make([]byte, 1<<18)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return bytes.Count(buf[:n], []byte(jwksRefresherFrame))
		}
		buf = make([]byte, 2*len(buf))
	}
}

func TestJWKSClose_StopsTheRefresherButKeepsTheKeys(t *testing.T) {
	gen1 := newIssuerKeys(t, "1")
	issuer := &rotatingIssuer{}
	issuer.serve(gen1.jwks(t))
	srv := httptest.NewServer(issuer)
	defer srv.Close()

	baseline := jwksRefresherCount()
	const sets = 3
	var all []*goSet.JWKS
	for i := 0; i < sets; i++ {
		jwks, err := goSet.FetchJwks(srv.URL, goSet.JwksOptions{
			Client: srv.Client(), RefreshInterval: 5 * time.Millisecond, RefreshRateLimit: time.Hour,
		})
		require.NoError(t, err)
		all = append(all, jwks)
	}
	assert.Eventually(t, func() bool { return jwksRefresherCount() == baseline+sets },
		5*time.Second, 5*time.Millisecond, "each remote set runs one refresher")

	for _, jwks := range all {
		jwks.Close()
		jwks.Close() // idempotent
	}
	// Close waits for the loop to exit, so the count is already back.
	assert.Equal(t, baseline, jwksRefresherCount(), "Close must end every refresher it started")

	issuer.mu.Lock()
	hitsAtClose := issuer.hits
	issuer.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	issuer.mu.Lock()
	assert.Equal(t, hitsAtClose, issuer.hits, "a closed set must stop fetching")
	issuer.mu.Unlock()

	// Ending the refresh must not invalidate the keys already held.
	_, err := goSet.Parse(signSET(t, jwt.SigningMethodRS256, gen1.rsa, gen1.rsaKid), all[0])
	assert.NoError(t, err)

	var static *goSet.JWKS
	static.Close() // nil-safe
	goSet.NewJwksFromKeys(nil).Close()
}

func TestNewJwksWithAKP_StaticSetVerifiesES256AndSkipsAnUnusableKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pad := func(b []byte) string {
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(out)
	}
	ecJSON, err := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "kid": "ec-1", "alg": "ES256",
		"x": pad(ecKey.PublicKey.X.Bytes()), "y": pad(ecKey.PublicKey.Y.Bytes()),
	})
	require.NoError(t, err)
	// No "alg": the key is usable for any alg its type supports.
	rsaJSON, err := json.Marshal(map[string]string{
		"kty": "RSA", "kid": "rsa-noalg",
		"n": base64.RawURLEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.PublicKey.E)).Bytes()),
	})
	require.NoError(t, err)
	broken := json.RawMessage(`{"kty":"EC","crv":"P-256","kid":"broken","x":"AAAA","y":"AAAA"}`)
	doc, err := json.Marshal(map[string]any{"keys": []json.RawMessage{ecJSON, broken, rsaJSON}})
	require.NoError(t, err)

	jwks, err := goSet.NewJwksWithAKP(doc)
	require.NoError(t, err, "one unusable key must not cost the receiver the set")
	assert.ElementsMatch(t, []string{"ec-1", "rsa-noalg"}, jwks.KIDs())

	_, err = goSet.Parse(signSET(t, jwt.SigningMethodES256, ecKey, "ec-1"), jwks)
	assert.NoError(t, err)
	_, err = goSet.Parse(signSET(t, jwt.SigningMethodRS256, rsaKey, "rsa-noalg"), jwks)
	assert.NoError(t, err)
	_, err = goSet.Parse(signSET(t, jwt.SigningMethodRS256, rsaKey, "ec-1"), jwks)
	assert.Error(t, err, "an ES256 key must not be handed to an RS256 token")
}
