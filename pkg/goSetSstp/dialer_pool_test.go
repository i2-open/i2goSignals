// Issue #289 — the SSTP dialer's default client must pool connections.
//
// Before this slice Exchange built `&http.Client{Timeout: timeout}` on every
// cycle. A client with a nil Transport falls back to http.DefaultTransport,
// which caps idle connections at 2 per host, so an SSTP pair with more than a
// couple of in-flight cycles re-handshaked TLS constantly (~17% of the
// receiver node's CPU sat in crypto/tls.(*Conn).clientHandshake). These tests
// pin the pooled-transport contract and the injection precedence that keeps
// per-stream TLS posture working.
package goSetSstp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultDialerClientIsAPooledSingleton pins the two properties that keep
// the TLS handshake off the per-cycle path: the client is process-wide (so its
// transport's connection pool survives between cycles) and the pool is sized
// past net/http's 2-idle-connections-per-host default.
func TestDefaultDialerClientIsAPooledSingleton(t *testing.T) {
	for _, skipVerify := range []bool{false, true} {
		first := defaultDialerClient(skipVerify)
		second := defaultDialerClient(skipVerify)
		require.NotNil(t, first)
		assert.Same(t, first, second,
			"defaultDialerClient(%v) rebuilt the client; the connection pool would be discarded every cycle", skipVerify)

		transport, ok := first.Transport.(*http.Transport)
		require.True(t, ok, "default dialer client (skipVerify=%v) is not on an *http.Transport", skipVerify)
		assert.Greater(t, transport.MaxIdleConnsPerHost, http.DefaultMaxIdleConnsPerHost,
			"default dialer transport (skipVerify=%v) still uses the 2-idle-conn default", skipVerify)
		assert.Equal(t, defaultDialerTimeout, first.Timeout)
	}
}

// TestDefaultDialerClientSeparatesTLSPosture pins the "separate client when
// certificate verification is deliberately skipped" rule: the two postures
// never share a transport, so enabling skip-verify on one pair can never
// relax verification for another.
func TestDefaultDialerClientSeparatesTLSPosture(t *testing.T) {
	verifying := defaultDialerClient(false)
	skipping := defaultDialerClient(true)
	assert.NotSame(t, verifying, skipping, "both TLS postures resolved to one client")

	verifyingTransport := verifying.Transport.(*http.Transport)
	skippingTransport := skipping.Transport.(*http.Transport)
	assert.NotSame(t, verifyingTransport, skippingTransport, "both TLS postures share a transport")

	require.NotNil(t, verifyingTransport.TLSClientConfig)
	assert.False(t, verifyingTransport.TLSClientConfig.InsecureSkipVerify,
		"the verifying posture stopped verifying certificates")
	assert.GreaterOrEqual(t, verifyingTransport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))

	require.NotNil(t, skippingTransport.TLSClientConfig)
	assert.True(t, skippingTransport.TLSClientConfig.InsecureSkipVerify,
		"the skip-verify posture is still verifying certificates")
	assert.GreaterOrEqual(t, skippingTransport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))
}

// recordingRoundTripper counts requests so the injection test can prove the
// caller's client — not the pooled default — carried the cycle.
type recordingRoundTripper struct {
	calls int32
}

func (r *recordingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	atomic.AddInt32(&r.calls, 1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       http.NoBody,
	}, nil
}

// TestExchangeInjectedClientWins pins the precedence that keeps per-stream TLS
// posture working: a caller-supplied client (the credential chain's
// per-stream skip-verify / mTLS / OAuth client) is used verbatim and is never
// swapped for the pooled default.
func TestExchangeInjectedClientWins(t *testing.T) {
	rt := &recordingRoundTripper{}
	injected := &http.Client{Transport: rt, Timeout: 3 * time.Second}

	result := Exchange(context.Background(), Message{}, DialerConfig{
		EndpointURL: "https://peer.example/sstp/abc",
		HTTPClient:  injected,
		// InsecureSkipVerify must be ignored entirely when a client is injected.
		InsecureSkipVerify: true,
	})

	require.NoError(t, result.Err)
	assert.Equal(t, http.StatusOK, result.StatusCode)
	assert.EqualValues(t, 1, atomic.LoadInt32(&rt.calls), "the injected client did not carry the cycle")
}

// TestExchangeHonoursCustomTimeoutOnThePooledTransport covers the one config
// knob that cannot be served by the shared default client: a non-default
// Timeout still gets its own *http.Client, but it must borrow the shared
// pooled transport rather than falling back to http.DefaultTransport.
func TestExchangeHonoursCustomTimeoutOnThePooledTransport(t *testing.T) {
	client := dialerClientFor(DialerConfig{Timeout: 5 * time.Second})
	assert.Equal(t, 5*time.Second, client.Timeout)
	assert.Same(t, pooledDialerTransport(false), client.Transport,
		"a custom-timeout client did not reuse the shared pooled transport")

	// Zero and the default both resolve to the shared singleton.
	assert.Same(t, defaultDialerClient(false), dialerClientFor(DialerConfig{}))
	assert.Same(t, defaultDialerClient(false), dialerClientFor(DialerConfig{Timeout: defaultDialerTimeout}))
	assert.Same(t, defaultDialerClient(true), dialerClientFor(DialerConfig{InsecureSkipVerify: true}))
}

// TestExchangeReusesTLSConnectionsAcrossConcurrentBursts is the behavioural
// proof, and the reason the pool has to be sized rather than merely shared.
//
// A per-cycle `&http.Client{...}` with a nil Transport falls through to
// http.DefaultTransport, which does pool — but keeps only
// http.DefaultMaxIdleConnsPerHost (2) idle connections per host. So a pair
// running several concurrent cycles retains 2 of them and re-handshakes the
// rest on the next burst. Two back-to-back bursts of `burst` concurrent cycles
// must therefore open at most `burst` connections in total: the second burst
// has to find every connection from the first still pooled. Against the 2-idle
// default this test sees roughly burst + (burst - 2).
func TestExchangeReusesTLSConnectionsAcrossConcurrentBursts(t *testing.T) {
	const burst = 8

	var newConns int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		// Hold each request briefly so a burst is genuinely concurrent and
		// really does need `burst` distinct connections.
		time.Sleep(30 * time.Millisecond)
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&newConns, 1)
		}
	}
	srv.StartTLS()
	defer srv.Close()

	cfg := DialerConfig{
		EndpointURL:        srv.URL + "/sstp/pool-test",
		InsecureSkipVerify: true,
	}

	runBurst := func(round int) {
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func(cycle int) {
				defer wg.Done()
				result := Exchange(context.Background(), Message{}, cfg)
				assert.NoError(t, result.Err, "round %d cycle %d", round, cycle)
				assert.Equal(t, http.StatusOK, result.StatusCode, "round %d cycle %d", round, cycle)
			}(i)
		}
		wg.Wait()
	}

	runBurst(1)
	runBurst(2)

	assert.LessOrEqual(t, atomic.LoadInt32(&newConns), int32(burst),
		"two bursts of %d concurrent SSTP cycles opened more than %d connections; "+
			"the dialer is re-handshaking TLS instead of reusing a warm pool", burst, burst)
}
