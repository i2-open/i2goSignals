// Server-side SSTP outbound HTTP client pool (issue #289).
//
// Every SSTP dial cycle needs an *http.Client. Two of the server's three
// sources for one used to mint a fresh client per call, and a fresh client
// means a fresh (or default-sized) connection pool, which means a full TLS
// handshake on every exchange:
//
//   - SstpDialerConfig.fillDefaults built `&http.Client{Timeout: 60s}`. Its
//     nil Transport resolves to http.DefaultTransport, whose
//     MaxIdleConnsPerHost is 2 — far below the number of concurrent SSTP
//     cycles a busy pair runs.
//   - resolveSstpBusinessClient's no-alias fallback built `&http.Client{}` and
//     passed it to tlsSupport.CheckCaInstalled. Because Transport was nil,
//     CheckCaInstalled installed a brand new *http.Transport on it
//     (pkg/tlsSupport/key.go), so each cycle got an empty pool of its own and
//     re-read the CA PEM off disk. Profiling the dev cluster's SSTP legs put
//     ~17% of the receiver node's CPU in crypto/tls.(*Conn).clientHandshake.
//
// Both now borrow one process-wide transport, the same shape push delivery
// adopted in pkg/goSetPush/transmitter.go (commit f88eb08). The pool lives in
// the transport, not the client, so the two call sites keep their distinct
// timeout semantics — 60s for the dialer safety net, none for the credential
// chain's long-poll-capable fallback — while sharing warm connections.
//
// The third source, the PeerServerAlias branch, still builds a per-Server
// client through pkg/oauthClient: that client carries operator-configured TLS
// trust and skip-verify posture and must not be collapsed onto this pool.
package server

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

const (
	// sstpMaxIdleConnsPerHost sizes the shared pool for the expected number of
	// concurrent SSTP peers and in-flight cycles per peer. Matches the value
	// push delivery settled on.
	sstpMaxIdleConnsPerHost = 64

	// sstpFallbackClientTimeout is the dialer safety-net timeout, unchanged
	// from the pre-pool inline client.
	sstpFallbackClientTimeout = 60 * time.Second
)

var (
	sstpClientOnce sync.Once
	// sstpTransport is the shared connection pool for all default-posture SSTP
	// outbound traffic.
	sstpTransport *http.Transport
	// sstpFallbackClient is the dialer's safety-net client (60s timeout).
	sstpFallbackClient *http.Client
	// sstpResolverClient is the credential chain's no-alias fallback. It
	// deliberately carries no client-level timeout, preserving the pre-pool
	// behaviour of `&http.Client{}` so a long-poll cycle is bounded by the
	// caller's context rather than by the client.
	sstpResolverClient *http.Client
)

// initSstpClients builds the shared transport and the two clients that ride it.
func initSstpClients() {
	sstpClientOnce.Do(func() {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConnsPerHost = sstpMaxIdleConnsPerHost
		transport.TLSClientConfig = tlsSupport.Harden(&tls.Config{MinVersion: tls.VersionTLS12})

		sstpTransport = transport
		sstpFallbackClient = &http.Client{Transport: transport, Timeout: sstpFallbackClientTimeout}
		sstpResolverClient = &http.Client{Transport: transport}

		// Install the deployment CA into the shared transport once, instead of
		// re-reading the PEM on every dial cycle. CheckCaInstalled mutates the
		// transport's TLSClientConfig, so both clients pick it up.
		tlsSupport.CheckCaInstalled(sstpFallbackClient)
	})
}

// sstpPooledTransport returns the process-wide SSTP outbound transport.
func sstpPooledTransport() *http.Transport {
	initSstpClients()
	return sstpTransport
}

// sstpFallbackHTTPClient returns the dialer's safety-net client: pooled
// transport, 60s timeout. Used when SstpDialerConfig.ResolveClient is unset
// (tests) or returns an error.
func sstpFallbackHTTPClient() *http.Client {
	initSstpClients()
	return sstpFallbackClient
}

// sstpResolverHTTPClient returns the credential chain's no-alias fallback
// client: pooled transport, no client-level timeout.
func sstpResolverHTTPClient() *http.Client {
	initSstpClients()
	return sstpResolverClient
}
