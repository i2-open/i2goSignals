package oauthClient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// spiffeMaxIdleConnsPerHost sizes each peer's idle pool for concurrent SSTP
// cycles and push/poll calls, matching the #289 SSTP dialer pool.
const spiffeMaxIdleConnsPerHost = 64

// spiffeSource is what a SPIFFE mTLS client needs from the workload API: the
// live SVID and trust bundles (both re-read on every handshake, so rotation
// takes effect) and a way to stop the background watcher.
type spiffeSource interface {
	x509svid.Source
	x509bundle.Source
	Close() error
}

// spiffeSourceFactory opens the process-wide workload-API source. It is a
// variable so tests can substitute a fake without a live SPIRE agent.
var spiffeSourceFactory = func(ctx context.Context) (spiffeSource, error) {
	return tlsSupport.NewX509Source(ctx)
}

type spiffePoolEntry struct {
	cfg       model.SpiffeConfig
	client    *http.Client
	transport *http.Transport
}

// errSpiffePoolClosed is returned once CloseSpiffeClients has run: shutdown
// is final, so a late caller cannot open (and leak) a fresh source.
var errSpiffePoolClosed = errors.New("spiffe: client pool is closed")

// spiffePool caches one SPIFFE mTLS client per peer server, all sharing a
// single long-lived X509Source (#326). mu guards the fields but is never held
// while the source is being created (that can take up to 60s); creating is
// non-nil while one goroutine creates it, and is closed when it finishes.
var spiffePool = struct {
	mu       sync.Mutex
	source   spiffeSource
	creating chan struct{}
	closed   bool
	entries  map[string]*spiffePoolEntry
}{entries: map[string]*spiffePoolEntry{}}

// spiffePoolKey identifies a server in the pool: its stored id when it has
// one, otherwise its alias, otherwise its host.
func spiffePoolKey(server *model.Server) string {
	if !server.Id.IsZero() {
		return server.Id.Hex()
	}
	if server.Alias != "" {
		return "alias:" + server.Alias
	}
	return "host:" + server.Host
}

// GetSpiffeClient returns an *http.Client configured with SPIFFE X.509-SVID
// mutual TLS for the given server, plus a close function. Clients are pooled
// per server: repeated calls for the same server and SpiffeConfig return the
// same client and transport, so connections and TLS sessions are reused across
// cycles. The returned close function is a no-op — the pool owns teardown (see
// EvictSpiffeClient and CloseSpiffeClients). Callers may still defer it.
//
//	client, closeClient, err := GetSpiffeClient(ctx, server)
//	if err != nil { ... }
//	defer closeClient()
//
// All pooled clients share one process-wide X509Source, created lazily on
// first use. The source watches the SPIRE agent and rotates SVIDs itself.
//
// The authorizer used depends on server.SpiffeConfig:
//   - If SpiffeID is set: authorizes only that exact SPIFFE ID
//   - If TrustDomain is set: authorizes any SVID from that trust domain
//
// Returns an error when:
//   - SPIFFE_ENDPOINT_SOCKET is not configured
//   - The SpiffeConfig fields are malformed
//   - The SPIRE agent cannot be reached or has no SVID yet (not cached; the
//     next call retries)
//   - The pool has been closed by CloseSpiffeClients
//
// Callers should fall back to the next authentication mode on error.
func GetSpiffeClient(ctx context.Context, server *model.Server) (*http.Client, func(), error) {
	if server == nil || server.SpiffeConfig == nil {
		return nil, nil, errors.New("spiffe: server or SpiffeConfig is nil")
	}
	if !tlsSupport.SpiffeEnabled() {
		return nil, nil, errors.New("spiffe: SPIFFE_ENDPOINT_SOCKET is not configured")
	}

	cfg := *server.SpiffeConfig
	authorizer, err := buildAuthorizer(&cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("spiffe: invalid SpiffeConfig: %w", err)
	}

	key := spiffePoolKey(server)
	noop := func() {}

	spiffePool.mu.Lock()
	if spiffePool.closed {
		spiffePool.mu.Unlock()
		return nil, nil, errSpiffePoolClosed
	}
	if entry, ok := spiffePool.entries[key]; ok && entry.cfg == cfg {
		spiffePool.mu.Unlock()
		return entry.client, noop, nil
	}
	spiffePool.mu.Unlock()

	source, err := acquireSpiffeSource(ctx)
	if err != nil {
		return nil, nil, err
	}

	tlsCfg := tlsconfig.MTLSClientConfig(source, source, authorizer)
	// We must set InsecureSkipVerify to true because we are using SPIFFE ID
	// verification instead of standard hostname verification.
	tlsCfg.InsecureSkipVerify = true
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// SPIFFE mTLS dials the peer directly; never route it via an env proxy.
	transport.Proxy = nil
	transport.MaxIdleConnsPerHost = spiffeMaxIdleConnsPerHost
	transport.TLSClientConfig = tlsCfg

	spiffePool.mu.Lock()
	defer spiffePool.mu.Unlock()
	if spiffePool.closed {
		return nil, nil, errSpiffePoolClosed
	}
	if entry, ok := spiffePool.entries[key]; ok {
		if entry.cfg == cfg {
			// Another caller cached this server first; use its client.
			return entry.client, noop, nil
		}
		// The authorizer changed: drop the old transport's connections.
		entry.transport.CloseIdleConnections()
	}
	entry := &spiffePoolEntry{
		cfg:       cfg,
		transport: transport,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
	spiffePool.entries[key] = entry
	return entry.client, noop, nil
}

// acquireSpiffeSource returns the shared X509Source, creating it on first use.
// Creation runs without spiffePool.mu held, so lookups for cached servers,
// evictions and shutdown are never stalled behind a slow SPIRE agent.
// Concurrent first callers wait for the one in-flight creation. A source that
// finishes after the pool closed (or after another source won) is closed
// rather than leaked.
func acquireSpiffeSource(ctx context.Context) (spiffeSource, error) {
	for {
		spiffePool.mu.Lock()
		if spiffePool.closed {
			spiffePool.mu.Unlock()
			return nil, errSpiffePoolClosed
		}
		if source := spiffePool.source; source != nil {
			spiffePool.mu.Unlock()
			return source, nil
		}
		if wait := spiffePool.creating; wait != nil {
			spiffePool.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("spiffe: waiting for X509Source: %w", ctx.Err())
			}
		}
		done := make(chan struct{})
		spiffePool.creating = done
		spiffePool.mu.Unlock()

		spiffeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		source, err := spiffeSourceFactory(spiffeCtx)
		cancel()

		spiffePool.mu.Lock()
		spiffePool.creating = nil
		close(done)
		if err != nil {
			spiffePool.mu.Unlock()
			return nil, fmt.Errorf("spiffe: failed to create X509Source: %w", err)
		}
		if spiffePool.closed || spiffePool.source != nil {
			winner, closed := spiffePool.source, spiffePool.closed
			spiffePool.mu.Unlock()
			_ = source.Close()
			if closed {
				return nil, errSpiffePoolClosed
			}
			return winner, nil
		}
		spiffePool.source = source
		spiffePool.mu.Unlock()
		return source, nil
	}
}

// EvictSpiffeClient drops the pooled SPIFFE client for the given server and
// closes its idle connections. The entry is located with the same key
// GetSpiffeClient used (id, else alias, else host), so every key form can be
// evicted. Call it when a server's SpiffeConfig changes or the server is
// deleted. A nil or unknown server is ignored.
func EvictSpiffeClient(server *model.Server) {
	if server == nil {
		return
	}
	key := spiffePoolKey(server)
	spiffePool.mu.Lock()
	defer spiffePool.mu.Unlock()
	if entry, ok := spiffePool.entries[key]; ok {
		entry.transport.CloseIdleConnections()
		delete(spiffePool.entries, key)
	}
}

// CloseSpiffeClients closes every pooled SPIFFE transport and the shared
// X509Source. Call it once at shutdown. Closing is final: afterwards
// GetSpiffeClient returns an error, and a source still being created when the
// pool closes is closed as soon as it arrives.
func CloseSpiffeClients() {
	spiffePool.mu.Lock()
	defer spiffePool.mu.Unlock()
	spiffePool.closed = true
	for key, entry := range spiffePool.entries {
		entry.transport.CloseIdleConnections()
		delete(spiffePool.entries, key)
	}
	if spiffePool.source != nil {
		_ = spiffePool.source.Close()
		spiffePool.source = nil
	}
}

// buildAuthorizer constructs the appropriate tlsconfig.Authorizer from the
// SpiffeConfig. SpiffeID takes precedence over TrustDomain when both are set.
func buildAuthorizer(cfg *model.SpiffeConfig) (tlsconfig.Authorizer, error) {
	if cfg.SpiffeID != "" {
		id, err := spiffeid.FromString(cfg.SpiffeID)
		if err != nil {
			return nil, fmt.Errorf("invalid SpiffeID %q: %w", cfg.SpiffeID, err)
		}
		return tlsconfig.AuthorizeID(id), nil
	}

	if cfg.TrustDomain != "" {
		td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
		if err != nil {
			return nil, fmt.Errorf("invalid TrustDomain %q: %w", cfg.TrustDomain, err)
		}
		return tlsconfig.AuthorizeMemberOf(td), nil
	}

	return nil, errors.New("SpiffeConfig must have either SpiffeID or TrustDomain set")
}
