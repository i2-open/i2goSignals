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

// spiffePool caches one SPIFFE mTLS client per peer server, all sharing a
// single long-lived X509Source (#326).
var spiffePool = struct {
	mu      sync.Mutex
	source  spiffeSource
	entries map[string]*spiffePoolEntry
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
	defer spiffePool.mu.Unlock()

	if entry, ok := spiffePool.entries[key]; ok {
		if entry.cfg == cfg {
			return entry.client, noop, nil
		}
		// The authorizer changed: drop the old transport's connections.
		entry.transport.CloseIdleConnections()
		delete(spiffePool.entries, key)
	}

	if spiffePool.source == nil {
		spiffeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		source, err := spiffeSourceFactory(spiffeCtx)
		if err != nil {
			return nil, nil, fmt.Errorf("spiffe: failed to create X509Source: %w", err)
		}
		spiffePool.source = source
	}

	source := spiffePool.source
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, authorizer)
	// We must set InsecureSkipVerify to true because we are using SPIFFE ID
	// verification instead of standard hostname verification.
	tlsCfg.InsecureSkipVerify = true
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = spiffeMaxIdleConnsPerHost
	transport.TLSClientConfig = tlsCfg

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

// EvictSpiffeClient drops the pooled SPIFFE client for the server with the
// given id (as stored; see spiffePoolKey) and closes its idle connections.
// Call it when a server's SpiffeConfig changes or the server is deleted.
// Unknown ids are ignored.
func EvictSpiffeClient(serverID string) {
	spiffePool.mu.Lock()
	defer spiffePool.mu.Unlock()
	if entry, ok := spiffePool.entries[serverID]; ok {
		entry.transport.CloseIdleConnections()
		delete(spiffePool.entries, serverID)
	}
}

// CloseSpiffeClients closes every pooled SPIFFE transport and the shared
// X509Source. Call it at shutdown. The pool stays usable: a later
// GetSpiffeClient opens a fresh source.
func CloseSpiffeClients() {
	spiffePool.mu.Lock()
	defer spiffePool.mu.Unlock()
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
