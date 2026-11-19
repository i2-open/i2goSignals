package goSet

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// JwksOptions tunes a remote JWKS fetched by FetchJwks. Zero values take the
// defaults noted on each field.
type JwksOptions struct {
	// Client fetches the set. Default: http.DefaultClient.
	Client *http.Client
	// RefreshInterval is the background refresh period. Default 1h; a negative
	// value disables background refresh (unknown-kid refresh still applies).
	RefreshInterval time.Duration
	// RefreshRateLimit is the least time between two refreshes triggered by a
	// token naming an unknown kid. Default 5m.
	RefreshRateLimit time.Duration
	// RefreshTimeout bounds one fetch. Default 60s.
	RefreshTimeout time.Duration
	// OnRefreshError is told about a failed refresh. The previous keys stay in
	// use. Default: logged at WARN.
	OnRefreshError func(error)
}

// maxJwksBytes bounds a fetched JWK Set; a real set is a few KB.
const maxJwksBytes = 1 << 20

// FetchJwks fetches the JWK Set at jwksUrl and keeps it fresh: a background
// refresh every RefreshInterval, and a synchronous, rate-limited refresh when a
// token names a kid the set does not hold. Every refresh rebuilds the RSA/EC and
// AKP keys together from the same bytes. The initial fetch must succeed. Call
// Close to stop the refresher.
func FetchJwks(jwksUrl string, opts JwksOptions) (*JWKS, error) {
	if opts.Client == nil {
		opts.Client = http.DefaultClient
	}
	if opts.RefreshInterval == 0 {
		opts.RefreshInterval = time.Hour
	}
	if opts.RefreshRateLimit == 0 {
		opts.RefreshRateLimit = 5 * time.Minute
	}
	if opts.RefreshTimeout == 0 {
		opts.RefreshTimeout = 60 * time.Second
	}
	if opts.OnRefreshError == nil {
		opts.OnRefreshError = func(err error) {
			jwksLog.Warn("JWKS refresh failed; keeping previous keys", "url", jwksUrl, "error", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	j := &JWKS{}
	r := &jwksRemote{owner: j, url: jwksUrl, opts: opts, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	j.remote = r
	if err := r.refresh(); err != nil {
		cancel()
		return nil, err
	}
	if opts.RefreshInterval > 0 {
		go r.loop()
	} else {
		close(r.done)
	}
	return j, nil
}

type jwksRemote struct {
	owner *JWKS
	url   string
	opts  JwksOptions

	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once

	refreshMu   sync.Mutex // serializes fetches
	lastAttempt time.Time
}

func (r *jwksRemote) refresh() error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	return r.refreshLocked()
}

func (r *jwksRemote) refreshLocked() error {
	r.lastAttempt = time.Now()
	ctx, cancel := context.WithTimeout(r.ctx, r.opts.RefreshTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return fmt.Errorf("goSet: JWKS request %s: %w", r.url, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.opts.Client.Do(req)
	if err != nil {
		return fmt.Errorf("goSet: fetching JWKS %s: %w", r.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("goSet: fetching JWKS %s: HTTP %d", r.url, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJwksBytes))
	if err != nil {
		return fmt.Errorf("goSet: reading JWKS %s: %w", r.url, err)
	}
	st, err := buildJwksState(raw)
	if err != nil {
		return err
	}
	r.owner.mu.Lock()
	r.owner.state = st
	r.owner.mu.Unlock()
	return nil
}

// refreshForUnknownKID refreshes unless one was attempted within the rate
// limit, and reports whether the keys were refreshed.
func (r *jwksRemote) refreshForUnknownKID() bool {
	if r.ctx.Err() != nil {
		return false
	}
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if time.Since(r.lastAttempt) < r.opts.RefreshRateLimit {
		return false
	}
	if err := r.refreshLocked(); err != nil {
		r.opts.OnRefreshError(err)
		return false
	}
	return true
}

func (r *jwksRemote) loop() {
	defer close(r.done)
	t := time.NewTicker(r.opts.RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			if err := r.refresh(); err != nil && r.ctx.Err() == nil {
				r.opts.OnRefreshError(err)
			}
		}
	}
}

// close stops the refresher and waits for it to exit.
func (r *jwksRemote) close() {
	r.closeOnce.Do(r.cancel)
	<-r.done
}

// GetJwks fetches a remote JWKS with this project's default client and refresh
// settings. An empty URL yields nil, nil.
func GetJwks(jwksUrl string) (*JWKS, error) {
	return GetJwksWithClient(jwksUrl, nil)
}

// GetJwksWithClient is like GetJwks but uses the supplied http.Client when
// non-nil. Receiver streams pass a client whose TLS config honors the stream's
// transmitter TLS settings (tx_tls_skip_verify / tx_tls_certificate) so the
// issuer JWKS can be fetched from a transmitter presenting a self-signed
// certificate. When client is nil, the SPIFFE resilient transport is used when
// SPIFFE is enabled, otherwise http.DefaultClient.
func GetJwksWithClient(jwksUrl string, client *http.Client) (*JWKS, error) {
	if jwksUrl == "" {
		return nil, nil
	}
	if client == nil && tlsSupport.SpiffeEnabled() {
		client = spiffeJwksClient()
	}
	jwksLog.Info("Loading JWKS", "url", jwksUrl)
	return FetchJwks(jwksUrl, JwksOptions{
		Client:           client,
		RefreshInterval:  time.Hour,
		RefreshRateLimit: 5 * time.Minute,
		RefreshTimeout:   60 * time.Second,
	})
}

// spiffeJwksClient returns a client on the SPIFFE resilient transport, which
// fetches JWKS from both internal SPIFFE nodes and external HTTPS endpoints, or
// nil if the X.509 source is unavailable.
func spiffeJwksClient() *http.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The x509Source lives as long as the client; it is created once per JWKS
	// load (startup or per stream), so this is bounded.
	x509Source, err := tlsSupport.NewX509Source(ctx)
	if err != nil {
		return nil
	}
	transport, err := tlsSupport.NewResilientMTLSClientTransport(x509Source)
	if err != nil {
		return nil
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}
