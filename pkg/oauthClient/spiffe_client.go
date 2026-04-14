package oauthClient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// GetSpiffeClient returns an *http.Client configured with SPIFFE X.509-SVID
// mutual TLS for the given server, plus a close function the caller must invoke
// when done with the client. The close function stops the background X509Source
// watcher that keeps the client's TLS certificate up to date.
//
//	client, closeClient, err := GetSpiffeClient(ctx, server)
//	if err != nil { ... }
//	defer closeClient()
//
// The authorizer used depends on server.SpiffeConfig:
//   - If SpiffeID is set: authorizes only that exact SPIFFE ID
//   - If TrustDomain is set: authorizes any SVID from that trust domain
//
// Returns an error when:
//   - SPIFFE_ENDPOINT_SOCKET is not configured
//   - The SpiffeConfig fields are malformed
//   - The SPIRE agent cannot be reached or has no SVID yet
//
// Callers should fall back to the next authentication mode on error.
func GetSpiffeClient(ctx context.Context, server *model.Server) (*http.Client, func(), error) {
	if server == nil || server.SpiffeConfig == nil {
		return nil, nil, errors.New("spiffe: server or SpiffeConfig is nil")
	}
	if !tlsSupport.SpiffeEnabled() {
		return nil, nil, errors.New("spiffe: SPIFFE_ENDPOINT_SOCKET is not configured")
	}

	authorizer, err := buildAuthorizer(server.SpiffeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("spiffe: invalid SpiffeConfig: %w", err)
	}

	spiffeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	x509Source, err := tlsSupport.NewX509Source(spiffeCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("spiffe: failed to create X509Source: %w", err)
	}

	closeFunc := func() { _ = x509Source.Close() }

	tlsCfg := tlsconfig.MTLSClientConfig(x509Source, x509Source, authorizer)
	// We must set InsecureSkipVerify to true because we are using SPIFFE ID
	// verification instead of standard hostname verification.
	tlsCfg.InsecureSkipVerify = true
	transport := &http.Transport{TLSClientConfig: tlsCfg}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}, closeFunc, nil
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
