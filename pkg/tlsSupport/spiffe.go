package tlsSupport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// FromX509Certificate returns the SPIFFE ID from the given X.509 certificate.
func FromX509Certificate(cert *x509.Certificate) (spiffeid.ID, error) {
	return x509svid.IDFromCert(cert)
}

const (
	// EnvSpiffeSocket is the environment variable that specifies the SPIRE agent
	// Unix socket path. Setting this variable enables all SPIFFE features.
	EnvSpiffeSocket = "SPIFFE_ENDPOINT_SOCKET"

	// EnvSpiffeTrustDomain is the environment variable that specifies the SPIFFE
	// trust domain for this cluster.
	EnvSpiffeTrustDomain = "SPIFFE_TRUST_DOMAIN"

	// DefaultTrustDomain is the default SPIFFE trust domain used when
	// SPIFFE_TRUST_DOMAIN is not set.
	DefaultTrustDomain = "cluster.i2gosignals.internal"
)

// SpiffeEnabled returns true when SPIFFE_ENDPOINT_SOCKET is configured,
// indicating that a SPIRE agent is available for SVID retrieval.
// All SPIFFE functionality in i2goSignals is gated on this check, allowing
// deployments without SPIRE to continue using existing HMAC and OAuth auth.
func SpiffeEnabled() bool {
	return os.Getenv(EnvSpiffeSocket) != ""
}

// NewX509Source creates a new X509Source backed by the SPIRE agent at the
// path given by SPIFFE_ENDPOINT_SOCKET. The source automatically watches
// for SVID rotations and must be closed when no longer needed.
//
// Returns an error if the socket is not set or the initial SVID cannot be fetched.
func NewX509Source(ctx context.Context) (*workloadapi.X509Source, error) {
	socket := os.Getenv(EnvSpiffeSocket)
	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SPIRE agent at %s: %w", socket, err)
	}
	return source, nil
}

// ClusterTrustDomain returns the trust domain for this cluster from
// SPIFFE_TRUST_DOMAIN, falling back to DefaultTrustDomain.
func ClusterTrustDomain() (spiffeid.TrustDomain, error) {
	name := os.Getenv(EnvSpiffeTrustDomain)
	if name == "" {
		name = DefaultTrustDomain
	}
	return spiffeid.TrustDomainFromString(name)
}

// NewResilientMTLSClientConfig returns a *tls.Config that presents the workload's
// X509-SVID and validates the peer using either its SPIFFE ID (internal)
// or standard hostname verification (external/legacy). This resilient configuration
// is required to prevent connectivity regressions to non-SPIRE HTTPS endpoints
// (e.g. JWKS, public APIs) while maintaining SPIFFE-level security for internal calls.
//
// Internal Logic (Dual-Validation):
//  1. SPIFFE Path: Attempts to extract a SPIFFE ID. If it matches the cluster
//     trust domain, validation is performed against the SPIRE trust bundle.
//  2. Standard Path: If the peer is NOT in the trust domain, falls back to
//     standard X.509 chain and hostname verification using the combined Root CAs.
func NewResilientMTLSClientConfig(x509Source *workloadapi.X509Source) (*tls.Config, error) {
	td, err := ClusterTrustDomain()
	if err != nil {
		return nil, err
	}

	// 1. Prepare combined RootCAs: System + Global CA (ca-cert.pem) + SPIRE Bundle
	roots := GetGlobalCertPool()
	bundle, err := x509Source.GetX509BundleForTrustDomain(td)
	if err == nil {
		for _, cert := range bundle.X509Authorities() {
			roots.AddCert(cert)
		}
	}

	// 2. Base SPIFFE config for client cert presentation
	spiffeCfg := tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())

	return &tls.Config{
		MinVersion:           tls.VersionTLS12,
		GetClientCertificate: spiffeCfg.GetClientCertificate,
		RootCAs:              roots,
		InsecureSkipVerify:   true, // Manual verification required for dual-path in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificates provided")
			}
			cert := cs.PeerCertificates[0]

			// PATH A: SPIFFE ID Validation
			id, err := FromX509Certificate(cert)
			if err == nil && id.TrustDomain() == td {
				// Peer is a member of the cluster trust domain.
				// Verify the chain against our combined roots (includes SPIRE bundle).
				_, err = cert.Verify(x509.VerifyOptions{
					Roots: roots,
				})
				if err == nil {
					return nil // SPIFFE validation successful
				}
			}

			// PATH B: Standard X.509 Hostname & Chain Validation
			// Fallback for external SSF endpoints or non-SPIRE internal nodes.
			opts := x509.VerifyOptions{
				Roots:         roots,
				DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			for i, c := range cs.PeerCertificates {
				if i > 0 {
					opts.Intermediates.AddCert(c)
				}
			}
			_, err = cert.Verify(opts)
			return err
		},
	}, nil
}

// NewClusterMTLSClientConfig returns a *tls.Config that presents the workload's
// X509-SVID to the server and validates the peer using the resilient
// dual-validation strategy (SPIFFE ID + standard X.509 hostname/chain).
// Used for outbound inter-cluster calls (e.g. WakeTransmitter).
//
// Returns an error if SPIFFE_TRUST_DOMAIN is malformed.
func NewClusterMTLSClientConfig(x509Source *workloadapi.X509Source) (*tls.Config, error) {
	return NewResilientMTLSClientConfig(x509Source)
}

// NewSpiffeServerConfig returns a *tls.Config that presents the workload's
// X509-SVID to connecting clients and optionally requests a client X509-SVID
// for mTLS. ClientAuth is set to tls.RequestClientCert to allow fallback to
// non-SPIFFE authentication (e.g. HMAC or OAuth).
func NewSpiffeServerConfig(x509Source *workloadapi.X509Source) (*tls.Config, error) {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequestClientCert,
		GetCertificate: tlsconfig.GetCertificate(x509Source),
		// Since we're requesting but not requiring a client cert,
		// we allow all through and let the handlers authorize the peer.
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
			return nil
		},
	}, nil
}

// NewResilientMTLSClientTransport returns an *http.Transport configured with the
// "Dual-Validation" strategy (SPIFFE ID + standard X.509 hostname/chain).
// This transport is suitable for all outbound cluster calls, as it correctly
// handles both internal SPIRE-enabled nodes and external HTTPS services.
func NewResilientMTLSClientTransport(x509Source *workloadapi.X509Source) (*http.Transport, error) {
	tlsConfig, err := NewResilientMTLSClientConfig(x509Source)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		TLSClientConfig: tlsConfig,
	}, nil
}

// NewClusterMTLSClientTransport returns an *http.Transport that is configured
// for inter-cluster SPIFFE mTLS, using the resilient "Dual-Validation" strategy.
func NewClusterMTLSClientTransport(x509Source *workloadapi.X509Source) *http.Transport {
	transport, err := NewResilientMTLSClientTransport(x509Source)
	if err != nil {
		return &http.Transport{}
	}
	return transport
}

// ExportTrustBundle writes the SPIFFE trust bundle for the current trust domain
// to a file in PEM format.
func ExportTrustBundle(x509Source *workloadapi.X509Source, path string) error {
	td, err := ClusterTrustDomain()
	if err != nil {
		return err
	}
	bundle, err := x509Source.GetX509BundleForTrustDomain(td)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, cert := range bundle.X509Authorities() {
		if err := encodeCert(f, cert); err != nil {
			return err
		}
	}
	return nil
}

func encodeCert(out io.Writer, cert *x509.Certificate) error {
	return pem.Encode(out, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// NewClusterMTLSServerConfig returns a *tls.Config for the internal cluster
// server that presents the workload's X509-SVID to connecting clients and
// optionally requests a client X509-SVID from the cluster trust domain.
//
// ClientAuth is set to tls.RequestClientCert rather than RequireAndVerifyClientCert,
// so that connections without a client certificate are still accepted. This allows
// HMAC-only nodes to communicate during a phased SPIRE rollout. The WakeTransmitter
// handler is responsible for checking the peer SPIFFE ID when a certificate is present.
//
// Returns an error if SPIFFE_TRUST_DOMAIN is malformed.
func NewClusterMTLSServerConfig(x509Source *workloadapi.X509Source) (*tls.Config, error) {
	_, err := ClusterTrustDomain()
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Request but don't require a client cert, preserving HMAC-only fallback.
		ClientAuth:     tls.RequestClientCert,
		GetCertificate: tlsconfig.GetCertificate(x509Source),
		// Allow all client certs through TLS; the handler validates SPIFFE ID.
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
			return nil
		},
	}
	return cfg, nil
}
