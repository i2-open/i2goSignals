package tlsSupport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

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
	return workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
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

// NewClusterMTLSClientConfig returns a *tls.Config that presents the workload's
// X509-SVID to the server and authorizes peer SVIDs that belong to the cluster
// trust domain. Used for outbound inter-cluster calls (e.g. WakeTransmitter).
//
// Returns an error if SPIFFE_TRUST_DOMAIN is malformed.
func NewClusterMTLSClientConfig(x509Source *workloadapi.X509Source) (*tls.Config, error) {
	td, err := ClusterTrustDomain()
	if err != nil {
		return nil, err
	}
	return tlsconfig.MTLSClientConfig(x509Source, x509Source,
		tlsconfig.AuthorizeMemberOf(td)), nil
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
