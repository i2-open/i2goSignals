package tlsSupport

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpiffeEnabled_NotSet(t *testing.T) {
	t.Setenv(EnvSpiffeSocket, "")
	assert.False(t, SpiffeEnabled())
}

func TestSpiffeEnabled_Set(t *testing.T) {
	t.Setenv(EnvSpiffeSocket, "unix:///tmp/spire-agent.sock")
	assert.True(t, SpiffeEnabled())
}

func TestClusterTrustDomain_Default(t *testing.T) {
	os.Unsetenv(EnvSpiffeTrustDomain)
	td, err := ClusterTrustDomain()
	require.NoError(t, err)
	assert.Equal(t, DefaultTrustDomain, td.Name())
}

func TestClusterTrustDomain_Custom(t *testing.T) {
	t.Setenv(EnvSpiffeTrustDomain, "example.com")
	td, err := ClusterTrustDomain()
	require.NoError(t, err)
	assert.Equal(t, "example.com", td.Name())
}

func TestClusterTrustDomain_Invalid(t *testing.T) {
	t.Setenv(EnvSpiffeTrustDomain, "not a valid trust domain!!!")
	_, err := ClusterTrustDomain()
	assert.Error(t, err)
}

func TestNewClusterMTLSClientConfig_NoSource(t *testing.T) {
	// Passing nil x509Source causes a panic in go-spiffe; this test exercises
	// the trust-domain validation path via ClusterTrustDomain.
	t.Setenv(EnvSpiffeTrustDomain, "bad domain!!!")
	_, err := ClusterTrustDomain()
	assert.Error(t, err, "invalid trust domain should produce an error")
}

func TestNewX509Source_NoSocket(t *testing.T) {
	t.Setenv(EnvSpiffeSocket, "unix:///tmp/nonexistent-spire-agent.sock")
	// Use a pre-cancelled context so NewX509Source fails fast without blocking.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewX509Source(ctx)
	assert.Error(t, err, "expected error when SPIRE agent socket is not available")
}

func TestNewClusterMTLSServerConfig_BadTrustDomain(t *testing.T) {
	t.Setenv(EnvSpiffeTrustDomain, "bad domain!!!")
	_, err := NewClusterMTLSServerConfig(nil)
	assert.Error(t, err)
}

func TestNewClusterMTLSClientConfig_BadTrustDomain(t *testing.T) {
	t.Setenv(EnvSpiffeTrustDomain, "bad domain!!!")
	_, err := NewClusterMTLSClientConfig(nil)
	assert.Error(t, err)
}
