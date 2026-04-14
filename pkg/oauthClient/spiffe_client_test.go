package oauthClient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

func TestGetSpiffeClient_NilServer(t *testing.T) {
	_, _, err := GetSpiffeClient(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestGetSpiffeClient_NilSpiffeConfig(t *testing.T) {
	server := &model.Server{Host: "https://example.com"}
	_, _, err := GetSpiffeClient(context.Background(), server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestGetSpiffeClient_NoSocket(t *testing.T) {
	t.Setenv(tlsSupport.EnvSpiffeSocket, "")
	server := &model.Server{
		Host:         "https://example.com",
		SpiffeConfig: &model.SpiffeConfig{TrustDomain: "example.com"},
	}
	_, _, err := GetSpiffeClient(context.Background(), server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPIFFE_ENDPOINT_SOCKET")
}

func TestGetSpiffeClient_InvalidSpiffeID(t *testing.T) {
	t.Setenv(tlsSupport.EnvSpiffeSocket, "unix:///tmp/nonexistent.sock")
	server := &model.Server{
		Host:         "https://example.com",
		SpiffeConfig: &model.SpiffeConfig{SpiffeID: "not-a-valid-spiffe-id"},
	}
	// SpiffeID is validated before contacting the SPIRE agent.
	_, _, err := GetSpiffeClient(context.Background(), server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SpiffeID")
}

func TestGetSpiffeClient_InvalidTrustDomain(t *testing.T) {
	t.Setenv(tlsSupport.EnvSpiffeSocket, "unix:///tmp/nonexistent.sock")
	server := &model.Server{
		Host:         "https://example.com",
		SpiffeConfig: &model.SpiffeConfig{TrustDomain: "bad domain!!!"},
	}
	// TrustDomain is validated before contacting the SPIRE agent.
	_, _, err := GetSpiffeClient(context.Background(), server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TrustDomain")
}

func TestGetSpiffeClient_EmptySpiffeConfig(t *testing.T) {
	t.Setenv(tlsSupport.EnvSpiffeSocket, "unix:///tmp/nonexistent.sock")
	server := &model.Server{
		Host:         "https://example.com",
		SpiffeConfig: &model.SpiffeConfig{}, // neither SpiffeID nor TrustDomain
	}
	_, _, err := GetSpiffeClient(context.Background(), server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SpiffeID or TrustDomain")
}

func TestGetSpiffeClient_AgentUnavailable(t *testing.T) {
	// When SPIRE agent socket path is set but agent is not running, NewX509Source
	// should fail after SpiffeConfig validation.
	if testing.Short() {
		t.Skip("skipping agent-dial test in short mode")
	}
	t.Setenv(tlsSupport.EnvSpiffeSocket, "unix:///tmp/nonexistent-agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled context forces fast failure
	server := &model.Server{
		Host:         "https://example.com",
		SpiffeConfig: &model.SpiffeConfig{TrustDomain: "example.com"},
	}
	_, _, err := GetSpiffeClient(ctx, server)
	assert.Error(t, err)
}

func TestBuildAuthorizer_BySpiffeID(t *testing.T) {
	cfg := &model.SpiffeConfig{
		SpiffeID: "spiffe://example.com/workload/server",
	}
	auth, err := buildAuthorizer(cfg)
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestBuildAuthorizer_ByTrustDomain(t *testing.T) {
	cfg := &model.SpiffeConfig{
		TrustDomain: "example.com",
	}
	auth, err := buildAuthorizer(cfg)
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestBuildAuthorizer_SpiffeIDTakesPrecedence(t *testing.T) {
	cfg := &model.SpiffeConfig{
		SpiffeID:    "spiffe://example.com/workload/server",
		TrustDomain: "example.com",
	}
	// Should succeed using SpiffeID (TrustDomain is ignored).
	auth, err := buildAuthorizer(cfg)
	require.NoError(t, err)
	assert.NotNil(t, auth)
}
