package test

import (
	"context"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterEventScopeIsMintedAsTokenRole pins the contract that supersedes the
// earlier #140 divergence: a granted event_delivery capability is BOTH persisted
// in the client's AllowedScopes AND minted into the stream-client token as a role.
//
// A single registered token can therefore drive both stream management and the
// delivery endpoints (poll/events): a token with empty StreamIds authorizes any
// stream in the project (EventAuthToken.IsAuthorized) and the delivery handlers
// resolve the stream id from the request path. (A per-stream delivery token,
// IssueStreamToken with Roles=[event]+StreamIds=[sid], is still issued at stream
// creation for counterparties that authenticate per stream.)
//
// The earlier divergence withheld event from the token on the premise that such a
// token would be 403'd at delivery anyway; that premise was incorrect, which is
// why the behavior was reconciled.
func TestRegisterEventScopeIsMintedAsTokenRole(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_scope_divergence_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// Default path: no requested scopes yields the [stream, event] default grant.
	status, clientToken, roles := registerClientToken(t, instance, instance.iatToken, nil)
	require.Equal(t, http.StatusOK, status, "default registration must succeed")
	require.NotEmpty(t, clientToken)

	// Minted token carries both stream_mgmt and event_delivery as roles.
	assert.Contains(t, roles, authSupport.ScopeStreamMgmt,
		"the token must carry stream_mgmt")
	assert.Contains(t, roles, authSupport.ScopeEventDelivery,
		"a granted event_delivery capability must be minted as a token role")

	// Persisted AllowedScopes also records event_delivery as a granted capability.
	eat, err := instance.GetAuthIssuer().ParseAuthToken(clientToken)
	require.NoError(t, err)
	require.NotEmpty(t, eat.ClientId, "the token must identify its client")
	client, err := instance.clientSvc().GetClient(context.Background(), eat.ClientId)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Contains(t, client.AllowedScopes, authSupport.ScopeEventDelivery,
		"persisted AllowedScopes must record event_delivery as a granted capability")
	assert.Contains(t, client.AllowedScopes, authSupport.ScopeStreamMgmt)
}

// TestRegisterExplicitEventScopeIsMinted pins the same contract on the
// explicit-request path: a caller asking for [stream_mgmt, event_delivery] has
// both granted, persisted, and minted into the token as roles.
func TestRegisterExplicitEventScopeIsMinted(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_explicit_event_divergence_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	status, clientToken, roles := registerClientToken(t, instance, instance.iatToken,
		[]string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
	require.Equal(t, http.StatusOK, status, "explicit [stream, event] registration must succeed")
	require.NotEmpty(t, clientToken)

	assert.Contains(t, roles, authSupport.ScopeStreamMgmt)
	assert.Contains(t, roles, authSupport.ScopeEventDelivery,
		"an explicitly requested event scope must be minted as a token role")

	eat, err := instance.GetAuthIssuer().ParseAuthToken(clientToken)
	require.NoError(t, err)
	require.NotEmpty(t, eat.ClientId)
	client, err := instance.clientSvc().GetClient(context.Background(), eat.ClientId)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Contains(t, client.AllowedScopes, authSupport.ScopeEventDelivery,
		"explicitly requested event_delivery must be persisted as a granted capability")
}
