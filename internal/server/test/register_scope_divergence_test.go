package test

import (
	"context"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterEventScopeIsCapabilityNotTokenRole pins the intentional divergence
// reported in #140: a self-registered client's persisted AllowedScopes records
// event_delivery as a *capability*, but the minted stream-client (management)
// token never carries the event scope as a role.
//
// This is correct-by-design. Event delivery is authorized by a separate
// per-stream delivery token (IssueStreamToken: Roles=[event] + StreamIds=[sid]),
// minted at stream creation and handed to the counterparty — never by the
// client/management token, which carries only stream_mgmt (and stream_admin only
// for out-of-band-provisioned clients). The delivery endpoints additionally
// require a StreamId the management token does not carry, so threading event into
// the management token would produce a token that is still 403'd everywhere.
//
// The test guards against a future change that "reconciles" the divergence by
// minting event into the management token (rejected option (a) in #140 triage):
// that would flip the NotContains assertion and fail here.
func TestRegisterEventScopeIsCapabilityNotTokenRole(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_scope_divergence_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// Default path: no requested scopes yields the [stream, event] default grant.
	status, clientToken, roles := registerClientToken(t, instance, instance.iatToken, nil)
	require.Equal(t, http.StatusOK, status, "default registration must succeed")
	require.NotEmpty(t, clientToken)

	// Minted management token carries stream_mgmt but NOT event_delivery.
	assert.Contains(t, roles, authSupport.ScopeStreamMgmt,
		"the management token must carry stream_mgmt")
	assert.NotContains(t, roles, authSupport.ScopeEventDelivery,
		"event_delivery is a capability, never minted as a management-token role (#140)")

	// Persisted AllowedScopes records event_delivery as a granted capability.
	eat, err := instance.GetAuthIssuer().ParseAuthToken(clientToken)
	require.NoError(t, err)
	require.NotEmpty(t, eat.ClientId, "the management token must identify its client")
	client, err := instance.clientSvc().GetClient(context.Background(), eat.ClientId)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Contains(t, client.AllowedScopes, authSupport.ScopeEventDelivery,
		"persisted AllowedScopes must record event_delivery as a granted capability")
	assert.Contains(t, client.AllowedScopes, authSupport.ScopeStreamMgmt)
}

// TestRegisterExplicitEventScopeDivergence pins the same divergence (#140) on the
// explicit-request path: a caller asking for [stream_mgmt, event_delivery] has
// both granted and persisted, but the minted management token still omits event.
func TestRegisterExplicitEventScopeDivergence(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_explicit_event_divergence_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	status, clientToken, roles := registerClientToken(t, instance, instance.iatToken,
		[]string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
	require.Equal(t, http.StatusOK, status, "explicit [stream, event] registration must succeed")
	require.NotEmpty(t, clientToken)

	assert.Contains(t, roles, authSupport.ScopeStreamMgmt)
	assert.NotContains(t, roles, authSupport.ScopeEventDelivery,
		"an explicitly requested event scope is still not minted as a management-token role (#140)")

	eat, err := instance.GetAuthIssuer().ParseAuthToken(clientToken)
	require.NoError(t, err)
	require.NotEmpty(t, eat.ClientId)
	client, err := instance.clientSvc().GetClient(context.Background(), eat.ClientId)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Contains(t, client.AllowedScopes, authSupport.ScopeEventDelivery,
		"explicitly requested event_delivery must be persisted as a granted capability")
}
