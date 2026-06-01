package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerClient posts /register with the supplied IAT and requested scopes,
// returning the granted client's AllowedScopes.
func registerClient(t *testing.T, instance *ssfInstance, iat string, scopes []string) (int, []string) {
	t.Helper()
	status, _, roles := registerClientToken(t, instance, iat, scopes)
	return status, roles
}

// registerClientToken posts /register and returns the HTTP status, the issued
// client token, and the granted scopes (carried as roles in the token).
func registerClientToken(t *testing.T, instance *ssfInstance, iat string, scopes []string) (int, string, []string) {
	t.Helper()
	body, _ := json.Marshal(model.RegisterParameters{
		Email:       "ceiling@example.com",
		Description: "ceiling test",
		Scopes:      scopes,
	})
	req, err := http.NewRequest(http.MethodPost, instance.ts.URL+"/register", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+iat)
	req.Header.Set("Content-Type", "application/json")
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, "", nil
	}
	var reg model.RegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	// The granted scopes are carried as roles in the issued client token.
	eat, err := instance.GetAuthIssuer().ParseAuthToken(reg.Token)
	require.NoError(t, err)
	return resp.StatusCode, reg.Token, eat.Roles
}

// TestRegisterCannotSelfGrantStreamAdmin verifies a reg (IAT) caller at
// /register cannot escalate itself to stream_admin. The privilege ceiling caps
// a self-registration at stream_mgmt + event_delivery.
func TestRegisterCannotSelfGrantStreamAdmin(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_ceiling_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	status, granted := registerClient(t, instance, instance.iatToken,
		[]string{authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
	require.Equal(t, http.StatusOK, status)
	assert.NotContains(t, granted, authSupport.ScopeStreamAdmin,
		"a reg token must not be able to self-grant stream_admin")
	// The permitted stream-management capability is still granted.
	assert.Contains(t, granted, authSupport.ScopeStreamMgmt)
}

// TestRegisterAllDroppedScopesRejected verifies that an explicit, non-empty
// scope list that filters entirely to empty (every entry unknown or above the
// privilege ceiling) is rejected with 400 rather than silently producing a
// zero-scope client that authorizes nothing (#137).
func TestRegisterAllDroppedScopesRejected(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_all_dropped_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// Above the ceiling: stream_admin only.
	status, _ := registerClient(t, instance, instance.iatToken,
		[]string{authSupport.ScopeStreamAdmin})
	assert.Equal(t, http.StatusBadRequest, status,
		"an explicit scope list of only above-ceiling scopes must be rejected with 400")

	// Unknown scope only.
	status, _ = registerClient(t, instance, instance.iatToken, []string{"bogus"})
	assert.Equal(t, http.StatusBadRequest, status,
		"an explicit scope list of only unknown scopes must be rejected with 400")
}

// TestRegisterNoScopesDefaults verifies the preserved behavior: a request with
// NO scopes at all still yields the [stream, event] default grant (#137).
func TestRegisterNoScopesDefaults(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_no_scopes_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// No requested scopes falls back to the [stream, event] default at the
	// handler. The issued stream-client token carries stream_mgmt (never admin)
	// — the observable signal that the default grant succeeded.
	status, granted := registerClient(t, instance, instance.iatToken, nil)
	require.Equal(t, http.StatusOK, status,
		"no requested scopes must succeed via the default grant")
	assert.Contains(t, granted, authSupport.ScopeStreamMgmt)
	assert.NotContains(t, granted, authSupport.ScopeStreamAdmin)
}

// TestRegisterMixedScopesAcceptedSubset verifies the preserved silent-drop
// behavior for mixed requests (ADR 0006): an accepted scope alongside a dropped
// one still succeeds, granting only the accepted subset (#137).
func TestRegisterMixedScopesAcceptedSubset(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_mixed_scopes_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// stream_mgmt is accepted; stream_admin is dropped (above the ceiling). The
	// request still succeeds with the accepted subset, and the issued token must
	// not carry admin.
	status, granted := registerClient(t, instance, instance.iatToken,
		[]string{authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin})
	require.Equal(t, http.StatusOK, status,
		"a mixed request must succeed with the accepted subset")
	assert.Contains(t, granted, authSupport.ScopeStreamMgmt)
	assert.NotContains(t, granted, authSupport.ScopeStreamAdmin,
		"the dropped admin scope must not appear in the issued token")
}

// TestStreamMgmtClientCanCreateStream verifies the end-to-end SCIM-receiver
// bootstrap: a client self-registered through /register is capped at
// stream_mgmt + event_delivery (never stream_admin), and must still be able to
// create its own stream. This guards against the regression where StreamCreate
// demanded stream_admin and a non-admin receiver got 403 Forbidden.
func TestStreamMgmtClientCanCreateStream(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "stream_mgmt_create_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// Register exactly as a SCIM receiver does: request stream + event, get
	// capped below stream_admin by the privilege ceiling.
	status, clientToken, granted := registerClientToken(t, instance, instance.iatToken,
		[]string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, clientToken)
	require.NotContains(t, granted, authSupport.ScopeStreamAdmin,
		"a self-registered receiver must not hold stream_admin")
	require.Contains(t, granted, authSupport.ScopeStreamMgmt)

	// A stream-mgmt (non-admin) client must be able to create its own stream.
	streamConfig := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"https://receiver.example.com"},
		EventsSupported: []string{"https://schemas.openid.net/secevent/ssf/event-type/verification"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}
	body, _ := json.Marshal(streamConfig)
	req, err := http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+clientToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode,
		"a stream_mgmt client must be allowed to create its own stream (not 403)")
}
