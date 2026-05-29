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
		return resp.StatusCode, nil
	}
	var reg model.RegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	// The granted scopes are carried as roles in the issued client token.
	eat, err := instance.GetAuthIssuer().ParseAuthToken(reg.Token)
	require.NoError(t, err)
	return resp.StatusCode, eat.Roles
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
