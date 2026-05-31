package test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getIat issues a GET /iat with the supplied bearer (empty => anonymous) and
// returns the HTTP status and the minted token (if any).
func getIat(t *testing.T, instance *ssfInstance, bearer string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, instance.ts.URL+"/iat", nil)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	var reg model.RegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	return resp.StatusCode, reg.Token
}

// TestIatFailsClosedWhenBootstrapUnset verifies the anonymous /iat door is gone:
// with I2SIG_BOOTSTRAP_TOKEN unset, an unauthenticated caller is rejected.
func TestIatFailsClosedWhenBootstrapUnset(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "iat_failclosed_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	status, _ := getIat(t, instance, "")
	assert.NotEqual(t, http.StatusOK, status, "anonymous /iat must not succeed when bootstrap is unset")
	assert.Contains(t, []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusForbidden}, status)
}

// TestIatAcceptsBootstrapSecretAndMintsRegOnly verifies a key-scope bootstrap
// caller can obtain an IAT, and that the minted IAT carries reg only — the key
// capability does not propagate.
func TestIatAcceptsBootstrapSecretAndMintsRegOnly(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "boot-secret-iat")
	instance, err := createServer(t, "iat_bootstrap_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	status, token := getIat(t, instance, "boot-secret-iat")
	require.Equal(t, http.StatusOK, status, "bootstrap secret should mint an IAT")
	require.NotEmpty(t, token)

	eat, err := instance.GetAuthIssuer().ParseAuthToken(token)
	require.NoError(t, err)
	assert.Contains(t, eat.Roles, authSupport.ScopeRegister, "minted IAT must carry reg")
	assert.NotContains(t, eat.Roles, authSupport.ScopeKey, "key capability must NOT propagate into the IAT")
	assert.NotContains(t, eat.Roles, authSupport.ScopeStreamAdmin)
	assert.NotContains(t, eat.Roles, authSupport.ScopeRoot)
}

// TestIatAcceptsAdminToken verifies an existing stream_admin token can still
// obtain an IAT (the /iat endpoint accepts {key, stream_admin, root}).
func TestIatAcceptsAdminToken(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "iat_admin_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	status, token := getIat(t, instance, instance.streamMgmtToken)
	require.Equal(t, http.StatusOK, status, "stream_admin token should obtain an IAT")
	require.NotEmpty(t, token)

	eat, err := instance.GetAuthIssuer().ParseAuthToken(token)
	require.NoError(t, err)
	assert.Contains(t, eat.Roles, authSupport.ScopeRegister)
}
