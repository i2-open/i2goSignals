package test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postKey issues POST /key/{keyName} (optionally with a force query) carrying
// the supplied bearer, and returns the HTTP status.
func postKey(t *testing.T, instance *ssfInstance, bearer, keyName, force string, body []byte) int {
	t.Helper()
	u := instance.ts.URL + "/key/" + keyName
	if force != "" {
		u += "?force=" + force
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

// deleteKey issues DELETE /key/{keyName} with the supplied bearer.
func deleteKey(t *testing.T, instance *ssfInstance, bearer, keyName string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, instance.ts.URL+"/key/"+keyName, nil)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestKeyScopeCanCreateNewKey verifies a key-scoped (bootstrap) caller may
// create a brand-new issuer signing key.
func TestKeyScopeCanCreateNewKey(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "boot-secret-key")
	instance, err := createServer(t, "key_create_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	status := postKey(t, instance, "boot-secret-key", "newissuer.example.com", "", nil)
	assert.Contains(t, []int{http.StatusOK, http.StatusCreated}, status,
		"key-scope caller must be able to create a new issuer key")
}

// TestKeyScopeDeniedReplace verifies a key-scoped caller cannot take over an
// existing key via force=replace.
func TestKeyScopeDeniedReplace(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "boot-secret-key")
	instance, err := createServer(t, "key_replace_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// First create the key as the bootstrap caller (allowed).
	create := postKey(t, instance, "boot-secret-key", "victim.example.com", "", nil)
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, create)

	// Attempting force=replace must be denied for a key-scope caller.
	status := postKey(t, instance, "boot-secret-key", "victim.example.com", "replace", nil)
	assert.Equal(t, http.StatusForbidden, status, "key scope must NOT permit force=replace (key takeover)")
}

// TestKeyScopeDeniedRotate verifies a key-scoped caller cannot rotate an
// existing key.
func TestKeyScopeDeniedRotate(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "boot-secret-key")
	instance, err := createServer(t, "key_rotate_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	create := postKey(t, instance, "boot-secret-key", "rot.example.com", "", nil)
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, create)

	status := postKey(t, instance, "boot-secret-key", "rot.example.com", "rotate", nil)
	assert.Equal(t, http.StatusForbidden, status, "key scope must NOT permit force=rotate")
}

// TestKeyScopeDeniedDelete verifies a key-scoped caller cannot delete a key.
func TestKeyScopeDeniedDelete(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "boot-secret-key")
	instance, err := createServer(t, "key_delete_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	create := postKey(t, instance, "boot-secret-key", "del.example.com", "", nil)
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, create)

	status := deleteKey(t, instance, "boot-secret-key", "del.example.com")
	assert.Equal(t, http.StatusForbidden, status, "key scope must NOT permit delete")
}

// TestAdminCanReplaceAndDelete confirms a full stream_admin token retains the
// ability to replace/rotate/delete (the key-scope restriction is additive, not
// a regression for admins).
func TestAdminCanReplaceAndDelete(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "key_admin_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()
	admin := instance.streamMgmtToken

	create := postKey(t, instance, admin, "adminkey.example.com", "", nil)
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, create)

	replace := postKey(t, instance, admin, "adminkey.example.com", "replace", nil)
	assert.Contains(t, []int{http.StatusOK, http.StatusCreated}, replace, "admin may replace")

	del := deleteKey(t, instance, admin, "adminkey.example.com")
	assert.Contains(t, []int{http.StatusOK, http.StatusNoContent}, del, "admin may delete")
}
