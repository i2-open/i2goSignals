package main

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateEvent_ES256DefaultServer is the spec #114 production-wiring
// test: against a server whose new keys default to ES256 (I2SIG_KEY_ALG),
// `create key` saves the ES256 key and its kid, and `generate event` signs
// with ES256 and the server's kid for that key, so the push receiver verifies
// and accepts the SET.
func TestGenerateEvent_ES256DefaultServer(t *testing.T) {
	t.Setenv("I2SIG_KEY_ALG", "ES256")
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "es256-bootstrap")
	t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "1")
	t.Setenv("I2SIG_POLL_MAX_TIMEOUT", "1")
	dir := t.TempDir()
	configName := filepath.Join(dir, "toolconfig.json")
	t.Setenv("GOSIGNALS_HOME", configName)

	instance, err := createServer(t, "es256server")
	require.NoError(t, err)
	defer instance.app.Shutdown()

	authIssuer := instance.persistence.KeyService.GetAuthIssuer()
	iat, err := authIssuer.IssueProjectIat(nil)
	require.NoError(t, err)
	eat, err := authIssuer.ParseAuthToken(iat)
	require.NoError(t, err)
	adminToken, err := authIssuer.IssueStreamClientToken(model.SsfClient{
		Id:            model.NewRecordId(),
		ProjectIds:    []string{eat.ProjectId},
		AllowedScopes: []string{authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt},
		Email:         "test@test.com",
		Description:   "es256 test",
	}, eat.ProjectId, true, eat.ID)
	require.NoError(t, err)

	cli := &CLI{}
	cli.Globals.Config = configName
	pd, err := initParser(cli)
	require.NoError(t, err)
	tool := &toolSuite{pd: pd}

	addr := instance.server.Addr
	iss := "es256.scim.example.com"
	_, err = tool.executeCommand(fmt.Sprintf("add server es256 http://%s/ --desc=es256 --email=test@example.com --token=%s", addr, adminToken), false)
	require.NoError(t, err)

	pemFile := filepath.Join(dir, "issuer.pem")
	_, err = tool.executeCommand(fmt.Sprintf("create key es256 %s --file=%s", iss, pemFile), false)
	require.NoError(t, err)

	kidBytes, err := os.ReadFile(pemFile + ".kid")
	require.NoError(t, err, "create key writes <file>.kid")
	kid := strings.TrimSpace(string(kidBytes))
	assert.NotEmpty(t, kid)
	assert.NotEqual(t, iss, kid, "an ES256 key's kid is not the legacy issuer kid")
	key, err := cli.Data.GetKey(iss)
	require.NoError(t, err)
	_, isEC := key.(*ecdsa.PrivateKey)
	assert.True(t, isEC, "the stored PEM is the created ES256 key, got %T", key)

	_, err = tool.executeCommand(fmt.Sprintf("create stream push receive es256 --name=generator --mode=IMPORT --aud=receiver.example.com --iss=%s --events=*:prov:create:* --iss-jwks-url=http://%s/jwks/%s", iss, addr, iss), true)
	require.NoError(t, err)

	out, err := tool.executeCommand("generate generator --event=create:full", true)
	require.NoError(t, err, "the receiver verifies the ES256 SET: %s", out)
	assert.Contains(t, string(out), "Submitted.")
}
