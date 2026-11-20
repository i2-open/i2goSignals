package memory_provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

// TestPersistence_KeyCreatedAtSurvivesSaveAndReopen (i2goSignals#316): a
// keys.json written before JwkKeyRec.CreatedAt existed loads with a zero
// CreatedAt, a key minted afterwards keeps its CreatedAt across a save and
// reopen, and after the reopen the rotated key, not the legacy one with the
// higher random id, is the signing key.
func TestPersistence_KeyCreatedAtSurvivesSaveAndReopen(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	t.Setenv(CEnvMemDir, tmpDir)
	t.Setenv(CEnvMemSaveRate, "0") // save on every change

	const issuer = "https://legacy.example"
	legacyKid := issuer + "-f1c2a9e0d3b4c5a6e7f80912"
	legacyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	legacyJSON, err := json.Marshal(map[string]*interfaces.JwkKeyRec{legacyKid: {
		Id:          "f1c2a9e0d3b4c5a6e7f80912",
		KeyName:     issuer,
		Kid:         legacyKid,
		Use:         "sig",
		KeyBytes:    x509.MarshalPKCS1PrivateKey(legacyKey),
		PubKeyBytes: x509.MarshalPKCS1PublicKey(&legacyKey.PublicKey),
	}})
	require.NoError(t, err)
	require.NotContains(t, string(legacyJSON), "createdAt", "the seeded record has the pre-upgrade shape")
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "keys.json"), legacyJSON, 0644))

	provider, err := Open("memorydb:", "testKeyCreatedAt")
	require.NoError(t, err)
	legacy, err := provider.rawKeyDAO.FindByKid(ctx, legacyKid)
	require.NoError(t, err)
	assert.True(t, legacy.CreatedAt.IsZero(), "a legacy record loads with a zero CreatedAt")

	_, newKid, err := provider.GetKeyService().RotateKey(ctx, issuer, "RS256", "")
	require.NoError(t, err)
	minted, err := provider.rawKeyDAO.FindByKid(ctx, newKid)
	require.NoError(t, err)
	require.False(t, minted.CreatedAt.IsZero())
	require.NoError(t, provider.Close())

	reopened, err := Open("memorydb:", "testKeyCreatedAt")
	require.NoError(t, err)
	defer func() { _ = reopened.Close() }()

	reloaded, err := reopened.rawKeyDAO.FindByKid(ctx, newKid)
	require.NoError(t, err)
	assert.True(t, minted.CreatedAt.Equal(reloaded.CreatedAt), "CreatedAt %v survives the reopen as %v", minted.CreatedAt, reloaded.CreatedAt)
	legacy, err = reopened.rawKeyDAO.FindByKid(ctx, legacyKid)
	require.NoError(t, err)
	assert.True(t, legacy.CreatedAt.IsZero(), "the legacy record is still unstamped")

	_, kid, err := reopened.GetKeyService().GetSigner(ctx, issuer, "RS256")
	require.NoError(t, err)
	assert.Equal(t, newKid, kid, "the rotated key is still the signing key after the reopen")
}
