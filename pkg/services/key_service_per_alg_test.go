package services

// Per-algorithm key create, rotate and replace (i2goSignals#314). A signing key
// is created only by an operator, one algorithm at a time, and rotate and
// replace leave the issuer's keys of other algorithms alone.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	cryptomldsa "crypto/mldsa"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// kidsByAlg groups keyName's records by their stored algorithm label.
func kidsByAlg(t *testing.T, dao interfaces.KeyDAO, keyName string) map[string][]string {
	t.Helper()
	recs, err := dao.FindByKeyName(context.Background(), keyName)
	require.NoError(t, err)
	out := map[string][]string{}
	for _, rec := range recs {
		label := algLabel(rec.Alg)
		out[label] = append(out[label], recKid(rec))
	}
	return out
}

func TestValidateKeyAlg_AcceptsTheKeyStoresAlgorithms(t *testing.T) {
	for _, alg := range []string{"", "RS256", "ES256", mldsa.Alg} {
		assert.NoError(t, ValidateKeyAlg(alg), "alg %q must be accepted", alg)
	}
	for _, alg := range []string{"HS256", "none", "ES384", "es256", "ML-DSA-44"} {
		err := ValidateKeyAlg(alg)
		require.Error(t, err, "alg %q must be rejected", alg)
		assert.True(t, errors.Is(err, ErrUnsupportedKeyAlg), "alg %q: %v", alg, err)
	}
}

func TestCreateKeyPairForAlg_AddsAKeyAlongsideTheIssuersOtherAlgorithms(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t) // rtIssuer already holds an RSA key

	ecKey, ecKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, "ES256", "sig", "")
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, ecKey)
	pqKey, pqKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, mldsa.Alg, "sig", "")
	require.NoError(t, err)
	assert.IsType(t, &cryptomldsa.PrivateKey{}, pqKey)
	assert.NotEqual(t, ecKid, pqKid)

	byAlg := kidsByAlg(t, dao, rtIssuer)
	assert.Equal(t, []string{rtIssuer}, byAlg["RS256"], "the RSA key is untouched")
	assert.Equal(t, []string{ecKid}, byAlg["ES256"])
	assert.Equal(t, []string{pqKid}, byAlg[mldsa.Alg])

	for _, alg := range []string{"RS256", "ES256", mldsa.Alg} {
		_, _, err := svc.GetSigner(ctx, rtIssuer, alg)
		assert.NoError(t, err, "a usable %s signer must exist", alg)
	}
	kids := map[string]bool{}
	for _, k := range jwksKeys(t, *svc.GetPublicJWKS(ctx, rtIssuer)) {
		kids[k["kid"].(string)] = true
	}
	assert.True(t, kids[rtIssuer] && kids[ecKid] && kids[pqKid], "every key is published in the JWKS: %v", kids)
}

func TestCreateKeyPairForAlg_RS256OnANewNameUsesTheNameAsKid(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)

	key, kid, err := svc.CreateKeyPairForAlg(ctx, "https://new.example", "", "sig", "")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, key)
	assert.Equal(t, "https://new.example", kid, "an RS256 key on a new name keeps today's kid")
	assert.Equal(t, map[string][]string{"RS256": {"https://new.example"}}, kidsByAlg(t, dao, "https://new.example"))
}

// TestCreateKeyPairForAlg_RS256AfterRevokeGetsItsOwnKid: a revoked record keeps
// the name's kid, so a new RS256 key must not overwrite it.
func TestCreateKeyPairForAlg_RS256AfterRevokeGetsItsOwnKid(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)
	_, _, err := svc.SetKeyStatus(ctx, rtIssuer, rtIssuer, interfaces.KeyStatusRevoked)
	require.NoError(t, err)

	_, kid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, "RS256", "sig", "")
	require.NoError(t, err)
	assert.NotEqual(t, rtIssuer, kid)

	assert.ElementsMatch(t, []string{rtIssuer, kid}, kidsByAlg(t, dao, rtIssuer)["RS256"], "the revoked record is kept")
	_, signingKid, err := svc.GetSigner(ctx, rtIssuer, "RS256")
	require.NoError(t, err)
	assert.Equal(t, kid, signingKid)
}

func TestCreateKeyPairForAlg_RejectsAnUnsupportedAlg(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)
	_, _, err := svc.CreateKeyPairForAlg(ctx, "https://new.example", "HS256", "sig", "")
	assert.True(t, errors.Is(err, ErrUnsupportedKeyAlg), "%v", err)
	assert.Empty(t, kidsByAlg(t, dao, "https://new.example"))
}

func TestKeyExistsForAlg_CountsOnlyUnrevokedKeysOfThatAlgorithm(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)

	exists, err := svc.KeyExistsForAlg(ctx, rtIssuer, "")
	require.NoError(t, err)
	assert.True(t, exists, "the RSA key exists")
	exists, err = svc.KeyExistsForAlg(ctx, rtIssuer, "ES256")
	require.NoError(t, err)
	assert.False(t, exists, "an RSA key is not an ES256 key")

	_, ecKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, "ES256", "sig", "")
	require.NoError(t, err)
	_, _, err = svc.SetKeyStatus(ctx, rtIssuer, ecKid, interfaces.KeyStatusSuspended)
	require.NoError(t, err)
	exists, err = svc.KeyExistsForAlg(ctx, rtIssuer, "ES256")
	require.NoError(t, err)
	assert.True(t, exists, "a suspended key still exists")

	_, _, err = svc.SetKeyStatus(ctx, rtIssuer, ecKid, interfaces.KeyStatusRevoked)
	require.NoError(t, err)
	exists, err = svc.KeyExistsForAlg(ctx, rtIssuer, "ES256")
	require.NoError(t, err)
	assert.False(t, exists, "a revoked key does not block a new one")
}

func TestRotateKey_ActsOnOneAlgorithm(t *testing.T) {
	for _, alg := range []string{"ES256", mldsa.Alg} {
		t.Run(alg, func(t *testing.T) {
			ctx := context.Background()
			svc, dao := newMLDSATestService(t)
			_, ecKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, "ES256", "sig", "")
			require.NoError(t, err)
			_, pqKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, mldsa.Alg, "sig", "")
			require.NoError(t, err)
			before := kidsByAlg(t, dao, rtIssuer)

			key, newKid, err := svc.RotateKey(ctx, rtIssuer, alg, "")
			require.NoError(t, err)

			after := kidsByAlg(t, dao, rtIssuer)
			previous := map[string]string{"ES256": ecKid, mldsa.Alg: pqKid}[alg]
			assert.ElementsMatch(t, []string{previous, newKid}, after[alg], "rotate adds a key and keeps the previous one")
			for _, other := range []string{"RS256", "ES256", mldsa.Alg} {
				if other != alg {
					assert.Equal(t, before[other], after[other], "%s keys are untouched", other)
				}
			}

			summary, err := dao.KeySummary(ctx, rtIssuer)
			require.NoError(t, err)
			for _, st := range summary.KeyStates {
				if st.Kid == previous {
					assert.Equal(t, interfaces.KeyStatusActive, st.Status, "the previous key stays active")
				}
			}
			rec, err := dao.FindByKid(ctx, newKid)
			require.NoError(t, err)
			stored, _, err := parseSigningRec(rec)
			require.NoError(t, err)
			assert.True(t, stored.(interface{ Equal(crypto.PrivateKey) bool }).Equal(key), "the stored key is the one rotate returned")
		})
	}
}

func TestRotateKey_EmptyAlgRotatesRSA(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)
	_, ecKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, "ES256", "sig", "")
	require.NoError(t, err)

	key, newKid, err := svc.RotateKey(ctx, rtIssuer, "", "")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, key)

	byAlg := kidsByAlg(t, dao, rtIssuer)
	assert.ElementsMatch(t, []string{rtIssuer, newKid}, byAlg["RS256"])
	assert.Equal(t, []string{ecKid}, byAlg["ES256"])
}

func TestRotateKey_RejectsAnUnsupportedAlg(t *testing.T) {
	svc, _ := newMLDSATestService(t)
	_, _, err := svc.RotateKey(context.Background(), rtIssuer, "HS256", "")
	assert.True(t, errors.Is(err, ErrUnsupportedKeyAlg), "%v", err)
}

func TestDeleteKeysByNameAndAlg_LeavesOtherAlgorithms(t *testing.T) {
	ctx := context.Background()
	svc, dao := newMLDSATestService(t)
	_, _, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, "ES256", "sig", "")
	require.NoError(t, err)
	_, _, err = svc.RotateKey(ctx, rtIssuer, "ES256", "")
	require.NoError(t, err)
	_, pqKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, mldsa.Alg, "sig", "")
	require.NoError(t, err)

	require.NoError(t, svc.DeleteKeysByNameAndAlg(ctx, rtIssuer, "ES256"))
	byAlg := kidsByAlg(t, dao, rtIssuer)
	assert.Empty(t, byAlg["ES256"], "every ES256 key is deleted")
	assert.Equal(t, []string{rtIssuer}, byAlg["RS256"])
	assert.Equal(t, []string{pqKid}, byAlg[mldsa.Alg])

	require.NoError(t, svc.DeleteKeysByNameAndAlg(ctx, rtIssuer, ""))
	byAlg = kidsByAlg(t, dao, rtIssuer)
	assert.Empty(t, byAlg["RS256"], "an empty alg deletes the RSA keys")
	assert.Equal(t, []string{pqKid}, byAlg[mldsa.Alg])

	assert.True(t, errors.Is(svc.DeleteKeysByNameAndAlg(ctx, rtIssuer, "ES256"), interfaces.ErrKeyNotFound),
		"deleting keys that are not there is ErrKeyNotFound, as DeleteKeysByName")
	assert.True(t, errors.Is(svc.DeleteKeysByNameAndAlg(ctx, rtIssuer, "HS256"), ErrUnsupportedKeyAlg))
}

// TestNonRSAKeyOnTheTokenIssuerLeavesAuthTokenSigningAlone: auth tokens are
// signed RS256, so an ES256 or ML-DSA key created or rotated under the token
// issuer's name must not become the auth signing key.
func TestNonRSAKeyOnTheTokenIssuerLeavesAuthTokenSigningAlone(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t) // token issuer "DEFAULT"
	auth := svc.GetAuthIssuer()
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"p"}}
	issue := func() error {
		_, err := auth.IssueStreamClientToken(client, "p", true, "")
		return err
	}
	require.NoError(t, issue())

	_, _, err := svc.CreateKeyPairForAlg(ctx, "DEFAULT", "ES256", "sig", "")
	require.NoError(t, err)
	assert.NoError(t, issue(), "an ES256 key on the token issuer must not replace the RS256 auth key")

	_, _, err = svc.RotateKey(ctx, "DEFAULT", mldsa.Alg, "")
	require.NoError(t, err)
	assert.NoError(t, issue(), "an ML-DSA rotation on the token issuer must not replace the RS256 auth key")

	tok, err := auth.IssueStreamClientToken(client, "p", true, "")
	require.NoError(t, err)
	_, err = auth.ParseAuthToken(tok)
	assert.NoError(t, err, "a freshly issued auth token still verifies")
}
