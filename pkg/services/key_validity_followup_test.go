package services

// Follow-ups to signing-key validity periods (i2goSignals#318, PR #320 review).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
)

// selfSignedCert certifies key for [notBefore, notAfter).
func selfSignedCert(t *testing.T, key *rsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "validity"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// The expiry WARN names only the key signing selection picks for an issuer and
// algorithm: an older key inside the window that a newer one has replaced is
// never used again, so warning about it would only be noise.
func TestKeyValidity_ExpiryWarningNamesOnlyTheSelectedSigningKey(t *testing.T) {
	svc, _ := validityKeyService(t)
	ctx := context.Background()
	seedSigningRec(t, svc, validityIssuer, "ES256", "k-old", validityT0.Add(-time.Hour), time.Time{}, validityT0.AddDate(0, 0, 10))
	seedSigningRec(t, svc, validityIssuer, "ES256", "k-new", validityT0, time.Time{}, validityT0.AddDate(0, 0, 20))
	seedSigningRec(t, svc, validityIssuer, "RS256", "k-rsa", validityT0, time.Time{}, validityT0.AddDate(0, 0, 5))

	logs := captureLogs(t)
	svc.WarnExpiringSigningKeys(ctx)
	out := logs.String()
	assert.Contains(t, out, "kid=k-new")
	assert.Contains(t, out, "kid=k-rsa", "each algorithm's selected key is warned about")
	assert.NotContains(t, out, "kid=k-old", "a replaced key is not the signing key")
}

// The once-a-day memory of warned keys forgets a key once it is no longer the
// warned signing key, so the map does not grow with every key ever rotated.
func TestKeyValidity_ExpiryWarningForgetsKeysNoLongerWarnedAbout(t *testing.T) {
	svc, clk := validityKeyService(t)
	ctx := context.Background()
	seedSigningRec(t, svc, validityIssuer, "ES256", "k1", validityT0, time.Time{}, validityT0.AddDate(0, 0, 10))
	svc.WarnExpiringSigningKeys(ctx)
	svc.validityMu.Lock()
	_, warned := svc.expiryWarnedAt["k1"]
	svc.validityMu.Unlock()
	require.True(t, warned)

	require.NoError(t, svc.keyDAO.DeleteByKid(ctx, "k1"))
	clk.Set(validityT0.Add(expiryScanEvery))
	svc.WarnExpiringSigningKeys(ctx)
	svc.validityMu.Lock()
	defer svc.validityMu.Unlock()
	assert.Empty(t, svc.expiryWarnedAt)
}

// expiryFailingKeyDAO fails the reads the expiry check makes.
type expiryFailingKeyDAO struct {
	interfaces.KeyDAO
	listErr, findErr error
}

func (d expiryFailingKeyDAO) ListKeyNames(ctx context.Context) ([]string, error) {
	if d.listErr != nil {
		return nil, d.listErr
	}
	return d.KeyDAO.ListKeyNames(ctx)
}

func (d expiryFailingKeyDAO) FindByKeyName(ctx context.Context, keyName string) ([]*interfaces.JwkKeyRec, error) {
	if d.findErr != nil {
		return nil, d.findErr
	}
	return d.KeyDAO.FindByKeyName(ctx, keyName)
}

// A key store that cannot answer the expiry check is a WARN with the error, not
// a silent skip: the check is how an operator learns a key is about to expire.
func TestKeyValidity_ExpiryCheckWarnsWhenTheKeyStoreFails(t *testing.T) {
	ctx := context.Background()
	for name, dao := range map[string]expiryFailingKeyDAO{
		"list key names": {listErr: errors.New("list boom")},
		"find by name":   {findErr: errors.New("find boom")},
	} {
		t.Run(name, func(t *testing.T) {
			inner := memory.NewKeyDAO()
			dao.KeyDAO = inner
			svc := NewKeyService(dao, "DEFAULT", nil, nil)
			svc.SetClock(newTestClock(validityT0).Now)
			seedSigningRec(t, &KeyService{keyDAO: inner}, validityIssuer, "ES256", "k1", validityT0, time.Time{}, validityT0.AddDate(0, 0, 10))

			logs := captureLogs(t)
			svc.WarnExpiringSigningKeys(ctx)
			out := logs.String()
			assert.Contains(t, out, "level=WARN")
			assert.Contains(t, out, "boom")
		})
	}
}

// The token issuer's key signs the server's own admin tokens, so it is exempt
// from validity like the startup keys: uploaded with a certificate, it keeps
// signing after the certificate's NotAfter.
func TestKeyValidity_TokenIssuerUploadWithCertificateSignsAfterNotAfter(t *testing.T) {
	svc, clk := validityKeyService(t)
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := selfSignedCert(t, key, validityT0.Add(-time.Hour), validityT0.AddDate(0, 0, 10))

	kid, err := svc.StoreUploadedSigningKey(ctx, "DEFAULT", "sig", "", key, cert, "")
	require.NoError(t, err)
	assert.True(t, svc.UploadedKeySignsNow("DEFAULT", cert))

	clk.Set(validityT0.AddDate(0, 0, 11))
	_, gotKid, err := svc.GetSigner(ctx, "DEFAULT", "RS256")
	require.NoError(t, err, "the token issuer still signs after the certificate expired")
	assert.Equal(t, kid, gotKid)
	assert.True(t, svc.UploadedKeySignsNow("DEFAULT", cert), "a replace of the token issuer key is a signing key")

	svc.refreshTokenIssuerKey(ctx)
	assert.NotNil(t, svc.tokenKey, "admin token signing keeps its key")
}

// Whether an uploaded key signs is judged at the KeyService clock, the same
// clock signing selection uses, not the wall clock.
func TestKeyValidity_UploadedKeySignsNowUsesTheServiceClock(t *testing.T) {
	svc, clk := validityKeyService(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	future := time.Now().AddDate(1, 0, 0)
	cert := selfSignedCert(t, key, future, future.AddDate(0, 0, 30))

	assert.False(t, svc.UploadedKeySignsNow(validityIssuer, cert))
	clk.Set(future.Add(time.Hour))
	assert.True(t, svc.UploadedKeySignsNow(validityIssuer, cert), "valid at the service clock")
	assert.True(t, svc.UploadedKeySignsNow(validityIssuer, nil), "a cert-less upload is valid from now")
}
