package services

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/stretchr/testify/suite"
)

type KeyStatusSuite struct {
	suite.Suite
}

func TestKeyStatusSuite(t *testing.T) {
	suite.Run(t, new(KeyStatusSuite))
}

func (s *KeyStatusSuite) svc() *KeyService {
	svc := NewKeyService(memory.NewKeyDAO(), "DEFAULT", nil, nil)
	s.Require().NoError(svc.InitializeTokenKey(context.Background(), "DEFAULT"))
	return svc
}

// publicKids returns the kids present in the public JWKS for keyName.
func (s *KeyStatusSuite) publicKids(svc *KeyService, keyName string) []string {
	raw := svc.GetPublicJWKS(context.Background(), keyName)
	s.Require().NotNil(raw)
	var parsed struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	s.Require().NoError(json.Unmarshal(*raw, &parsed))
	var kids []string
	for _, k := range parsed.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

// TestSuspendStopsSigningButStaysPublished: a suspended key no longer signs but
// remains published in both the public and auth JWKS.
func (s *KeyStatusSuite) TestSuspendStopsSigningButStaysPublished() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "")
	s.Require().NoError(err)

	summary, warn, err := svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusSuspended)
	s.Require().NoError(err)
	s.NotEmpty(warn, "suspending the last active key must warn")
	s.Require().Len(summary.KeyStates, 1)
	s.Equal(interfaces.KeyStatusSuspended, summary.KeyStates[0].Status)

	_, _, err = svc.GetPrivateKeyWithKeyname(ctx, "iss")
	s.ErrorIs(err, interfaces.ErrKeyNotFound, "suspended key must not be a signing candidate")

	s.Contains(s.publicKids(svc, "iss"), "iss", "suspended key stays in public JWKS")
	auth := svc.getInternalPublicJWKS(ctx, "iss")
	s.Require().NotNil(auth)
	s.Contains(auth.KIDs(), "iss", "suspended key stays in auth JWKS")
}

// TestIssuancePicksLatestActive: with a rotated key, suspending the newest kid
// makes issuance fall back to the older active kid (no auto-rotate).
func (s *KeyStatusSuite) TestIssuancePicksLatestActive() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "") // kid "iss"
	s.Require().NoError(err)
	_, newKid, err := svc.RotateKey(ctx, "iss", "") // newest kid
	s.Require().NoError(err)

	// Suspending the newest kid should leave the original active.
	_, warn, err := svc.SetKeyStatus(ctx, "iss", newKid, interfaces.KeyStatusSuspended)
	s.Require().NoError(err)
	s.Empty(warn, "an active key still remains, so no warning")

	_, kid, err := svc.GetPrivateKeyWithKeyname(ctx, "iss")
	s.Require().NoError(err)
	s.Equal("iss", kid, "issuance falls back to the older active kid")
}

// TestRevokeExcludesFromJWKSButRetainsRecord: a revoked key is absent from both
// JWKS yet its DB record survives.
func (s *KeyStatusSuite) TestRevokeExcludesFromJWKSButRetainsRecord() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "")
	s.Require().NoError(err)

	_, _, err = svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusRevoked)
	s.Require().NoError(err)

	s.NotContains(s.publicKids(svc, "iss"), "iss", "revoked key excluded from public JWKS")
	auth := svc.getInternalPublicJWKS(ctx, "iss")
	if auth != nil {
		s.NotContains(auth.KIDs(), "iss", "revoked key excluded from auth JWKS")
	}

	rec, err := svc.keyDAO.FindByKid(ctx, "iss")
	s.Require().NoError(err, "revoked record must survive")
	s.NotEmpty(rec.KeyBytes, "key material retained")
	s.True(rec.IsRevoked())
}

// TestReactivateSuspendedRestoresSigning: clearing suspension makes the key a
// signing candidate again.
func (s *KeyStatusSuite) TestReactivateSuspendedRestoresSigning() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "")
	s.Require().NoError(err)

	_, _, err = svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusSuspended)
	s.Require().NoError(err)
	_, _, err = svc.GetPrivateKeyWithKeyname(ctx, "iss")
	s.Require().ErrorIs(err, interfaces.ErrKeyNotFound)

	_, _, err = svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusActive)
	s.Require().NoError(err)
	_, kid, err := svc.GetPrivateKeyWithKeyname(ctx, "iss")
	s.Require().NoError(err)
	s.Equal("iss", kid)
}

// TestReactivateRevokedIsTerminal: moving away from revoked is refused.
func (s *KeyStatusSuite) TestReactivateRevokedIsTerminal() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "")
	s.Require().NoError(err)
	_, _, err = svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusRevoked)
	s.Require().NoError(err)

	_, _, err = svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusActive)
	s.ErrorIs(err, ErrKeyStatusTerminal)
	_, _, err = svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusSuspended)
	s.ErrorIs(err, ErrKeyStatusTerminal)

	// Re-asserting revoked is idempotent.
	_, _, err = svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusRevoked)
	s.NoError(err)
}

// TestKidMustBelongToKeyName: a kid from another keyName is rejected.
func (s *KeyStatusSuite) TestKidMustBelongToKeyName() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "")
	s.Require().NoError(err)
	_, err = svc.CreateKeyPair(ctx, "other", "sig", "")
	s.Require().NoError(err)

	_, _, err = svc.SetKeyStatus(ctx, "iss", "other", interfaces.KeyStatusSuspended)
	s.ErrorIs(err, interfaces.ErrKeyNotFound, "a kid from a different keyName must be rejected")
}

// TestInvalidStatusRejected: an unknown status string is refused.
func (s *KeyStatusSuite) TestInvalidStatusRejected() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "")
	s.Require().NoError(err)
	_, _, err = svc.SetKeyStatus(ctx, "iss", "", "bogus")
	s.ErrorIs(err, ErrKeyStatusInvalid)
}

// TestPartialSuspendKeepsActiveInPublicJWKS confirms both suspended and active
// kids remain in the public JWKS (only issuance is filtered).
func (s *KeyStatusSuite) TestPartialSuspendKeepsActiveInPublicJWKS() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "")
	s.Require().NoError(err)
	_, newKid, err := svc.RotateKey(ctx, "iss", "")
	s.Require().NoError(err)

	_, _, err = svc.SetKeyStatus(ctx, "iss", newKid, interfaces.KeyStatusSuspended)
	s.Require().NoError(err)

	kids := s.publicKids(svc, "iss")
	s.True(slices.Contains(kids, "iss"))
	s.True(slices.Contains(kids, newKid), "suspended kid still published")
}

// TestKeyNameWideSuspendSkipsRevokedSibling: a keyName-wide suspend must apply to
// the remaining active kid rather than being blocked by an already-revoked
// sibling (revoked stays terminal). Regression for the terminal-guard over-reach.
func (s *KeyStatusSuite) TestKeyNameWideSuspendSkipsRevokedSibling() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "") // kid "iss"
	s.Require().NoError(err)
	_, newKid, err := svc.RotateKey(ctx, "iss", "") // second active kid
	s.Require().NoError(err)

	// Revoke only the older kid.
	_, _, err = svc.SetKeyStatus(ctx, "iss", "iss", interfaces.KeyStatusRevoked)
	s.Require().NoError(err)

	// keyName-wide suspend: not blocked by the revoked sibling.
	summary, _, err := svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusSuspended)
	s.Require().NoError(err)

	byKid := map[string]string{}
	for _, ks := range summary.KeyStates {
		byKid[ks.Kid] = ks.Status
	}
	s.Equal(interfaces.KeyStatusRevoked, byKid["iss"], "revoked sibling stays terminal")
	s.Equal(interfaces.KeyStatusSuspended, byKid[newKid], "active kid gets suspended")
}

// TestEnsureSigningKeyDoesNotRemintSuspended: EnsureSigningKey must respect a
// deliberate suspend/revoke and NOT silently mint a fresh active key over it.
func (s *KeyStatusSuite) TestEnsureSigningKeyDoesNotRemintSuspended() {
	ctx := context.Background()
	svc := s.svc()
	_, err := svc.CreateKeyPair(ctx, "iss", "sig", "")
	s.Require().NoError(err)
	_, _, err = svc.SetKeyStatus(ctx, "iss", "", interfaces.KeyStatusSuspended)
	s.Require().NoError(err)

	created, err := svc.EnsureSigningKey(ctx, "iss", "")
	s.Require().NoError(err)
	s.False(created, "must not mint a fresh key over a deliberately suspended one")
	_, _, err = svc.GetPrivateKeyWithKeyname(ctx, "iss")
	s.ErrorIs(err, interfaces.ErrKeyNotFound, "suspend stays respected")
}

// TestEnsureSigningKeyCreatesWhenAbsent: the genuinely-absent case still mints.
func (s *KeyStatusSuite) TestEnsureSigningKeyCreatesWhenAbsent() {
	ctx := context.Background()
	svc := s.svc()
	created, err := svc.EnsureSigningKey(ctx, "brand-new", "")
	s.Require().NoError(err)
	s.True(created)
	_, _, err = svc.GetPrivateKeyWithKeyname(ctx, "brand-new")
	s.Require().NoError(err)
}

// TestRevokeTokenIssuerDropsFromAuthJWKSAndClearsSigning: revoking the token
// issuer's only key must drop the revoked kid from the verification JWKS and
// clear the cached signing key so the next issuance fails loudly.
func (s *KeyStatusSuite) TestRevokeTokenIssuerDropsFromAuthJWKSAndClearsSigning() {
	ctx := context.Background()
	svc := s.svc() // token issuer "DEFAULT", kid "DEFAULT"
	s.Require().Contains(svc.GetAuthValidatorPubKey().KIDs(), "DEFAULT")
	s.Require().NotNil(svc.tokenKey)

	_, _, err := svc.SetKeyStatus(ctx, "DEFAULT", "", interfaces.KeyStatusRevoked)
	s.Require().NoError(err)

	s.NotContains(svc.GetAuthValidatorPubKey().KIDs(), "DEFAULT",
		"revoked token-issuer kid must stop verifying")
	s.Nil(svc.tokenKey, "signing key cleared, not re-registered under the revoked kid")
}

// TestRevokeTokenIssuerActiveKidKeepsSuspendedSibling: when the active token kid
// is revoked but a suspended sibling remains, the verification JWKS drops the
// revoked kid, keeps the suspended one, and the signing key is not re-registered
// to the revoked kid.
func (s *KeyStatusSuite) TestRevokeTokenIssuerActiveKidKeepsSuspendedSibling() {
	ctx := context.Background()
	svc := s.svc()                                      // kid "DEFAULT" active
	_, newKid, err := svc.RotateKey(ctx, "DEFAULT", "") // newKid becomes active signer
	s.Require().NoError(err)
	_, _, err = svc.SetKeyStatus(ctx, "DEFAULT", "DEFAULT", interfaces.KeyStatusSuspended)
	s.Require().NoError(err)
	_, _, err = svc.SetKeyStatus(ctx, "DEFAULT", newKid, interfaces.KeyStatusRevoked)
	s.Require().NoError(err)

	kids := svc.GetAuthValidatorPubKey().KIDs()
	s.NotContains(kids, newKid, "revoked kid dropped from verification")
	s.Contains(kids, "DEFAULT", "suspended sibling stays published for verification")
	s.Nil(svc.tokenKey, "no active signing key → signing cleared")
}
