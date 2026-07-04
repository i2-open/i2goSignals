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
