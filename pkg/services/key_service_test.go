package services

import (
	"context"
	"errors"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/stretchr/testify/suite"
)

// failingKeyDAO wraps a real in-memory KeyDAO but makes FindByKeyName return an
// error, simulating a transient MongoDB failure during JWKS loading.
type failingKeyDAO struct {
	interfaces.KeyDAO
}

func (f *failingKeyDAO) FindByKeyName(_ context.Context, _ string) ([]*interfaces.JwkKeyRec, error) {
	return nil, errors.New("simulated MongoDB error during FindByKeyName")
}

// failingFindLatestKeyDAO wraps a real in-memory KeyDAO but makes
// FindLatestByKeyName return a transient (non-ErrKeyNotFound) error, simulating
// a brief MongoDB outage during the key-load phase of InitializeTokenKey.
type failingFindLatestKeyDAO struct {
	interfaces.KeyDAO
}

func (f *failingFindLatestKeyDAO) FindLatestByKeyName(_ context.Context, _ string) (*interfaces.JwkKeyRec, error) {
	return nil, errors.New("simulated transient MongoDB error during FindLatestByKeyName")
}

// ---- test suite ----

type KeyServiceTestSuite struct {
	suite.Suite
}

func (s *KeyServiceTestSuite) newService(tokenIssuer string) (*KeyService, interfaces.KeyDAO) {
	dao := memory.NewKeyDAO()
	return NewKeyService(dao, tokenIssuer, nil, nil), dao
}

// TestInitializeTokenKey_FreshStart verifies that on an empty DB the service
// creates a key and leaves authIssuer fully populated.
func (s *KeyServiceTestSuite) TestInitializeTokenKey_FreshStart() {
	svc, _ := s.newService("DEFAULT")
	err := svc.InitializeTokenKey(context.Background(), "DEFAULT")
	s.NoError(err)
	s.NotNil(svc.authIssuer.PublicKey, "PublicKey must be set after fresh init")
	s.NotNil(svc.authIssuer.PrivateKey, "PrivateKey must be set after fresh init")
	s.Equal("DEFAULT", svc.authIssuer.TokenKid)
	s.Equal("DEFAULT", svc.authIssuer.TokenIssuer)
}

// TestInitializeTokenKey_ExistingKey verifies that re-initialising with the
// same DAO (server reconnect) loads the persisted key correctly.
func (s *KeyServiceTestSuite) TestInitializeTokenKey_ExistingKey() {
	ctx := context.Background()
	_, dao := s.newService("DEFAULT")

	// First init — creates the key
	svc1 := NewKeyService(dao, "DEFAULT", nil, nil)
	s.Require().NoError(svc1.InitializeTokenKey(ctx, "DEFAULT"))

	// Second init — loads the existing key (simulate MongoDB reconnect)
	svc2 := NewKeyService(dao, "DEFAULT", nil, nil)
	s.Require().NoError(svc2.InitializeTokenKey(ctx, "DEFAULT"))
	s.NotNil(svc2.authIssuer.PublicKey)
	s.NotNil(svc2.authIssuer.PrivateKey)
}

// TestInitializeTokenKey_JWKSLoadFailure_ReturnsError verifies that when
// getInternalPublicJWKS fails (MongoDB unavailable), InitializeTokenKey
// returns an error rather than leaving authIssuer.PublicKey nil and silently
// succeeding — which would cause every subsequent token validation to fail.
func (s *KeyServiceTestSuite) TestInitializeTokenKey_JWKSLoadFailure_ReturnsError() {
	ctx := context.Background()

	// Seed a key into the in-memory store so the "load existing" path is taken.
	inner := memory.NewKeyDAO()
	seed := NewKeyService(inner, "DEFAULT", nil, nil)
	s.Require().NoError(seed.InitializeTokenKey(ctx, "DEFAULT"))

	// Wrap with a DAO that fails FindByKeyName (prevents JWKS from being built).
	dao := &failingKeyDAO{KeyDAO: inner}
	svc := NewKeyService(dao, "DEFAULT", nil, nil)

	err := svc.InitializeTokenKey(ctx, "DEFAULT")
	s.Error(err, "InitializeTokenKey must return error when JWKS cannot be built")
	s.Nil(svc.authIssuer.PublicKey, "PublicKey must not be set when JWKS load failed")
}

// TestInitializeTokenKey_TransientDBError_ReturnsErrorWithoutCreatingKey verifies
// that when FindLatestByKeyName returns a transient (non-ErrKeyNotFound) error,
// InitializeTokenKey propagates the error and does NOT create a new key record.
// This prevents a duplicate kid=DEFAULT from being inserted into MongoDB during
// SPIFFE cert rotation, which would cause non-deterministic JWKS construction
// and signature-mismatch 503 errors on subsequent token validations.
func (s *KeyServiceTestSuite) TestInitializeTokenKey_TransientDBError_ReturnsErrorWithoutCreatingKey() {
	ctx := context.Background()

	// Seed a key so the DB is non-empty — this simulates a server that has
	// already run at least once and has a DEFAULT key in MongoDB.
	inner := memory.NewKeyDAO()
	seed := NewKeyService(inner, "DEFAULT", nil, nil)
	s.Require().NoError(seed.InitializeTokenKey(ctx, "DEFAULT"))

	// Confirm exactly one key exists before the test.
	beforeKeys, err := inner.FindByKeyName(ctx, "DEFAULT")
	s.Require().NoError(err)
	s.Require().Len(beforeKeys, 1, "setup: should be exactly one DEFAULT key before test")

	// Inject a DAO whose FindLatestByKeyName returns a transient error.
	// This simulates a brief MongoDB outage mid-reconnect.
	dao := &failingFindLatestKeyDAO{KeyDAO: inner}
	svc := NewKeyService(dao, "DEFAULT", nil, nil)

	initErr := svc.InitializeTokenKey(ctx, "DEFAULT")
	s.Error(initErr, "InitializeTokenKey must return error on transient DB failure")

	// Crucially, no new key must have been inserted — we must still have exactly
	// one DEFAULT record, not two.
	afterKeys, err := inner.FindByKeyName(ctx, "DEFAULT")
	s.Require().NoError(err)
	s.Len(afterKeys, 1, "no new key must be created when InitializeTokenKey fails with a transient error")
}

// TestCreateKeyPair_NonTokenIssuerDoesNotAffectPublicKey verifies that creating
// a key for a name other than tokenIssuer leaves the auth issuer untouched.
func (s *KeyServiceTestSuite) TestCreateKeyPair_NonTokenIssuerDoesNotAffectPublicKey() {
	svc, _ := s.newService("DEFAULT")
	ctx := context.Background()
	s.Require().NoError(svc.InitializeTokenKey(ctx, "DEFAULT"))

	origPubKey := svc.authIssuer.PublicKey

	_, err := svc.CreateKeyPair(ctx, "cluster.scim.example.com", "sig", "")
	s.NoError(err)
	s.Equal(origPubKey, svc.authIssuer.PublicKey, "PublicKey must not change when creating a non-token-issuer key")
}

// TestCreateKeyPair_JWKSLoadFailure_PreservesExistingPublicKey verifies that if
// getInternalPublicJWKS returns nil (transient DB error) during CreateKeyPair,
// the previously valid PublicKey is preserved rather than cleared.
func (s *KeyServiceTestSuite) TestCreateKeyPair_JWKSLoadFailure_PreservesExistingPublicKey() {
	ctx := context.Background()
	inner := memory.NewKeyDAO()

	svc := NewKeyService(inner, "DEFAULT", nil, nil)
	s.Require().NoError(svc.InitializeTokenKey(ctx, "DEFAULT"))

	existingPubKey := svc.authIssuer.PublicKey
	s.Require().NotNil(existingPubKey)

	// Inject the failing DAO so subsequent FindByKeyName calls fail.
	svc.keyDAO = &failingKeyDAO{KeyDAO: inner}

	// CreateKeyPair: Insert succeeds but JWKS load fails.
	// The existing PublicKey must be preserved.
	_, err := svc.CreateKeyPair(ctx, "DEFAULT", "sig", "")
	s.NoError(err, "CreateKeyPair should not error just because JWKS load fails")
	s.Equal(existingPubKey, svc.authIssuer.PublicKey, "Existing PublicKey must be preserved when JWKS load fails")
}

// TestRotateKey_UpdatesPublicKey verifies that after a rotation the authIssuer
// has a non-nil PublicKey and the new kid is recorded.
func (s *KeyServiceTestSuite) TestRotateKey_UpdatesPublicKey() {
	svc, _ := s.newService("DEFAULT")
	ctx := context.Background()
	s.Require().NoError(svc.InitializeTokenKey(ctx, "DEFAULT"))

	_, newKid, err := svc.RotateKey(ctx, "DEFAULT", "")
	s.NoError(err)
	s.NotNil(svc.authIssuer.PublicKey, "PublicKey must remain non-nil after rotation")
	s.Equal(newKid, svc.authIssuer.TokenKid, "TokenKid must be updated to the new kid after rotation")
}

// TestIssuedTokenValidatesAfterInit is an end-to-end test that mirrors the
// scim-container registration scenario: the server initialises, issues an IAT,
// and that IAT must validate against the server's own public key.
func (s *KeyServiceTestSuite) TestIssuedTokenValidatesAfterInit() {
	svc, _ := s.newService("DEFAULT")
	ctx := context.Background()
	s.Require().NoError(svc.InitializeTokenKey(ctx, "DEFAULT"))

	issuer := svc.GetAuthIssuer()

	tokenStr, err := issuer.IssueProjectIat(nil)
	s.Require().NoError(err)
	s.NotEmpty(tokenStr)

	claims, err := issuer.ParseAuthTokenVerbose(tokenStr, true)
	s.NoError(err, "IAT issued by the server must validate against its own public key")
	s.Require().NotNil(claims)
	s.Contains(claims.Roles, authSupport.ScopeRegister)
}

// TestIssuedTokenValidatesAfterReconnect verifies that a token issued before a
// MongoDB reconnect still validates after the key is reloaded from the database.
// This is the regression scenario for the SPIFFE-rotation 503 bug.
func (s *KeyServiceTestSuite) TestIssuedTokenValidatesAfterReconnect() {
	ctx := context.Background()
	_, dao := s.newService("DEFAULT")

	// First service instance — creates the key and issues a token.
	svc1 := NewKeyService(dao, "DEFAULT", nil, nil)
	s.Require().NoError(svc1.InitializeTokenKey(ctx, "DEFAULT"))
	tokenStr, err := svc1.GetAuthIssuer().IssueProjectIat(nil)
	s.Require().NoError(err)

	// Second service instance — simulates reconnect (loads existing key from DB).
	svc2 := NewKeyService(dao, "DEFAULT", nil, nil)
	s.Require().NoError(svc2.InitializeTokenKey(ctx, "DEFAULT"))

	// Token issued before reconnect must still validate.
	claims, err := svc2.GetAuthIssuer().ParseAuthTokenVerbose(tokenStr, true)
	s.NoError(err, "Token issued before reconnect must validate after reloading the key from DB")
	s.NotNil(claims)
}

// TestIssuedTokenValidatesAfterRotation verifies that tokens issued before a
// key rotation continue to validate — getInternalPublicJWKS includes all kids
// for the keyName, so old tokens remain valid during the grace period.
func (s *KeyServiceTestSuite) TestIssuedTokenValidatesAfterRotation() {
	svc, _ := s.newService("DEFAULT")
	ctx := context.Background()
	s.Require().NoError(svc.InitializeTokenKey(ctx, "DEFAULT"))

	issuer := svc.GetAuthIssuer()

	// Issue a token with the initial (pre-rotation) key.
	oldToken, err := issuer.IssueProjectIat(nil)
	s.Require().NoError(err)

	// Rotate the key.
	_, _, err = svc.RotateKey(ctx, "DEFAULT", "")
	s.Require().NoError(err)

	// The pre-rotation token must still validate because the JWKS contains
	// all keys for the keyName (old + new).
	claims, err := issuer.ParseAuthTokenVerbose(oldToken, true)
	s.NoError(err, "Token issued before rotation must still validate after rotation")
	s.NotNil(claims)

	// A newly issued token (with the rotated key) must also validate.
	newToken, err := issuer.IssueProjectIat(nil)
	s.Require().NoError(err)
	claims, err = issuer.ParseAuthTokenVerbose(newToken, true)
	s.NoError(err, "Token issued after rotation must validate")
	s.NotNil(claims)
}

func TestKeyServiceSuite(t *testing.T) {
	suite.Run(t, new(KeyServiceTestSuite))
}
