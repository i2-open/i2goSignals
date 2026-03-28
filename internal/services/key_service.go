package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var ksLog = logger.Sub("KEY_SERVICE")

type KeyService struct {
	keyDAO      interfaces.KeyDAO
	tokenIssuer string
	tokenKid    string
	tokenKey    *rsa.PrivateKey
	tokenPubKey *keyfunc.JWKS
	authIssuer  *authUtil.AuthIssuer
}

func NewKeyService(keyDAO interfaces.KeyDAO, tokenIssuer string) *KeyService {
	return &KeyService{
		keyDAO:      keyDAO,
		tokenIssuer: tokenIssuer,
		authIssuer: &authUtil.AuthIssuer{
			TokenIssuer: tokenIssuer,
		},
	}
}

// InitializeTokenKey loads or creates the token signing key for authentication
func (s *KeyService) InitializeTokenKey(ctx context.Context, defaultIssuer string) error {
	// Try to load existing key
	key, kid, err := s.GetPrivateKeyWithKid(ctx, s.tokenIssuer)
	if err == nil && key != nil {
		s.tokenKey = key
		s.tokenKid = kid
		s.tokenPubKey = s.getInternalPublicJWKS(ctx, s.tokenIssuer)
		s.authIssuer.UpdateTokenKey(s.tokenIssuer, s.tokenKid, s.tokenKey, s.tokenPubKey)
		return nil
	}

	// Create new key
	s.tokenKey, err = s.CreateKeyPair(ctx, s.tokenIssuer, "sig", "")
	if err != nil {
		return fmt.Errorf("failed to create token key: %v", err)
	}
	s.tokenKid = s.tokenIssuer
	s.tokenPubKey = s.getInternalPublicJWKS(ctx, s.tokenIssuer)
	s.authIssuer.UpdateTokenKey(s.tokenIssuer, s.tokenKid, s.tokenKey, s.tokenPubKey)

	if defaultIssuer != s.tokenIssuer {
		// Also create default issuer signing key if different
		_, err = s.CreateKeyPair(ctx, defaultIssuer, "sig", "")
		if err != nil {
			ksLog.Error("Error creating default issuer key", "error", err)
		}
	}
	s.tokenPubKey = s.getInternalPublicJWKS(ctx, s.tokenIssuer)
	return nil
}

// CreateKeyPair generates a new RSA key pair identified by keyName with the given use ("sig" or "enc").
func (s *KeyService) CreateKeyPair(ctx context.Context, keyName string, use string, projectId string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		ksLog.Error("Error generating key pair", "error", err)
		return nil, err
	}

	err = s.storeKeyPair(ctx, keyName, keyName, use, privateKey, projectId)
	if err != nil {
		ksLog.Error("Error storing key pair", "error", err)
		return nil, err
	}

	if keyName == s.tokenIssuer {
		s.tokenKey = privateKey
		s.tokenKid = keyName
		s.tokenPubKey = s.getInternalPublicJWKS(ctx, keyName)
		s.authIssuer.UpdateTokenKey(keyName, keyName, privateKey, s.tokenPubKey)
	}

	return privateKey, nil
}

// RotateKey generates a new key pair for keyName with a unique kid.
func (s *KeyService) RotateKey(ctx context.Context, keyName string, projectId string) (*rsa.PrivateKey, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	kid := fmt.Sprintf("%s-%s", keyName, bson.NewObjectID().Hex())

	// Preserve the use from the existing key if available
	use := "sig"
	if existing, err2 := s.keyDAO.FindLatestByKeyName(ctx, keyName); err2 == nil {
		use = existing.Use
	}

	err = s.storeKeyPair(ctx, keyName, kid, use, privateKey, projectId)
	if err != nil {
		return nil, "", err
	}

	if keyName == s.tokenIssuer {
		s.tokenKey = privateKey
		s.tokenKid = kid
		s.tokenPubKey = s.getInternalPublicJWKS(ctx, keyName)
		s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
	}

	return privateKey, kid, nil
}

func (s *KeyService) storeKeyPair(ctx context.Context, keyName string, kid string, use string, privateKey *rsa.PrivateKey, projectId string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKey := privateKey.PublicKey
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	keyPairRec := &interfaces.JwkKeyRec{
		Id:          bson.NewObjectID(),
		KeyName:     keyName,
		Kid:         kid,
		Use:         use,
		ProjectId:   projectId,
		KeyBytes:    privateKeyBytes,
		PubKeyBytes: pubKeyBytes,
	}

	err := s.keyDAO.Insert(ctx, keyPairRec)
	if err == nil && keyName == s.tokenIssuer {
		s.tokenKey = privateKey
		s.tokenKid = kid
		s.tokenPubKey = s.getInternalPublicJWKS(ctx, keyName)
		s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
	}
	return err
}

// AddKey stores an externally-provided key (or key pair) identified by keyName.
func (s *KeyService) AddKey(ctx context.Context, keyName string, use string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	var privateKeyBytes []byte
	if privateKey != nil {
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
		if publicKey == nil {
			publicKey = &privateKey.PublicKey
		}
	}

	var pubKeyBytes []byte
	if publicKey != nil {
		pubKeyBytes = x509.MarshalPKCS1PublicKey(publicKey)
	}

	if kid == "" {
		kid = keyName
	}

	keyPairRec := &interfaces.JwkKeyRec{
		Id:          bson.NewObjectID(),
		KeyName:     keyName,
		Kid:         kid,
		Use:         use,
		ProjectId:   projectId,
		KeyBytes:    privateKeyBytes,
		PubKeyBytes: pubKeyBytes,
	}

	err := s.keyDAO.Insert(ctx, keyPairRec)
	if err == nil && keyName == s.tokenIssuer && privateKey != nil {
		s.tokenKey = privateKey
		s.tokenKid = kid
		s.tokenPubKey = s.getInternalPublicJWKS(ctx, keyName)
		s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
	}
	return err
}

// DeleteKeysByName removes all key records with the given keyName.
func (s *KeyService) DeleteKeysByName(ctx context.Context, keyName string) error {
	return s.keyDAO.DeleteByKeyName(ctx, keyName)
}

// GetPrivateKey retrieves the latest private key for keyName.
func (s *KeyService) GetPrivateKey(ctx context.Context, keyName string) (*rsa.PrivateKey, error) {
	key, _, err := s.GetPrivateKeyWithKid(ctx, keyName)
	return key, err
}

// GetPrivateKeyWithKid retrieves the latest private key and its kid for keyName.
func (s *KeyService) GetPrivateKeyWithKid(ctx context.Context, keyName string) (*rsa.PrivateKey, string, error) {
	rec, err := s.keyDAO.FindLatestByKeyName(ctx, keyName)
	if err != nil {
		return nil, "", err
	}

	if len(rec.KeyBytes) == 0 {
		return nil, "", errors.New("no private key found for: " + keyName)
	}

	key, err := x509.ParsePKCS1PrivateKey(rec.KeyBytes)
	if err != nil {
		return nil, "", err
	}

	kid := rec.Kid
	if kid == "" {
		kid = rec.KeyName
	}

	return key, kid, nil
}

// GetPublicJWKS returns the JWKS JSON for the public keys associated with keyName.
func (s *KeyService) GetPublicJWKS(ctx context.Context, keyName string) *json.RawMessage {
	keys, err := s.keyDAO.FindByKeyName(ctx, keyName)
	if err != nil {
		ksLog.Error("Error retrieving keys", "keyName", keyName, "error", err)
		return nil
	}

	jwkstore := jwkset.NewMemoryStorage()

	for _, rec := range keys {
		pubKey, err := x509.ParsePKCS1PublicKey(rec.PubKeyBytes)
		if err != nil {
			ksLog.Error("Error parsing public key", "kid", rec.Kid, "error", err)
			continue
		}

		kid := rec.Kid
		if kid == "" {
			kid = rec.KeyName
		}

		metadata := jwkset.JWKMetadataOptions{
			KID: kid,
		}
		metadata.USE = jwkset.UseSig
		jwkOptions := jwkset.JWKOptions{
			Metadata: metadata,
		}

		jwkSet, err := jwkset.NewJWKFromKey(pubKey, jwkOptions)
		if err != nil {
			ksLog.Error("Error parsing rsa key into jwk", "error", err)
			continue
		}
		err = jwkstore.KeyWrite(context.Background(), jwkSet)
		if err != nil {
			ksLog.Error("Error adding key to JWKS", "kid", kid, "error", err)
		}
	}

	response, err := jwkstore.JSONPublic(context.Background())
	if err != nil {
		ksLog.Error("Error creating JWKS response", "error", err)
		return nil
	}

	return &response
}

func (s *KeyService) getInternalPublicJWKS(ctx context.Context, keyName string) *keyfunc.JWKS {
	keys, err := s.keyDAO.FindByKeyName(ctx, keyName)
	if err != nil {
		ksLog.Error("Error retrieving keys", "keyName", keyName, "error", err)
		return nil
	}

	if len(keys) == 0 {
		ksLog.Error("No keys found", "keyName", keyName)
		return nil
	}

	givenKeys := make(map[string]keyfunc.GivenKey)
	for _, rec := range keys {
		pubKey, err := x509.ParsePKCS1PublicKey(rec.PubKeyBytes)
		if err != nil {
			ksLog.Error("Error parsing public key", "kid", rec.Kid, "error", err)
			continue
		}

		kid := rec.Kid
		if kid == "" {
			kid = rec.KeyName
		}

		givenKey := keyfunc.NewGivenRSA(pubKey, keyfunc.GivenKeyOptions{
			Algorithm: "RS256",
		})
		givenKeys[kid] = givenKey
	}
	return keyfunc.NewGiven(givenKeys)
}

// ListKeyNames returns the distinct keyName values in the key store.
func (s *KeyService) ListKeyNames(ctx context.Context) ([]string, error) {
	return s.keyDAO.ListKeyNames(ctx)
}

// GetKeyIds returns all kid values in the key store.
func (s *KeyService) GetKeyIds(ctx context.Context) ([]string, error) {
	return s.keyDAO.ListKids(ctx)
}

// ListSummaries returns key summaries for all keys without exposing key material.
func (s *KeyService) ListSummaries(ctx context.Context) ([]interfaces.KeySummary, error) {
	return s.keyDAO.ListSummaries(ctx)
}

// GetKeySummary returns the summary for a specific kid.
func (s *KeyService) GetKeySummary(ctx context.Context, kid string) (*interfaces.KeySummary, error) {
	return s.keyDAO.KeySummary(ctx, kid)
}

// DeleteKey removes the key with the given kid.
func (s *KeyService) DeleteKey(ctx context.Context, kid string) error {
	return s.keyDAO.DeleteByKid(ctx, kid)
}

// GetPrivateKeyByKid retrieves a private key by its kid.
func (s *KeyService) GetPrivateKeyByKid(ctx context.Context, kid string) (*rsa.PrivateKey, error) {
	rec, err := s.keyDAO.FindByKid(ctx, kid)
	if err != nil {
		return nil, err
	}

	if len(rec.KeyBytes) == 0 {
		return nil, errors.New("no private key found for: " + kid)
	}

	return x509.ParsePKCS1PrivateKey(rec.KeyBytes)
}

// GetAuthValidatorPubKey returns the JWKS used to validate auth tokens issued by this server.
func (s *KeyService) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return s.tokenPubKey
}

// GetAuthIssuer returns the AuthIssuer used for signing auth tokens.
func (s *KeyService) GetAuthIssuer() *authUtil.AuthIssuer {
	return s.authIssuer
}

// StoreExternalKey stores a reference to an external JWKS URL for a receiver or encryption target.
// keyName identifies the entity (e.g. audience/receiver name), use is "sig" or "enc".
func (s *KeyService) StoreExternalKey(ctx context.Context, keyName string, streamID string, use string, jwksUri string) error {
	keyPairRec := &interfaces.JwkKeyRec{
		Id:              bson.NewObjectID(),
		KeyName:         keyName,
		Kid:             keyName,
		Use:             use,
		StreamId:        streamID,
		ReceiverJwksUrl: jwksUri,
	}
	return s.keyDAO.Insert(ctx, keyPairRec)
}

// GetKeyByStreamID retrieves the key record associated with a stream.
func (s *KeyService) GetKeyByStreamID(ctx context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	return s.keyDAO.FindByStreamID(ctx, streamID)
}
