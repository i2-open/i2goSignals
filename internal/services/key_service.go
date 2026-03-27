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

// InitializeTokenKey loads or creates the token key for authentication
func (s *KeyService) InitializeTokenKey(ctx context.Context, defaultIssuer string) error {
	// Try to load existing key
	key, kid, err := s.GetIssuerPrivateKeyWithKid(ctx, s.tokenIssuer)
	if err == nil && key != nil {
		s.tokenKey = key
		s.tokenKid = kid
		s.tokenPubKey = s.getInternalPublicTransmitterJWKS(ctx, s.tokenIssuer)
		s.authIssuer.UpdateTokenKey(s.tokenIssuer, s.tokenKid, s.tokenKey, s.tokenPubKey)
		return nil
	}

	// Create new key
	s.tokenKey, err = s.CreateIssuerJwkKeyPair(ctx, s.tokenIssuer, "")
	if err != nil {
		return fmt.Errorf("failed to create token key: %v", err)
	}
	s.tokenKid = s.tokenIssuer
	s.tokenPubKey = s.getInternalPublicTransmitterJWKS(ctx, s.tokenIssuer)
	s.authIssuer.UpdateTokenKey(s.tokenIssuer, s.tokenKid, s.tokenKey, s.tokenPubKey)

	if defaultIssuer != s.tokenIssuer {
		// Also create default issuer key if different
		_, err = s.CreateIssuerJwkKeyPair(ctx, defaultIssuer, "")
		if err != nil {
			ksLog.Error("Error creating default issuer key", "error", err)
		}
	}
	s.tokenPubKey = s.getInternalPublicTransmitterJWKS(ctx, s.tokenIssuer)
	return nil
}

func (s *KeyService) CreateIssuerJwkKeyPair(ctx context.Context, issuer string, projectId string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		ksLog.Error("Error generating key pair", "error", err)
		return nil, err
	}

	err = s.storeJwkKeyPair(ctx, issuer, issuer, privateKey, projectId)
	if err != nil {
		ksLog.Error("Error storing key pair", "error", err)
		return nil, err
	}

	if issuer == s.tokenIssuer {
		s.tokenKey = privateKey
		s.tokenKid = issuer
		s.tokenPubKey = s.getInternalPublicTransmitterJWKS(ctx, issuer)
		s.authIssuer.UpdateTokenKey(issuer, issuer, privateKey, s.tokenPubKey)
	}

	return privateKey, nil
}

func (s *KeyService) RotateIssuerKey(ctx context.Context, issuer string, projectId string) (*rsa.PrivateKey, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	kid := fmt.Sprintf("%s-%s", issuer, bson.NewObjectID().Hex())
	err = s.storeJwkKeyPair(ctx, issuer, kid, privateKey, projectId)
	if err != nil {
		return nil, "", err
	}

	if issuer == s.tokenIssuer {
		s.tokenKey = privateKey
		s.tokenKid = kid
		s.tokenPubKey = s.getInternalPublicTransmitterJWKS(ctx, issuer)
		s.authIssuer.UpdateTokenKey(issuer, kid, privateKey, s.tokenPubKey)
	}

	return privateKey, kid, nil
}

func (s *KeyService) storeJwkKeyPair(ctx context.Context, issuer string, kid string, privateKey *rsa.PrivateKey, projectId string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKey := privateKey.PublicKey
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	keyPairRec := &interfaces.JwkKeyRec{
		Id:          bson.NewObjectID(),
		Iss:         issuer,
		Kid:         kid,
		ProjectId:   projectId,
		KeyBytes:    privateKeyBytes,
		PubKeyBytes: pubKeyBytes,
	}

	err := s.keyDAO.Insert(ctx, keyPairRec)
	if err == nil && issuer == s.tokenIssuer {
		s.tokenKey = privateKey
		s.tokenKid = kid
		s.tokenPubKey = s.getInternalPublicTransmitterJWKS(ctx, issuer)
		s.authIssuer.UpdateTokenKey(issuer, kid, privateKey, s.tokenPubKey)
	}
	return err
}

func (s *KeyService) AddIssuerKey(ctx context.Context, issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
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
		kid = issuer
	}

	keyPairRec := &interfaces.JwkKeyRec{
		Id:          bson.NewObjectID(),
		Iss:         issuer,
		Kid:         kid,
		ProjectId:   projectId,
		KeyBytes:    privateKeyBytes,
		PubKeyBytes: pubKeyBytes,
	}

	err := s.keyDAO.Insert(ctx, keyPairRec)
	if err == nil && issuer == s.tokenIssuer && privateKey != nil {
		s.tokenKey = privateKey
		s.tokenKid = kid
		s.tokenPubKey = s.getInternalPublicTransmitterJWKS(ctx, issuer)
		s.authIssuer.UpdateTokenKey(issuer, kid, privateKey, s.tokenPubKey)
	}
	return err
}

func (s *KeyService) DeleteIssuer(ctx context.Context, issuer string) error {
	return s.keyDAO.DeleteByIssuer(ctx, issuer)
}

func (s *KeyService) GetIssuerPrivateKey(ctx context.Context, issuer string) (*rsa.PrivateKey, error) {
	key, _, err := s.GetIssuerPrivateKeyWithKid(ctx, issuer)
	return key, err
}

func (s *KeyService) GetIssuerPrivateKeyWithKid(ctx context.Context, issuer string) (*rsa.PrivateKey, string, error) {
	rec, err := s.keyDAO.FindLatestByIssuer(ctx, issuer)
	if err != nil {
		return nil, "", err
	}

	if len(rec.KeyBytes) == 0 {
		return nil, "", errors.New("no key found for: " + issuer)
	}

	key, err := x509.ParsePKCS1PrivateKey(rec.KeyBytes)
	if err != nil {
		return nil, "", err
	}

	kid := rec.Kid
	if kid == "" {
		kid = rec.Iss
	}

	return key, kid, nil
}

func (s *KeyService) GetPublicTransmitterJWKS(ctx context.Context, issuer string) *json.RawMessage {
	keys, err := s.keyDAO.FindByIssuer(ctx, issuer)
	if err != nil {
		ksLog.Error("Error retrieving keys for issuer", "issuer", issuer, "error", err)
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
			kid = rec.Iss
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

func (s *KeyService) getInternalPublicTransmitterJWKS(ctx context.Context, issuer string) *keyfunc.JWKS {
	keys, err := s.keyDAO.FindByIssuer(ctx, issuer)
	if err != nil {
		ksLog.Error("Error retrieving keys for issuer", "issuer", issuer, "error", err)
		return nil
	}

	if len(keys) == 0 {
		ksLog.Error("No keys found for issuer", "issuer", issuer)
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
			kid = rec.Iss
		}

		givenKey := keyfunc.NewGivenRSA(pubKey, keyfunc.GivenKeyOptions{
			Algorithm: "RS256",
		})
		givenKeys[kid] = givenKey
	}
	return keyfunc.NewGiven(givenKeys)
}

func (s *KeyService) GetIssuerKeyNames(ctx context.Context) ([]string, error) {
	return s.keyDAO.ListIssuers(ctx)
}

func (s *KeyService) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return s.tokenPubKey
}

func (s *KeyService) GetAuthIssuer() *authUtil.AuthIssuer {
	return s.authIssuer
}

func (s *KeyService) StoreReceiverKey(ctx context.Context, streamID string, audience string, jwksUri string) error {
	return s.keyDAO.InsertReceiverKey(ctx, streamID, audience, jwksUri)
}

func (s *KeyService) GetReceiverKey(ctx context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	return s.keyDAO.FindReceiverKeyByStreamID(ctx, streamID)
}
