package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
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

func NewKeyService(keyDAO interfaces.KeyDAO, tokenIssuer string, tokenTracker authSupport.TokenTracker) *KeyService {
	return &KeyService{
		keyDAO:      keyDAO,
		tokenIssuer: tokenIssuer,
		authIssuer: &authUtil.AuthIssuer{
			TokenIssuer:  tokenIssuer,
			TokenTracker: tokenTracker,
		},
	}
}

// InitializeTokenKey loads or creates the token signing key for authentication
func (s *KeyService) InitializeTokenKey(ctx context.Context, defaultIssuer string) error {
	// Try to load existing key
	key, kid, err := s.GetPrivateKeyWithKeyname(ctx, s.tokenIssuer)
	if err == nil && key != nil {
		s.tokenKey = key
		s.tokenKid = kid
		// Use buildAuthJWKS with the loaded key so that, even when there are duplicate
		// kid=DEFAULT records in the DB (race between two nodes on first start), the
		// JWKS entry for this kid always reflects the private key we actually loaded.
		s.tokenPubKey = s.buildAuthJWKS(ctx, s.tokenIssuer, key, kid)
		if s.tokenPubKey == nil {
			return fmt.Errorf("failed to build public JWKS for token issuer %q; MongoDB may be temporarily unavailable", s.tokenIssuer)
		}
		s.authIssuer.UpdateTokenKey(s.tokenIssuer, s.tokenKid, s.tokenKey, s.tokenPubKey)
		return nil
	}

	// Only create a new key if the key genuinely does not exist in the database.
	// Any other error (e.g. a transient MongoDB failure) must propagate so that the
	// caller retries rather than accidentally inserting a duplicate kid=DEFAULT record,
	// which would cause non-deterministic JWKS construction and signature-mismatch 503s.
	if err != nil && !errors.Is(err, interfaces.ErrKeyNotFound) {
		return fmt.Errorf("failed to load token key %q: %w", s.tokenIssuer, err)
	}

	// Create new key. CreateKeyPair → storeKeyPair sets AuthIssuer atomically using
	// buildAuthJWKS with the signing key override. Do NOT re-query getInternalPublicJWKS
	// here — doing so would race with concurrent cluster nodes inserting their own
	// kid=DEFAULT key, causing the JWKS to contain a different node's public key while
	// this node's private key is used for signing.
	s.tokenKey, err = s.CreateKeyPair(ctx, s.tokenIssuer, "sig", "")
	if err != nil {
		return fmt.Errorf("failed to create token key: %v", err)
	}
	s.tokenKid = s.tokenIssuer
	s.tokenPubKey = s.authIssuer.PublicKey // already set correctly by storeKeyPair
	if s.tokenPubKey == nil {
		return fmt.Errorf("failed to build public JWKS for token issuer %q after key creation", s.tokenIssuer)
	}

	if defaultIssuer != s.tokenIssuer {
		// Also create default issuer signing key if different
		_, err = s.CreateKeyPair(ctx, defaultIssuer, "sig", "")
		if err != nil {
			ksLog.Error("Error creating default issuer key", "error", err)
		}
	}
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

	// storeKeyPair above already called buildAuthJWKS + UpdateTokenKey for the token
	// issuer key. No need to re-query the DB here; doing so would reintroduce the
	// race where a concurrent node's same-kid record overwrites our JWKS entry.

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
		jwks := s.buildAuthJWKS(ctx, keyName, privateKey, kid)
		if jwks != nil {
			s.tokenPubKey = jwks
			s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
		} else {
			ksLog.Error("Failed to build JWKS after key rotation", "keyName", keyName)
		}
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
		// Use buildAuthJWKS with the signing key override to guarantee that the JWKS
		// entry for this kid matches privateKey, regardless of concurrent inserts from
		// other cluster nodes with the same kid.
		jwks := s.buildAuthJWKS(ctx, keyName, privateKey, kid)
		if jwks != nil {
			s.tokenPubKey = jwks
			s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
		} else {
			ksLog.Error("Failed to build JWKS after key store", "keyName", keyName)
		}
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
		jwks := s.getInternalPublicJWKS(ctx, keyName)
		if jwks != nil {
			s.tokenPubKey = jwks
			s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
		} else {
			ksLog.Error("Failed to build JWKS after key add", "keyName", keyName)
		}
	}
	return err
}

// DeleteKeysByName removes all key records with the given keyName.
func (s *KeyService) DeleteKeysByName(ctx context.Context, keyName string) error {
	return s.keyDAO.DeleteByKeyName(ctx, keyName)
}

// GetPrivateKey retrieves the latest private key for keyName.
func (s *KeyService) GetPrivateKey(ctx context.Context, keyName string) (*rsa.PrivateKey, error) {
	key, _, err := s.GetPrivateKeyWithKeyname(ctx, keyName)
	return key, err
}

// GetPrivateKeyWithKeyname retrieves the latest private key and its kid for keyName.
func (s *KeyService) GetPrivateKeyWithKeyname(ctx context.Context, keyName string) (*rsa.PrivateKey, string, error) {
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
		var jwkSet jwkset.JWK
		var err error
		if rec.ReceiverJwksUrl != "" {
			// key is an external key fetch the jwks and convert so it can be added to jwkstore
			srvLog.Debug("Fetching JWK from server", "url", rec.ReceiverJwksUrl)
			var jwksExtern *keyfunc.JWKS
			jwksExtern, err = goSet.GetJwks(rec.ReceiverJwksUrl)
			if err != nil {
				ksLog.Error("Error fetching JWKS from server", "url", rec.ReceiverJwksUrl, "error", err)
				continue
			}

			// Convert keyfunc.JWKS to jwkset.JWK and add to jwkstore
			rawJWKS := jwksExtern.RawJWKS()

			var jwksData struct {
				Keys []json.RawMessage `json:"keys"`
			}
			if err = json.Unmarshal(rawJWKS, &jwksData); err != nil {
				ksLog.Error("Error unmarshaling JWKS", "error", err)
				continue
			}

			for _, keyData := range jwksData.Keys {
				jwkSet, err = jwkset.NewJWKFromRawJSON(keyData, jwkset.JWKMarshalOptions{}, jwkset.JWKValidateOptions{})
				if err != nil {
					ksLog.Error("Error creating JWK from raw JSON", "error", err)
					continue
				}
				err = jwkstore.KeyWrite(context.Background(), jwkSet)
				if err != nil {
					ksLog.Error("Error adding external key to JWKS", "error", err)
				}
			}
			continue

		} else {
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
			if rec.Use == "enc" {
				metadata.USE = jwkset.UseEnc
			} else {
				metadata.USE = jwkset.UseSig
			}
			jwkOptions := jwkset.JWKOptions{
				Metadata: metadata,
			}

			jwkSet, err = jwkset.NewJWKFromKey(pubKey, jwkOptions)
			if err != nil {
				ksLog.Error("Error parsing rsa key into jwk", "error", err)
				continue
			}
			err = jwkstore.KeyWrite(context.Background(), jwkSet)
			if err != nil {
				ksLog.Error("Error adding key to JWKS", "kid", kid, "error", err)
			}
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
	return s.buildAuthJWKS(ctx, keyName, nil, "")
}

// buildAuthJWKS constructs a keyfunc.JWKS from all stored public keys for keyName.
// When signingKey/signingKid are provided, the map entry for signingKid is always
// set to signingKey's public component — overriding whatever the DB returned for
// that kid. This guarantees that the signing private key and the verification
// public key in the returned JWKS are always a matched pair, even when a concurrent
// cluster node has inserted a different key with the same kid.
func (s *KeyService) buildAuthJWKS(ctx context.Context, keyName string, signingKey *rsa.PrivateKey, signingKid string) *keyfunc.JWKS {
	keys, err := s.keyDAO.FindByKeyName(ctx, keyName)
	if err != nil {
		ksLog.Error("Error retrieving keys", "keyName", keyName, "error", err)
		return nil
	}

	if len(keys) == 0 && signingKey == nil {
		ksLog.Error("No keys found", "keyName", keyName)
		return nil
	}

	// Sort oldest-first so that when multiple records share the same kid (which can
	// happen after a transient DB error causes a duplicate insert), the newest
	// record's public key overwrites older ones in the givenKeys map — keeping the
	// JWKS consistent with FindLatestByKeyName, which is used for signing.
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Id.Hex() < keys[j].Id.Hex()
	})

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

		givenKeys[kid] = keyfunc.NewGivenRSA(pubKey, keyfunc.GivenKeyOptions{
			Algorithm: "RS256",
		})
	}

	// Always use the caller-supplied signing key for its kid, overriding whatever the
	// DB returned. This is safe because the caller has the canonical private key in
	// hand; a concurrent node's conflicting DB record cannot affect signing/verify
	// consistency.
	if signingKey != nil && signingKid != "" {
		givenKeys[signingKid] = keyfunc.NewGivenRSA(&signingKey.PublicKey, keyfunc.GivenKeyOptions{
			Algorithm: "RS256",
		})
	}

	if len(givenKeys) == 0 {
		ksLog.Error("No valid keys found", "keyName", keyName)
		return nil
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
func (s *KeyService) StoreExternalKey(ctx context.Context, keyName string, kids []string, streamID string, use string, jwksUri string) error {
	kid := keyName
	if kids != nil && len(kids) > 0 {
		kid = kids[0]
	}
	keyPairRec := &interfaces.JwkKeyRec{
		Id:              bson.NewObjectID(),
		KeyName:         keyName,
		Kid:             kid,
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
