package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptomldsa "crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

// supportedSigningKeys is the list an unsupported-key error names.
const supportedSigningKeys = "a signing key must be RSA (RS256), ECDSA P-256 (ES256) or ML-DSA-65"

// SigningAlgOf names the JWS algorithm an uploaded private key signs with:
// RS256, ES256 or ML-DSA-65. Any other key is an error naming its type
// (i2goSignals#318).
func SigningAlgOf(key crypto.Signer) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RS256", nil
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P256() {
			return jwtES256, nil
		}
		return "", fmt.Errorf("unsupported key type ECDSA %s: %s", k.Curve.Params().Name, supportedSigningKeys)
	case *cryptomldsa.PrivateKey:
		if params := k.PublicKey().Parameters(); params.String() != cryptomldsa.MLDSA65().String() {
			return "", fmt.Errorf("unsupported key type %s: %s", params, supportedSigningKeys)
		}
		return mldsa.Alg, nil
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return "", fmt.Errorf("unsupported key type Ed25519: %s", supportedSigningKeys)
	default:
		return "", fmt.Errorf("unsupported key type %T: %s", key, supportedSigningKeys)
	}
}

// supportedVerificationKeys is the list an unsupported public-key error names.
const supportedVerificationKeys = "a verification key must be RSA (RS256), ECDSA P-256 (ES256) or ML-DSA-65"

// VerificationAlgOf names the JWS algorithm an uploaded public key, or a
// certificate's, verifies: RS256, ES256 or ML-DSA-65. Any other key is an
// error naming its type (i2goSignals#318).
func VerificationAlgOf(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RS256", nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return jwtES256, nil
		}
		return "", fmt.Errorf("unsupported key type ECDSA %s: %s", k.Curve.Params().Name, supportedVerificationKeys)
	case *cryptomldsa.PublicKey:
		if params := k.Parameters(); params.String() != cryptomldsa.MLDSA65().String() {
			return "", fmt.Errorf("unsupported key type %s: %s", params, supportedVerificationKeys)
		}
		return mldsa.Alg, nil
	case ed25519.PublicKey, *ed25519.PublicKey:
		return "", fmt.Errorf("unsupported key type Ed25519: %s", supportedVerificationKeys)
	default:
		return "", fmt.Errorf("unsupported key type %T: %s", pub, supportedVerificationKeys)
	}
}

// AddVerificationKey stores an uploaded public key (RS256, ES256 or ML-DSA-65)
// as a verification-only key of keyName and returns its kid. It never signs
// and carries no validity period (#318 leaves verification-only keys without
// expiry). An RSA key is stored as AddKey always stored it; an empty kid is the
// keyName for an RSA key and a unique kid for the other algorithms.
func (s *KeyService) AddVerificationKey(ctx context.Context, keyName string, use string, kid string, pub crypto.PublicKey, projectId string) (string, error) {
	alg, err := VerificationAlgOf(pub)
	if err != nil {
		return "", err
	}
	if rsaKey, ok := pub.(*rsa.PublicKey); ok {
		if kid == "" {
			kid = keyName
		}
		return kid, s.AddKey(ctx, keyName, use, kid, nil, rsaKey, projectId)
	}
	var pubBytes []byte
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if pubBytes, err = x509.MarshalPKIXPublicKey(k); err != nil {
			return "", fmt.Errorf("encoding %s public key: %w", jwtES256, err)
		}
	case *cryptomldsa.PublicKey:
		pubBytes = k.Bytes()
	}
	if kid == "" {
		kid = newKeyKid(keyName, alg)
	}
	rec := &interfaces.JwkKeyRec{
		Id:          ids.NewObjectID(),
		KeyName:     keyName,
		Kid:         kid,
		Use:         use,
		ProjectId:   projectId,
		Alg:         alg,
		PubKeyBytes: pubBytes,
		CreatedAt:   s.mintedAt(),
	}
	return kid, s.keyDAO.Insert(ctx, rec)
}

// StoreUploadedSigningKey stores an uploaded private key (RS256, ES256 or
// ML-DSA-65) as a signing key of keyName and returns its kid. Its validity
// period is cert's when a certificate came with it; otherwise the key is valid
// from now for the lifetime in opts, else the configured default (#318). The
// token issuer's key never expires, certificate or not. An
// empty kid is the keyName for an RSA key, as uploads always had, and a unique
// kid for the other algorithms.
func (s *KeyService) StoreUploadedSigningKey(ctx context.Context, keyName string, use string, kid string, key crypto.Signer, cert *x509.Certificate, projectId string, opts ...KeyOption) (string, error) {
	alg, err := SigningAlgOf(key)
	if err != nil {
		return "", err
	}
	storedAlg, err := storedAlgFor(alg)
	if err != nil {
		return "", err
	}
	if kid == "" {
		kid = keyName
		if storedAlg != "" {
			kid = newKeyKid(keyName, storedAlg)
		}
	}
	if err := s.storeKeyPair(ctx, keyName, kid, use, key, projectId, s.uploadedValidity(keyName, cert, opts)); err != nil {
		return "", err
	}
	return kid, nil
}
