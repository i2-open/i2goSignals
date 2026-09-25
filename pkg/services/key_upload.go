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

// StoreUploadedSigningKey stores an uploaded private key (RS256, ES256 or
// ML-DSA-65) as a signing key of keyName and returns its kid. Its validity
// period is cert's when a certificate came with it; otherwise the key is valid
// from now for the lifetime in opts, else the configured default (#318). An
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
	v := s.generatedValidity(keyName, s.mintedAt(), opts)
	if cert != nil {
		v = keyValidity{notBefore: cert.NotBefore.UTC(), notAfter: cert.NotAfter.UTC()}
	}
	if err := s.storeKeyPair(ctx, keyName, kid, use, key, projectId, v); err != nil {
		return "", err
	}
	return kid, nil
}
