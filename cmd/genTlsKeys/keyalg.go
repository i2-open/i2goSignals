package main

import (
	"crypto"
	cryptomldsa "crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Post-quantum option for the internal mTLS certificates (RFC 9964 slice,
// i2goSignals#278).
//
// Go 1.27 can issue and verify X.509 certificates signed with ML-DSA (FIPS
// 204) and negotiate them in TLS 1.3, so the cluster's own mTLS material can be
// made post-quantum without touching the SET signing path — the two are
// independent choices with independent blast radii. This file is that option
// and nothing more: the algorithm is chosen once, here, and the rest of
// keySupport.go works through crypto.Signer.
//
// It is OFF by default and stays that way. These certificates are trusted by
// every node in a deployment; switching the default would invalidate every
// existing CA on upgrade, and ML-DSA certificates are ~4 KB where RSA-4096 is
// ~1.7 KB, which is paid on every handshake. An operator opts in per
// deployment with CERT_KEY_ALG=ML-DSA-65.

// EnvCertKeyAlg selects the key algorithm for the generated CA and leaf
// certificates: "RSA" (default) or "ML-DSA-65".
const EnvCertKeyAlg string = "CERT_KEY_ALG"

const (
	// KeyAlgRSA is the default: RSA-4096, matching every certificate this
	// command has generated to date.
	KeyAlgRSA = "RSA"
	// KeyAlgMLDSA65 is the FIPS 204 post-quantum option.
	KeyAlgMLDSA65 = "ML-DSA-65"
)

// certKeyAlg reads the configured certificate key algorithm, defaulting to RSA
// and refusing an unrecognised value rather than silently falling back — an
// operator who asked for post-quantum certificates and got RSA would have no
// way to notice.
func certKeyAlg() (string, error) {
	return normalizeKeyAlg(os.Getenv(EnvCertKeyAlg))
}

func normalizeKeyAlg(raw string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", KeyAlgRSA:
		return KeyAlgRSA, nil
	case KeyAlgMLDSA65:
		return KeyAlgMLDSA65, nil
	default:
		return "", fmt.Errorf("unsupported %s value %q; want %q or %q", EnvCertKeyAlg, raw, KeyAlgRSA, KeyAlgMLDSA65)
	}
}

// generateCertKey mints a private key of the given algorithm. RSA-4096 keeps
// the existing strength; ML-DSA-65 is the Category 3 parameter set, matching
// the SET signing choice so a deployment reasons about one PQ level.
func generateCertKey(alg string) (crypto.Signer, error) {
	switch alg {
	case KeyAlgMLDSA65:
		return cryptomldsa.GenerateKey(cryptomldsa.MLDSA65())
	default:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
}

// marshalPrivateKeyPEM encodes a private key in the PEM form that matches its
// algorithm. RSA stays PKCS#1 ("RSA PRIVATE KEY") so files written by earlier
// versions of this command and files written now are interchangeable; ML-DSA
// has no PKCS#1 representation and uses PKCS#8 ("PRIVATE KEY"), which is also
// what crypto/tls reads back.
func marshalPrivateKeyPEM(key crypto.Signer) (*pem.Block, error) {
	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}, nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &pem.Block{Type: "PRIVATE KEY", Bytes: der}, nil
}

// parsePrivateKeyPEM reads a private key written by marshalPrivateKeyPEM.
// PKCS#1 is tried first because that is what every existing CA key file on
// disk is; PKCS#8 covers ML-DSA and anything else Go can carry.
func parsePrivateKeyPEM(block *pem.Block) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA key is neither PKCS#1 nor PKCS#8: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key cannot sign")
	}
	return signer, nil
}
