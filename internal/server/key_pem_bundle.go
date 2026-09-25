package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/i2-open/i2goSignals/pkg/services"
)

// pemBundle is what an application/x-pem-file key upload carries: a private
// key (RSA, ECDSA P-256 or ML-DSA-65) optionally with its certificate, or an
// RSA public key or certificate for verification only (#318).
type pemBundle struct {
	priv crypto.Signer
	pub  *rsa.PublicKey
	cert *x509.Certificate
	alg  string
}

// validAt reports whether the bundle's certificate, if any, is valid at now
// (NotAfter exclusive, as for a key's validity period).
func (b *pemBundle) validAt(now time.Time) bool {
	return b.cert == nil || (!now.Before(b.cert.NotBefore) && now.Before(b.cert.NotAfter))
}

// parsePemBundle reads every PEM block of an upload. A private key is a signing
// key of the algorithm SigningAlgOf names; a certificate with it must certify
// that key. Without a private key the upload is an RSA public key, from a
// PUBLIC KEY block or a certificate.
func parsePemBundle(body []byte) (*pemBundle, error) {
	b := &pemBundle{alg: "RS256"}
	var pubBlock crypto.PublicKey
	blocks := 0
	for rest := body; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		switch block.Type {
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if b.priv != nil {
				return nil, errors.New("the PEM data holds more than one private key")
			}
			key, err := parsePemPrivateKey(block)
			if err != nil {
				return nil, err
			}
			b.priv = key
		case "PUBLIC KEY", "RSA PUBLIC KEY":
			if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
				pubBlock = key
			} else if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				pubBlock = key
			}
		case "CERTIFICATE":
			if b.cert != nil {
				continue // the leaf comes first; the rest is its chain
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("Invalid certificate")
			}
			b.cert = cert
		}
	}
	if blocks == 0 {
		return nil, errors.New("Invalid PEM data")
	}

	if b.priv != nil {
		alg, err := services.SigningAlgOf(b.priv)
		if err != nil {
			return nil, err
		}
		b.alg = alg
		if b.cert != nil {
			pub, ok := b.priv.Public().(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !pub.Equal(b.cert.PublicKey) {
				return nil, errors.New("the certificate does not match the private key")
			}
		}
		if rsaKey, ok := b.priv.(*rsa.PrivateKey); ok {
			b.pub = &rsaKey.PublicKey
		}
		return b, nil
	}

	// Verification only: an RSA public key. Its certificate's dates are not
	// enforced (#318 leaves verification-only keys without expiry).
	if rsaKey, ok := pubBlock.(*rsa.PublicKey); ok {
		b.pub = rsaKey
	} else if b.cert != nil {
		if rsaKey, ok := b.cert.PublicKey.(*rsa.PublicKey); ok {
			b.pub = rsaKey
		}
	}
	b.cert = nil
	if b.pub == nil {
		return nil, errors.New("Could not parse key or unsupported key type")
	}
	return b, nil
}

// parsePemPrivateKey parses a PKCS#8, PKCS#1 (RSA) or SEC 1 (EC) private key.
func parsePemPrivateKey(block *pem.Block) (crypto.Signer, error) {
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			// Some tools label a PKCS#1 RSA key "PRIVATE KEY".
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		}
	}
	if err != nil {
		return nil, errors.New("Could not parse key or unsupported key type")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("Could not parse key or unsupported key type")
	}
	return signer, nil
}
