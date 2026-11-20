package server

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/i2-open/i2goSignals/pkg/services"
)

// pemBundle is what an application/x-pem-file key upload carries: a private
// key (RSA, ECDSA P-256 or ML-DSA-65) optionally with its certificate, or a
// public key or certificate of those types for verification only (#318).
type pemBundle struct {
	priv crypto.Signer
	pub  crypto.PublicKey
	cert *x509.Certificate
	alg  string
}

// parsePemBundle reads every PEM block of an upload. A private key is a signing
// key of the algorithm SigningAlgOf names; its certificate is the one among the
// upload's CERTIFICATE blocks that certifies that key, in whatever order the
// chain was concatenated. Without a private key the upload is a verification
// key, from a PUBLIC KEY block or the first certificate.
//
// The capitalized error strings here are HTTP response body text returned to
// the uploader verbatim; they are kept as the wire has always carried them.
func parsePemBundle(body []byte) (*pemBundle, error) {
	b := &pemBundle{alg: "RS256"}
	var pubBlock crypto.PublicKey
	var certs []*x509.Certificate
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
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("Invalid certificate")
			}
			certs = append(certs, cert)
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
		if len(certs) > 0 {
			// The leaf is the certificate whose public key is the private
			// key's; the others are its chain.
			pub, ok := b.priv.Public().(interface{ Equal(crypto.PublicKey) bool })
			for _, cert := range certs {
				if ok && pub.Equal(cert.PublicKey) {
					b.cert = cert
					break
				}
			}
			if b.cert == nil {
				return nil, errors.New("the certificate does not match the private key")
			}
		}
		return b, nil
	}

	// Verification only: the PUBLIC KEY block's key, else the first
	// certificate's (the leaf, by the PEM chain convention).
	if pubBlock == nil && len(certs) > 0 {
		pubBlock = certs[0].PublicKey
	}
	return verificationBundle(pubBlock)
}

// parsePkixUpload reads an application/pkix-cert upload: a DER certificate, or
// a DER PKIX public key, registered for verification only.
func parsePkixUpload(body []byte) (*pemBundle, error) {
	if cert, err := x509.ParseCertificate(body); err == nil {
		return verificationBundle(cert.PublicKey)
	}
	if key, err := x509.ParsePKIXPublicKey(body); err == nil {
		return verificationBundle(key)
	}
	return nil, errors.New("Could not parse key or unsupported key type")
}

// verificationBundle is the upload of pub for verification only: RSA, ECDSA
// P-256 or ML-DSA-65, any other type being an error naming it. A certificate's
// dates are not kept (#318 leaves verification-only keys without expiry).
func verificationBundle(pub crypto.PublicKey) (*pemBundle, error) {
	if pub == nil {
		return nil, errors.New("Could not parse key or unsupported key type")
	}
	alg, err := services.VerificationAlgOf(pub)
	if err != nil {
		return nil, err
	}
	return &pemBundle{pub: pub, alg: alg}, nil
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
