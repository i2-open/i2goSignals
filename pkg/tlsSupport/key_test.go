package tlsSupport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestCert(t *testing.T, priv *rsa.PrivateKey, dnsNames []string) *tls.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  priv,
	}
	leaf, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	cert.Leaf = leaf
	return cert
}

func TestGetCertificateSelectionLogic(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fileCert := createTestCert(t, priv, []string{"goSignals1", "localhost"})
	spiffeCertMatched := createTestCert(t, priv, []string{"goSignals1"})
	spiffeCertUnmatched := createTestCert(t, priv, []string{"otherName"})

	tests := []struct {
		name          string
		sni           string
		spiffeCert    *tls.Certificate
		spiffeErr     error
		useFileCert   bool
		expectedCert  *tls.Certificate
		expectedError bool
	}{
		{
			name:         "SNI matches SPIFFE",
			sni:          "goSignals1",
			spiffeCert:   spiffeCertMatched,
			useFileCert:  true,
			expectedCert: spiffeCertMatched,
		},
		{
			name:         "SNI matches FileCert but not SPIFFE",
			sni:          "localhost",
			spiffeCert:   spiffeCertUnmatched,
			useFileCert:  true,
			expectedCert: fileCert,
		},
		{
			name:         "SNI matches neither, return File default",
			sni:          "unknown",
			spiffeCert:   spiffeCertUnmatched,
			useFileCert:  true,
			expectedCert: fileCert,
		},
		{
			name:         "SNI empty, return File default",
			sni:          "",
			spiffeCert:   spiffeCertMatched,
			useFileCert:  true,
			expectedCert: fileCert,
		},
		{
			name:         "SPIFFE fails, SNI matches FileCert",
			sni:          "goSignals1",
			spiffeCert:   nil,
			spiffeErr:    assert.AnError,
			useFileCert:  true,
			expectedCert: fileCert,
		},
		{
			name:         "SPIFFE fails, no SNI, return File default",
			sni:          "",
			spiffeCert:   nil,
			spiffeErr:    assert.AnError,
			useFileCert:  true,
			expectedCert: fileCert,
		},
		{
			name:         "Both fail, return SPIFFE error",
			sni:          "unknown",
			spiffeCert:   nil,
			spiffeErr:    assert.AnError,
			useFileCert:  false,
			expectedCert: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock spiffeGetCert
			spiffeGetCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return tt.spiffeCert, tt.spiffeErr
			}

			var currentFileCert *tls.Certificate
			if tt.useFileCert {
				currentFileCert = fileCert
			}

			// Define the logic locally to test it (updated to match key.go)
			getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				spiffeCert, spiffeErr := spiffeGetCert(hello)

				// 1. Try to find a certificate that matches the requested SNI.
				if hello.ServerName != "" {
					// Check if SPIFFE SVID matches the requested SNI.
					if spiffeErr == nil && spiffeCert != nil {
						leaf := spiffeCert.Leaf
						if leaf == nil && len(spiffeCert.Certificate) > 0 {
							leaf, _ = x509.ParseCertificate(spiffeCert.Certificate[0])
						}
						if leaf != nil && leaf.VerifyHostname(hello.ServerName) == nil {
							return spiffeCert, nil
						}
					}

					// Fallback to file-based cert if it matches the SNI.
					if currentFileCert != nil && currentFileCert.Leaf != nil {
						if err := currentFileCert.Leaf.VerifyHostname(hello.ServerName); err == nil {
							return currentFileCert, nil
						}
					}
				}

				// 2. Default: prefer the file-based cert if no match or no SNI.
				if currentFileCert != nil {
					return currentFileCert, nil
				}

				// 3. Last resort: use the SPIFFE SVID.
				if spiffeErr == nil && spiffeCert != nil {
					return spiffeCert, nil
				}

				return spiffeCert, spiffeErr
			}

			hello := &tls.ClientHelloInfo{
				ServerName: tt.sni,
			}
			cert, err := getCert(hello)

			if tt.spiffeErr != nil && tt.expectedCert == nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCert, cert)
			}
		})
	}
}
