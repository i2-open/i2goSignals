package oauthClient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTlsConfigForServer_NilServer(t *testing.T) {
	t.Setenv("AUTH_DEBUG", "")
	config := GetTlsConfigForServer(nil)
	assert.NotNil(t, config)
	assert.False(t, config.InsecureSkipVerify)
	// RootCAs must be seeded from the global CA pool (system roots + ca-cert.pem),
	// never left nil. See issue #220.
	assert.NotNil(t, config.RootCAs)
}

func TestGetTlsConfigForServer_NoCustomConfig(t *testing.T) {
	t.Setenv("AUTH_DEBUG", "")
	server := &model.Server{
		Alias:          "test-server",
		TLSCertificate: "",
		TLSSkipVerify:  false,
	}
	config := GetTlsConfigForServer(server)
	assert.NotNil(t, config)
	assert.False(t, config.InsecureSkipVerify)
	// Core regression for issue #220: a server with no per-server cert and
	// TLSSkipVerify=false must still load the global CA pool (ca-cert.pem), so
	// RootCAs must be non-nil rather than an empty &tls.Config{}.
	assert.NotNil(t, config.RootCAs)
}

func TestGetTlsConfigForServer_SkipVerify(t *testing.T) {
	server := &model.Server{
		Alias:         "test-server",
		TLSSkipVerify: true,
	}
	config := GetTlsConfigForServer(server)
	assert.NotNil(t, config)
	assert.True(t, config.InsecureSkipVerify)
	// RootCAs is still seeded from the global pool even though skip-verify ignores it.
	assert.NotNil(t, config.RootCAs)
}

func TestGetTlsConfigForServer_CustomCertificate(t *testing.T) {
	// This is a test certificate - in real scenarios it would be a valid PEM cert
	pemCert := `-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxzyYw
ln/hMYBnJ6dUwwcVdGsyWvJhxq3uQf5cBY7lP3HzME6q8G/KWHB8VuVmrOhkQ7hx
P1JT2eMb
-----END CERTIFICATE-----`

	server := &model.Server{
		Alias:          "test-server",
		TLSCertificate: pemCert,
	}
	config := GetTlsConfigForServer(server)
	assert.NotNil(t, config)
	assert.False(t, config.InsecureSkipVerify)
	assert.NotNil(t, config.RootCAs)
}

func TestGetTlsConfigForServer_InvalidCertificate(t *testing.T) {
	server := &model.Server{
		Alias:          "test-server",
		TLSCertificate: "invalid-pem-data",
	}
	config := GetTlsConfigForServer(server)
	assert.NotNil(t, config)
	// On append failure we fall back to the global pool rather than dropping all
	// trust, so RootCAs stays non-nil (the global CA pool). See issue #220.
	assert.False(t, config.InsecureSkipVerify)
	assert.NotNil(t, config.RootCAs)
}

func TestGetBaseHTTPClientForServer_NilServer(t *testing.T) {
	client := GetBaseHTTPClientForServer(nil)
	assert.NotNil(t, client)
	assert.NotNil(t, client.Transport)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestGetBaseHTTPClientForServer_WithSkipVerify(t *testing.T) {
	server := &model.Server{
		Alias:         "test-server",
		TLSSkipVerify: true,
	}
	client := GetBaseHTTPClientForServer(server)
	assert.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestGetBaseHTTPClientForServer_WithCustomCert(t *testing.T) {
	pemCert := `-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxzyYw
ln/hMYBnJ6dUwwcVdGsyWvJhxq3uQf5cBY7lP3HzME6q8G/KWHB8VuVmrOhkQ7hx
P1JT2eMb
-----END CERTIFICATE-----`

	server := &model.Server{
		Alias:          "test-server",
		TLSCertificate: pemCert,
	}
	client := GetBaseHTTPClientForServer(server)
	assert.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestCreateCertPool_ValidPEM(t *testing.T) {
	pemCert := `-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxzyYw
ln/hMYBnJ6dUwwcVdGsyWvJhxq3uQf5cBY7lP3HzME6q8G/KWHB8VuVmrOhkQ7hx
P1JT2eMb
-----END CERTIFICATE-----`

	pool, err := CreateCertPool(pemCert)
	assert.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestCreateCertPool_InvalidPEM(t *testing.T) {
	pool, err := CreateCertPool("not-a-valid-pem")
	assert.Error(t, err)
	assert.Nil(t, pool)
}

func TestParsePEMCertificate_ValidPEM(t *testing.T) {
	pemCert := `-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxzyYw
ln/hMYBnJ6dUwwcVdGsyWvJhxq3uQf5cBY7lP3HzME6q8G/KWHB8VuVmrOhkQ7hx
P1JT2eMb
-----END CERTIFICATE-----`

	cert, err := ParsePEMCertificate(pemCert)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.IsType(t, &x509.Certificate{}, cert)
}

func TestParsePEMCertificate_InvalidPEM(t *testing.T) {
	cert, err := ParsePEMCertificate("not-a-valid-pem")
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestParsePEMCertificate_WrongBlockType(t *testing.T) {
	// This is a private key, not a certificate
	pemKey := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5VYT7Xj/GZAih
-----END PRIVATE KEY-----`

	cert, err := ParsePEMCertificate(pemKey)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "not a certificate")
}

func TestParseCertificateInfo(t *testing.T) {
	pemCert := `-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxzyYw
ln/hMYBnJ6dUwwcVdGsyWvJhxq3uQf5cBY7lP3HzME6q8G/KWHB8VuVmrOhkQ7hx
P1JT2eMb
-----END CERTIFICATE-----`

	cert, err := ParsePEMCertificate(pemCert)
	require.NoError(t, err)

	info := ParseCertificateInfo(cert)
	assert.NotNil(t, info)
	assert.NotEmpty(t, info.Subject)
	assert.NotEmpty(t, info.Issuer)
	assert.NotEmpty(t, info.Fingerprint)
	assert.NotEmpty(t, info.PEM)
	assert.NotEmpty(t, info.SerialNumber)
	assert.False(t, info.ValidFrom.IsZero())
	assert.False(t, info.ValidTo.IsZero())
}

func TestGetTlsConfigForServer_PrecedenceSkipVerifyOverCert(t *testing.T) {
	// If both SkipVerify and Certificate are set, SkipVerify should take precedence
	pemCert := `-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxzyYw
ln/hMYBnJ6dUwwcVdGsyWvJhxq3uQf5cBY7lP3HzME6q8G/KWHB8VuVmrOhkQ7hx
P1JT2eMb
-----END CERTIFICATE-----`

	server := &model.Server{
		Alias:          "test-server",
		TLSCertificate: pemCert,
		TLSSkipVerify:  true,
	}

	config := GetTlsConfigForServer(server)
	assert.NotNil(t, config)
	assert.True(t, config.InsecureSkipVerify)
	// RootCAs is still seeded from the global pool; skip-verify simply bypasses it.
	assert.NotNil(t, config.RootCAs)
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedHost string
		expectedPort string
	}{
		{"HTTPS URL with port", "https://example.com:8443", "example.com", "8443"},
		{"HTTPS URL without port", "https://example.com", "example.com", "443"},
		{"HTTP URL with port", "http://example.com:8080", "example.com", "8080"},
		{"Host with port no scheme", "example.com:9000", "example.com", "9000"},
		{"Host without port", "example.com", "example.com", "443"},
		{"URL with path", "https://example.com:8443/some/path", "example.com", "8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseHostPort(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

// generateCAAndLeaf creates a self-signed CA certificate (returned as PEM) plus a
// leaf certificate signed by that CA (returned parsed). Because the leaf chains to
// the CA, verifying the leaf against a pool proves the CA is trusted in that pool.
func generateCAAndLeaf(t *testing.T, cn string) (caPEM string, leaf *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn + "-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn + "-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return caPEM, leaf
}

// TestGetTlsConfigForServer_AppendsToGlobalPoolWithoutDiscarding is the central
// fix for issue #220: a per-server TLSCertificate must be APPENDED to the global
// CA pool (system roots + ca-cert.pem), not REPLACE it. We wire a temp project CA
// via I2SIG_TLS_CA_CERT and pin a distinct per-server CA, then assert both are
// trusted by the resulting RootCAs pool.
func TestGetTlsConfigForServer_AppendsToGlobalPoolWithoutDiscarding(t *testing.T) {
	t.Setenv("AUTH_DEBUG", "")

	// A "global/dev CA" written to a temp ca-cert.pem and wired via the env var
	// GetGlobalCertPool consults, mirroring how the project CA is loaded.
	globalCAPem, globalLeaf := generateCAAndLeaf(t, "global")
	caFile := filepath.Join(t.TempDir(), "ca-cert.pem")
	require.NoError(t, os.WriteFile(caFile, []byte(globalCAPem), 0o600))
	t.Setenv("I2SIG_TLS_CA_CERT", caFile)

	// A distinct per-server CA, pinned as the server's TLSCertificate.
	perServerCAPem, perServerLeaf := generateCAAndLeaf(t, "perserver")

	server := &model.Server{Alias: "test-server", TLSCertificate: perServerCAPem}
	config := GetTlsConfigForServer(server)
	require.NotNil(t, config)
	require.NotNil(t, config.RootCAs, "RootCAs must be seeded from the global pool, not nil")
	assert.False(t, config.InsecureSkipVerify)

	// The per-server cert was appended -> its leaf must verify against the pool.
	_, err := perServerLeaf.Verify(x509.VerifyOptions{Roots: config.RootCAs})
	assert.NoError(t, err, "per-server certificate should be appended to the global pool")

	// The global/dev CA must STILL be trusted -> we appended, not replaced.
	_, err = globalLeaf.Verify(x509.VerifyOptions{Roots: config.RootCAs})
	assert.NoError(t, err, "global CA roots must be retained (append, not replace)")
}

// TestGetTlsConfigForServer_AuthDebugEnablesSkipVerify covers the global AUTH_DEBUG
// override: it forces InsecureSkipVerify even when there is no per-server cert and
// TLSSkipVerify is false.
func TestGetTlsConfigForServer_AuthDebugEnablesSkipVerify(t *testing.T) {
	t.Setenv("AUTH_DEBUG", "true")

	server := &model.Server{Alias: "test-server"}
	config := GetTlsConfigForServer(server)
	require.NotNil(t, config)
	assert.True(t, config.InsecureSkipVerify)
	assert.NotNil(t, config.RootCAs)

	// Applies on the nil-server path too.
	nilConfig := GetTlsConfigForServer(nil)
	require.NotNil(t, nilConfig)
	assert.True(t, nilConfig.InsecureSkipVerify)
}

func TestGetTLSConfigIntegrationWithHTTPClient(t *testing.T) {
	// Test that TLS config properly integrates with http.Client
	server := &model.Server{
		Alias:         "test-server",
		TLSSkipVerify: true,
	}

	client := GetBaseHTTPClientForServer(server)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)

	// Verify the config is accessible and correct
	assert.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)

	// Test cloning the transport config
	clonedConfig := transport.TLSClientConfig.Clone()
	assert.NotNil(t, clonedConfig)
	assert.True(t, clonedConfig.InsecureSkipVerify)
}
