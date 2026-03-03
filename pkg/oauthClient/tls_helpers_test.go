package oauthClient

import (
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTlsConfigForServer_NilServer(t *testing.T) {
	config := GetTlsConfigForServer(nil)
	assert.NotNil(t, config)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.RootCAs)
}

func TestGetTlsConfigForServer_NoCustomConfig(t *testing.T) {
	server := &model.Server{
		Alias:          "test-server",
		TLSCertificate: "",
		TLSSkipVerify:  false,
	}
	config := GetTlsConfigForServer(server)
	assert.NotNil(t, config)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.RootCAs)
}

func TestGetTlsConfigForServer_SkipVerify(t *testing.T) {
	server := &model.Server{
		Alias:         "test-server",
		TLSSkipVerify: true,
	}
	config := GetTlsConfigForServer(server)
	assert.NotNil(t, config)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.RootCAs)
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
	// Should return empty config on error
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.RootCAs)
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
	// RootCAs should not be set when SkipVerify is true
	assert.Nil(t, config.RootCAs)
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
