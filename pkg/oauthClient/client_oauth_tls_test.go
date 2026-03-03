package oauthClient

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGetClientCredentialsHTTPClient_WithTLSConfig(t *testing.T) {
	// Create a test server
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	// Get the test server's certificate
	cert := server.Certificate()
	pemCert := certToPEM(cert)

	// Create a server model with the TLS certificate
	modelServer := &model.Server{
		Alias:          "test-server",
		TLSCertificate: pemCert,
		TLSSkipVerify:  false,
	}

	cfg := Config{
		TokenURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"read", "write"},
	}

	mgr := NewManager(cfg, nil)
	client, err := mgr.GetClientCredentialsHTTPClient(context.Background(), nil, "", modelServer)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// The client should be able to make requests to the HTTPS server
	// (this would fail without proper TLS configuration)
	resp, err := client.Get(server.URL + "/test")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	resp.Body.Close()
}

func TestGetClientCredentialsHTTPClient_WithTLSSkipVerify(t *testing.T) {
	// Create a test TLS server (self-signed cert)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	// Create a server model with TLSSkipVerify enabled
	modelServer := &model.Server{
		Alias:         "test-server",
		TLSSkipVerify: true,
	}

	cfg := Config{
		TokenURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"read", "write"},
	}

	mgr := NewManager(cfg, nil)
	client, err := mgr.GetClientCredentialsHTTPClient(context.Background(), nil, "", modelServer)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Verify the transport has InsecureSkipVerify set
	oauthTransport, ok := client.Transport.(*oauth2.Transport)
	if ok {
		baseTransport, ok := oauthTransport.Base.(*http.Transport)
		if ok {
			assert.NotNil(t, baseTransport.TLSClientConfig)
			assert.True(t, baseTransport.TLSClientConfig.InsecureSkipVerify)
		}
	}

	// The client should be able to make requests even with self-signed cert
	resp, err := client.Get(server.URL + "/test")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	resp.Body.Close()
}

func TestGetClientCredentialsHTTPClient_CachingWithDifferentTLS(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	cfg := Config{
		TokenURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"read"},
	}

	mgr := NewManager(cfg, nil)

	// First call without TLS config
	client1, err := mgr.GetClientCredentialsHTTPClient(context.Background(), []string{"read"}, "", nil)
	assert.NoError(t, err)

	// Trigger token fetch
	_, _ = client1.Get("http://example.com")
	assert.Equal(t, 1, callCount)

	// Second call with same params should return cached client
	client2, err := mgr.GetClientCredentialsHTTPClient(context.Background(), []string{"read"}, "", nil)
	assert.NoError(t, err)
	assert.Same(t, client1, client2)

	// Token should be cached, no new call
	_, _ = client2.Get("http://example.com")
	assert.Equal(t, 1, callCount)
}

func TestGetClientCredentialsClient_GlobalCaching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	cfg := Config{
		TokenURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"read"},
	}

	ctx := context.Background()

	// First call
	client1, err := GetClientCredentialsClient(ctx, cfg, nil)
	assert.NoError(t, err)
	_, _ = client1.Get("http://example.com")
	assert.Equal(t, 1, callCount)

	// Second call with same config should use cached manager and client
	client2, err := GetClientCredentialsClient(ctx, cfg, nil)
	assert.NoError(t, err)
	assert.Same(t, client1, client2)
	_, _ = client2.Get("http://example.com")
	assert.Equal(t, 1, callCount) // Token still cached
}

func TestGetClientCredentialsHTTPClient_TokenEndpointUsesTLS(t *testing.T) {
	// This test verifies that the token endpoint requests use the server's TLS config
	tokenCallMade := false
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCallMade = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	// Get the test server's certificate
	cert := tokenServer.Certificate()
	pemCert := certToPEM(cert)

	modelServer := &model.Server{
		Alias:          "test-server",
		TLSCertificate: pemCert,
	}

	cfg := Config{
		TokenURL:     tokenServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"read"},
	}

	mgr := NewManager(cfg, nil)
	client, err := mgr.GetClientCredentialsHTTPClient(context.Background(), nil, "", modelServer)
	assert.NoError(t, err)

	// Make a request that will trigger token fetch
	_, _ = client.Get("http://example.com")

	// Verify the token endpoint was called
	assert.True(t, tokenCallMade, "Token endpoint should have been called")
}

func TestValidateClientCredentials_WithTLSConfig(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	cert := server.Certificate()
	pemCert := certToPEM(cert)

	modelServer := &model.Server{
		Alias:          "test-server",
		TLSCertificate: pemCert,
	}

	cfg := Config{
		TokenURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	err := ValidateClientCredentials(context.Background(), cfg, modelServer)
	assert.NoError(t, err)
}

func TestGetClientCredentialsHTTPClient_NilServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	cfg := Config{
		TokenURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	mgr := NewManager(cfg, nil)
	client, err := mgr.GetClientCredentialsHTTPClient(context.Background(), nil, "", nil)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Should work fine with default TLS config
	_, err = client.Get("http://example.com")
	assert.NoError(t, err)
}

func TestClientCredentialsSource_UsesTLSClient(t *testing.T) {
	// Verify that the clientCredentialsSource uses the TLS-configured HTTP client
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	cert := tokenServer.Certificate()
	pemCert := certToPEM(cert)

	modelServer := &model.Server{
		Alias:          "test-server",
		TLSCertificate: pemCert,
	}

	cfg := Config{
		TokenURL:     tokenServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	mgr := NewManager(cfg, nil)
	client, err := mgr.GetClientCredentialsHTTPClient(context.Background(), nil, "", modelServer)
	require.NoError(t, err)

	// Accessing the token source will trigger a token fetch
	// If TLS is not properly configured, this will fail
	resp, err := client.Get("http://example.com")
	assert.NoError(t, err)
	if resp != nil {
		resp.Body.Close()
	}
}

// Helper function to convert a certificate to PEM format
func certToPEM(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	info := ParseCertificateInfo(cert)
	return info.PEM
}

func TestGetClientCredentialsHTTPClient_ResourceScopeFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	cfg := Config{
		TokenURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"default-scope"},
		Resource:     "default-resource",
	}

	mgr := NewManager(cfg, nil)

	// Test with no scopes/resource provided - should use defaults
	client, err := mgr.GetClientCredentialsHTTPClient(context.Background(), nil, "", nil)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Test with explicit scopes/resource
	client2, err := mgr.GetClientCredentialsHTTPClient(context.Background(), []string{"custom-scope"}, "custom-resource", nil)
	assert.NoError(t, err)
	assert.NotNil(t, client2)

	// Should be different clients due to different cache keys
	assert.NotSame(t, client, client2)
}

func TestGetClientCredentialsHTTPClient_TransportBaseIsConsistent(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	cert := server.Certificate()
	pemCert := certToPEM(cert)

	modelServer := &model.Server{
		Alias:          "test-server",
		TLSCertificate: pemCert,
	}

	cfg := Config{
		TokenURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	mgr := NewManager(cfg, nil)
	client, err := mgr.GetClientCredentialsHTTPClient(context.Background(), nil, "", modelServer)
	require.NoError(t, err)

	// Check that the oauth2.Transport base transport has the correct TLS config
	oauthTransport, ok := client.Transport.(*oauth2.Transport)
	if ok {
		baseTransport, ok := oauthTransport.Base.(*http.Transport)
		if ok {
			require.NotNil(t, baseTransport.TLSClientConfig)
			require.NotNil(t, baseTransport.TLSClientConfig.RootCAs)
		}
	}
}
