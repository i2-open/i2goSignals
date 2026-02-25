package oauthclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientCredentialsFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		assert.NoError(t, err)
		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))
		assert.Equal(t, "read write", r.FormValue("scope"))
		assert.Equal(t, "my-aud", r.FormValue("audience"))
		assert.Equal(t, "my-res", r.FormValue("resource"))

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
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		Audience:     "my-aud",
		Resource:     "my-res",
		Scopes:       []string{"read", "write"},
	}

	err := ValidateClientCredentials(t.Context(), cfg)
	assert.NoError(t, err)
}

func TestDiscoverTokenURL(t *testing.T) {
	// Mock AS
	asServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_endpoint": "http://as.example.com/token",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer asServer.Close()

	// Mock Resource
	resServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_servers": []string{asServer.URL},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer resServer.Close()

	tokenURL, err := DiscoverTokenURL(t.Context(), resServer.URL)
	assert.NoError(t, err)
	assert.Equal(t, "http://as.example.com/token", tokenURL)
}

func TestGetClientCredentialsClient_Caching(t *testing.T) {
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
		ClientID:     "my-client",
		ClientSecret: "my-secret",
	}

	ctx := t.Context()
	client1, err := GetClientCredentialsClient(ctx, cfg)
	assert.NoError(t, err)

	_, err = client1.Get("http://example.com")
	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)

	client2, err := GetClientCredentialsClient(ctx, cfg)
	assert.NoError(t, err)
	assert.Same(t, client1, client2)

	_, err = client2.Get("http://example.com")
	assert.NoError(t, err)
	// callCount should still be 1 because the token is cached
	assert.Equal(t, 1, callCount)
}

func TestConfig_key(t *testing.T) {
	c1 := Config{TokenURL: "u", ClientID: "id", ClientSecret: "s", Scopes: []string{"a", "b"}}
	c2 := Config{TokenURL: "u", ClientID: "id", ClientSecret: "s", Scopes: []string{"b", "a"}}
	c3 := Config{TokenURL: "u", ClientID: "id", ClientSecret: "s2", Scopes: []string{"a", "b"}}

	assert.Equal(t, c1.key(), c2.key())
	assert.NotEqual(t, c1.key(), c3.key())
}
