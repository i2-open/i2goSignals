package goSet

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rsaJWK(key *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}
}

func signedToken(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://issuer.example"})
	token.Header["kid"] = kid
	encoded, err := token.SignedString(key)
	require.NoError(t, err)
	return encoded
}

func TestGetJwksRefreshesOnUnknownKIDAfterRollover(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var mu sync.RWMutex
	keys := []map[string]string{rsaJWK(oldKey, "issuer-old")}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
	}))
	defer server.Close()

	jwks, err := GetJwks(server.URL)
	require.NoError(t, err)
	_, err = jwt.Parse(signedToken(t, oldKey, "issuer-old"), jwks.Keyfunc)
	require.NoError(t, err)

	mu.Lock()
	keys = []map[string]string{rsaJWK(oldKey, "issuer-old"), rsaJWK(newKey, "issuer-new")}
	mu.Unlock()

	_, err = jwt.Parse(signedToken(t, newKey, "issuer-new"), jwks.Keyfunc)
	require.NoError(t, err)
	mu.RLock()
	defer mu.RUnlock()
	assert.GreaterOrEqual(t, requests, 2, "unknown kid must trigger a JWKS refresh")
}
