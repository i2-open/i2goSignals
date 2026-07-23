package goSetPoll

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeWISETestSET(t *testing.T, key *rsa.PrivateKey, eventURI string, payload map[string]interface{}) (string, string) {
	t.Helper()
	set := goSet.CreateSet(nil, "https://issuer.example.com", []string{"https://aud.example.com"})
	set.AddEventPayload(eventURI, payload)
	token, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return set.ID, token
}

func makeWISETestSETWithKID(t *testing.T, key *rsa.PrivateKey, kid, eventURI string, payload map[string]interface{}) (string, string) {
	t.Helper()
	set := goSet.CreateSet(nil, "https://issuer.example.com", []string{"https://aud.example.com"})
	set.Kid = kid
	set.AddEventPayload(eventURI, payload)
	token, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return set.ID, token
}

func publicRSAJWK(key *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}
}

func TestPollWithWISESemanticValidator(t *testing.T) {
	key := generateTestKey(t)
	jti, token := makeWISETestSET(t, key, events.WISEWorkloadCompromisedURI, map[string]interface{}{
		"subject": map[string]interface{}{
			"format": "uri",
			"uri":    "spiffe://trust.example/ns/prod/sa/payment-service",
		},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PollResponse{Sets: map[string]string{jti: token}})
	}))
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL:       server.URL,
		ExpectedIssuer:    "https://issuer.example.com",
		ExpectedAudiences: []string{"https://aud.example.com"},
		SETValidator:      events.ValidateWISESET,
	})

	require.NoError(t, err)
	assert.Contains(t, parsed.ParsedSETs, jti)
	assert.Empty(t, parsed.Errors)
}

func TestPollWithWISESemanticValidatorReportsMalformedPayload(t *testing.T) {
	key := generateTestKey(t)
	jti, token := makeWISETestSET(t, key, events.WISECredentialCompromiseURI, map[string]interface{}{
		"subject": map[string]interface{}{
			"format": "uri",
			"uri":    "wimse://trust.example/workload/payment-service",
		},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PollResponse{Sets: map[string]string{jti: token}})
	}))
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL:  server.URL,
		SETValidator: events.ValidateWISESET,
	})

	require.NoError(t, err)
	assert.Empty(t, parsed.ParsedSETs)
	require.Contains(t, parsed.Errors, jti)
	assert.Equal(t, "invalid_request", parsed.Errors[jti].Error)
}

func TestPollWithWISESemanticValidatorRefreshesJWKSAfterRollover(t *testing.T) {
	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	var mu sync.RWMutex
	jwksKeys := []map[string]string{publicRSAJWK(oldKey, "issuer-old")}
	jwksRequests := 0
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		jwksRequests++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": jwksKeys})
	}))
	defer jwksServer.Close()

	jwks, err := goSet.GetJwks(jwksServer.URL)
	require.NoError(t, err)
	firstJTI, firstSET := makeWISETestSETWithKID(t, oldKey, "issuer-old", events.WISEWorkloadCompromisedURI, map[string]interface{}{
		"subject": map[string]interface{}{"format": "uri", "uri": "wimse://trust.example/workload/payment-service"},
	})
	secondJTI, secondSET := makeWISETestSETWithKID(t, newKey, "issuer-new", events.WISETrustAnchorChangedURI, map[string]interface{}{
		"subject":      map[string]interface{}{"format": "uri", "uri": "wimse://trust.example"},
		"anchor_type":  "jwks",
		"change_type":  "key_rotated",
		"trust_domain": "trust.example",
	})
	currentJTI, currentSET := firstJTI, firstSET
	pollServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PollResponse{Sets: map[string]string{currentJTI: currentSET}})
	}))
	defer pollServer.Close()
	config := ReceiverConfig{
		EndpointURL:       pollServer.URL,
		JWKS:              jwks,
		ExpectedIssuer:    "https://issuer.example.com",
		ExpectedAudiences: []string{"https://aud.example.com"},
		SETValidator:      events.ValidateWISESET,
	}

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, config)
	require.NoError(t, err)
	assert.Contains(t, parsed.ParsedSETs, firstJTI)

	mu.Lock()
	jwksKeys = []map[string]string{publicRSAJWK(oldKey, "issuer-old"), publicRSAJWK(newKey, "issuer-new")}
	mu.Unlock()
	currentJTI, currentSET = secondJTI, secondSET
	parsed, _, err = Poll(context.Background(), PollRequest{ReturnImmediately: true}, config)
	require.NoError(t, err)
	assert.Contains(t, parsed.ParsedSETs, secondJTI)

	mu.RLock()
	defer mu.RUnlock()
	assert.GreaterOrEqual(t, jwksRequests, 2, "new kid must cause a JWKS refresh")
}
