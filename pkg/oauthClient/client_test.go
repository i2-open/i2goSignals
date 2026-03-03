package oauthClient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetHTTPClient_CachingAndContext(t *testing.T) {
	exchangeCount := 0
	// Setup a mock STS server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchangeCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"foo","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	cfg := Config{
		TokenURL:     ts.URL,
		ClientID:     "client",
		ClientSecret: "secret",
	}
	mgr := NewManager(cfg, nil)

	scopes := []string{"scope"}
	resource := "resource"
	token1 := "token-1"

	// 1. Get client with a context that will be cancelled
	ctx1, cancel1 := context.WithCancel(context.Background())
	client1, err := mgr.GetHTTPClient(ctx1, token1, scopes, resource)
	if err != nil {
		t.Fatalf("Failed to get client1: %v", err)
	}

	// 2. Use client1 to trigger initial exchange
	_, err = client1.Get("http://example.com")
	if err != nil && strings.Contains(err.Error(), "context canceled") {
		t.Errorf("Initial request failed with context error: %v", err)
	}
	if exchangeCount != 1 {
		t.Errorf("Expected 1 exchange, got %d", exchangeCount)
	}

	// 3. Cancel the first context
	cancel1()

	// 4. Get client again for the same token - should hit cache
	client2, err := mgr.GetHTTPClient(context.Background(), token1, scopes, resource)
	if err != nil {
		t.Fatalf("Failed to get client2: %v", err)
	}
	if client1 != client2 {
		t.Fatal("Expected cached client")
	}

	// 5. Use client2 - it should work because it uses context.Background() for TokenSource internally
	_, err = client2.Get("http://example.com")
	if err != nil {
		t.Fatalf("Expected client2 to work, but got: %v", err)
	}
	// exchangeCount should still be 1 because the token is cached in ReuseTokenSource
	if exchangeCount != 1 {
		t.Errorf("Expected exchangeCount to be 1 (cached token), got %d", exchangeCount)
	}
}

func TestGetHTTPClient_StaleContextOnInitialFailure(t *testing.T) {
	// Setup a mock STS server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"foo","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	cfg := Config{
		TokenURL:     ts.URL,
		ClientID:     "client",
		ClientSecret: "secret",
	}
	mgr := NewManager(cfg, nil)

	scopes := []string{"scope"}
	resource := "resource"
	token2 := "token-2"

	// 1. Get client with an ALREADY cancelled context
	ctx3, cancel3 := context.WithCancel(context.Background())
	cancel3()
	client3, _ := mgr.GetHTTPClient(ctx3, token2, scopes, resource)

	// 2. Use client3 - it should SUCCEED in getting the token because of context.Background() in TokenSource
	_, err := client3.Get("http://example.com")
	if err != nil && strings.Contains(err.Error(), "context canceled") {
		t.Errorf("Request failed with context error, but should have used Background: %v", err)
	}
}
