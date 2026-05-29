package main

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func strp(s string) *string { return &s }

func TestResolveIssuer_SingleAdvertised(t *testing.T) {
    meta := &model.ProtectedResourceMetadata{
        AuthorizationServers: []string{"https://idp.example.com"},
    }
    iss, err := resolveIssuer(meta, "")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if iss != "https://idp.example.com" {
        t.Errorf("expected single advertised issuer, got %q", iss)
    }
}

func TestResolveIssuer_ExplicitOverridesAdvertised(t *testing.T) {
    meta := &model.ProtectedResourceMetadata{
        AuthorizationServers: []string{"https://a.example.com", "https://b.example.com"},
    }
    iss, err := resolveIssuer(meta, "https://b.example.com")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if iss != "https://b.example.com" {
        t.Errorf("explicit --issuer should win, got %q", iss)
    }
}

func TestResolveIssuer_MultipleWithoutExplicitIsAmbiguous(t *testing.T) {
    meta := &model.ProtectedResourceMetadata{
        AuthorizationServers: []string{"https://a.example.com", "https://b.example.com"},
    }
    if _, err := resolveIssuer(meta, ""); err == nil {
        t.Errorf("expected ambiguity error when multiple AS and no --issuer")
    }
}

func TestResolveIssuer_NoneIsError(t *testing.T) {
    meta := &model.ProtectedResourceMetadata{}
    if _, err := resolveIssuer(meta, ""); err == nil {
        t.Errorf("expected error when no authorization_servers advertised")
    }
}

func TestResolveClientId_AdvertisedUsedWhenNoOverride(t *testing.T) {
    meta := &model.ProtectedResourceMetadata{ClientID: strp("gosignals-cli")}
    if got := resolveClientId(meta, ""); got != "gosignals-cli" {
        t.Errorf("expected advertised client_id, got %q", got)
    }
}

func TestResolveClientId_OverrideWins(t *testing.T) {
    meta := &model.ProtectedResourceMetadata{ClientID: strp("gosignals-cli")}
    if got := resolveClientId(meta, "my-client"); got != "my-client" {
        t.Errorf("expected override client_id, got %q", got)
    }
}

func TestDiscoverEndpoints_CapturesDeviceAuthorizationEndpoint(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{
            "issuer":"https://idp.example.com",
            "authorization_endpoint":"https://idp.example.com/auth",
            "token_endpoint":"https://idp.example.com/token",
            "device_authorization_endpoint":"https://idp.example.com/device"
        }`))
    }))
    defer srv.Close()

    ep, err := discoverEndpoints(srv.URL)
    if err != nil {
        t.Fatalf("discoverEndpoints failed: %v", err)
    }
    if ep.DeviceAuthorization != "https://idp.example.com/device" {
        t.Errorf("expected device_authorization_endpoint to be discovered, got %q", ep.DeviceAuthorization)
    }
}
