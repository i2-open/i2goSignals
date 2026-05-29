package main

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
)

// discoverProtectedResource fetches the server's RFC9728 Protected Resource
// Metadata so the CLI can learn the advertised authorization_servers and the
// recommended public client_id.
func discoverProtectedResource(host string) (*model.ProtectedResourceMetadata, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    client := getHttpClient(30 * time.Second)
    return wellKnownSupport.FetchProtectedResourceMetadata(ctx, client, host)
}

// resolveIssuer selects the OAuth issuer (authorization server) to log in
// against. An explicit issuer (from --issuer) always wins. Otherwise, if the
// metadata advertises exactly one authorization server it is used. Multiple
// advertised servers with no explicit choice is ambiguous, and none advertised
// is an error (the caller may fall back to the bootstrap-secret flow).
func resolveIssuer(meta *model.ProtectedResourceMetadata, explicit string) (string, error) {
    if explicit != "" {
        return explicit, nil
    }
    if meta == nil || len(meta.AuthorizationServers) == 0 {
        return "", errors.New("no authorization_servers advertised in protected resource metadata")
    }
    if len(meta.AuthorizationServers) == 1 {
        return meta.AuthorizationServers[0], nil
    }
    return "", fmt.Errorf("multiple authorization servers advertised (%v); specify one with --issuer", meta.AuthorizationServers)
}

// resolveClientId selects the public OAuth client_id. An explicit value (from
// --client-id) always wins; otherwise the advertised client_id is used.
func resolveClientId(meta *model.ProtectedResourceMetadata, explicit string) string {
    if explicit != "" {
        return explicit
    }
    if meta != nil && meta.ClientID != nil {
        return *meta.ClientID
    }
    return ""
}

// oidcEndpoints carries the discovered OIDC/OAuth endpoints for an issuer.
type oidcEndpoints struct {
    Authorization string
    Token         string
    Issuer        string
    // DeviceAuthorization is the RFC 8628 device authorization endpoint, when
    // advertised. Empty if the issuer does not support the device-code grant.
    DeviceAuthorization string
}

// discoverEndpoints fetches the issuer's OpenID Provider configuration to learn
// its authorization and token endpoints.
func discoverEndpoints(issuer string) (*oidcEndpoints, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    client := getHttpClient(30 * time.Second)
    cfg, err := wellKnownSupport.FetchOpenIDConfiguration(ctx, client, issuer)
    if err != nil {
        return nil, err
    }
    if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
        return nil, fmt.Errorf("issuer %s did not advertise authorization/token endpoints", issuer)
    }
    return &oidcEndpoints{
        Authorization:       cfg.AuthorizationEndpoint,
        Token:               cfg.TokenEndpoint,
        Issuer:              cfg.Issuer,
        DeviceAuthorization: cfg.DeviceAuthEndpoint,
    }, nil
}
