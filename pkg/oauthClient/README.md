<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# STS Token Handling

This package provides a small client helper that performs RFC 8693 token exchange to obtain an access token for downstream APIs and returns an `http.Client` that automatically refreshes tokens when they expire.

Environment variables (used by `DefaultManager()`):
- `STS_TOKEN_URL` — OAuth2 token endpoint that supports token exchange and refresh
- `STS_CLIENT_ID` — OAuth client ID for the exchange
- `STS_CLIENT_SECRET` — OAuth client secret for the exchange
- `STS_AUDIENCE` — optional audience parameter sent to the token endpoint
- `STS_RESOURCE` — optional default resource parameter sent to the token endpoint; can be overridden per call

Usage from a handler:

```go
// r is *http.Request inside a handler in package server
accessToken, _ := AccessTokenFromContext(r.Context())
scopes := []string{"signals.read", "signals.write"}
resource := "https://api.signals.example.com" // protected resource identifier (per RFC8707)
httpClient, err := oauthclient.GetClient(r.Context(), accessToken, scopes, resource)
if err != nil {
    // handle error
}
// use httpClient to call downstream APIs; it auto-injects Authorization and refreshes tokens
```

Caching: the manager caches `http.Client` instances per (subject access token + scopes + resource) tuple to avoid repeat exchanges across requests and to isolate tokens for different resources.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub><img src="../../brand/logo/gosignals-favicon-simple.svg" width="12" height="12" alt="goSignals"> (C)2026 Independent Identity Inc.</sub></p>
