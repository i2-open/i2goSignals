<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 26. OAuth Authorization Server Metadata discovery reflects the configured AS (proxy)

Date: 2026-06-23

## Status

Accepted (GH #209 follow-up).
Builds on ADR 0001 (per-service Keycloak clients — OAuth delegated to an external
authorization server), ADR 0023 (local-issuer addressing), and the GH #209
local-rooted-then-bare issuer resolution.

## Context

goSignals is an SSF transmitter / **resource server**. It does not run an OAuth
authorization server of its own: the authorization grant and access-token
issuance are delegated to an external authorization server (Keycloak in the
reference deployment — ADR 0001). goSignals already *consumes* RFC 8414 OAuth
2.0 Authorization Server Metadata as a client (`pkg/oauthClient`
`discoverTokenEndpoint`) and advertises the external `authorization_servers` via
RFC 9728 Protected Resource Metadata at `/.well-known/oauth-protected-resource`.

A concurrent cleanup (this branch) moved the OAuth metadata
(`authorization_servers`, `scopes_supported`, `bearer_methods_supported`) *out*
of the SSF Transmitter Configuration document, where it never belonged, leaving
RFC 9728 PRM as its home. What remained absent was the RFC 8414 discovery surface
itself: a client that resolved
`/.well-known/oauth-authorization-server[/{issuer}]` against goSignals got a
`404`, even though goSignals knows exactly which authorization server it is bound
to.

goSignals *does* implement a partial authorization-server surface for the bearer
tokens it mints itself (stream-management / rotate-on-GET tokens — ADR 0022):
`/introspect`, `/revoke`, `/register`, and its JWKS. But it has no
`authorization_endpoint` or `token_endpoint` — those live on the configured
external AS.

So "what should goSignals say at `/.well-known/oauth-authorization-server`?"
splits on whether an external AS is configured. The interesting case is the
common one: when Keycloak is configured, the information a client actually needs
is about the **currently configured authorization server**, not about goSignals.

## Decision

Serve RFC 8414 metadata at `/.well-known/oauth-authorization-server` and
`/.well-known/oauth-authorization-server/{issuer:.+}`, with two behaviors keyed
off whether an external authorization server is configured
(`AuthIssuer.GetOAuthServers()`):

1. **External AS configured → reflect it verbatim (a discovery proxy).** goSignals
   fetches the configured authorization server's RFC 8414 document
   (`oauth-authorization-server`, falling back to the OpenID Provider
   `openid-configuration` — Keycloak serves both) and returns the **raw JSON
   unmodified**. The client thereby learns the real AS's `issuer`,
   `authorization_endpoint`, and `token_endpoint`, and talks to it directly.
   Passthrough is lossless (`json.RawMessage`): no field of the upstream document
   is dropped through a narrower local struct.

2. **No external AS → advertise goSignals' own partial surface.** A small RFC 8414
   document carrying only what goSignals implements directly —
   `introspection_endpoint`, `revocation_endpoint`, `registration_endpoint`,
   `jwks_uri`, and `scopes_supported` — and **deliberately no**
   `authorization_endpoint` / `token_endpoint`, so the document never advertises a
   grant capability goSignals cannot honor.

The optional `{issuer}` path segment is resolved with the **same
local-rooted-then-bare lookup** SSF §7.2.1 discovery and JWKS serving use
(`resolveIssuerKeyName`, GH #209): a path-bearing variant must address a
registered issuer or `404` — it never synthesizes metadata for an unknown issuer.
The bare endpoint describes the default issuer.

A configured-but-unreachable authorization server returns **502 Bad Gateway**,
not the self-document: claiming to be the authorization server when goSignals is
not would be misleading.

## Considered alternatives

- **302-redirect to the upstream AS's well-known.** Standard, and keeps goSignals
  out of the data path, but many OAuth clients do not follow redirects on metadata
  fetches, and it leaks the upstream URL structure. Rejected in favor of a
  same-origin reflect.
- **Composite document** — merge the upstream AS's `token`/`authorization`
  endpoints with goSignals' own `introspection`/`revocation`/`registration`. More
  "helpful" but it fabricates a single authorization server out of two distinct
  issuers, reintroducing exactly the §7.2.4-style issuer-binding ambiguity the
  rest of this work removes. Deferred; verbatim passthrough is the v1.
- **Synthesize a full self-AS document always.** Dishonest — goSignals would
  advertise `authorization_endpoint`/`token_endpoint` it does not serve.

## Consequences

**Positive**

- A client doing RFC 8414 discovery against goSignals now learns the real,
  currently-configured authorization server — the proxy behavior asked for —
  rather than a `404`.
- The partial self-document is honest: it advertises only the token-management
  surface goSignals actually implements.
- Issuer resolution is identical across `ssf-configuration`, JWKS, and
  `oauth-authorization-server`: any segment that serves a key also discovers, and
  unknown issuers `404` uniformly (GH #209 parity extended).
- Purely additive — a new endpoint plus one reusable
  `wellKnownSupport.FetchOAuthAuthorizationServerRaw`; no existing route or
  contract changes.

**Negative / accepted trade-offs**

- The proxy fetches the upstream document per discovery request (no caching in
  v1). Discovery is low-frequency, so acceptable; a short-TTL cache can be added
  later if needed.
- Availability coupling: when an AS is configured, discovery depends on that AS
  being reachable (surfaced as a 502 rather than masked).
- With multiple configured authorization servers only the first is reflected; the
  multi-AS shape is left for a later iteration.

## Related

- GH #209 — local-rooted-then-bare issuer resolution shared by discovery/JWKS.
- ADR 0001 — per-service Keycloak clients (OAuth delegated to an external AS).
- ADR 0022 — rotate-on-GET bearer rotation (the tokens goSignals introspects/revokes).
- ADR 0023 — local-issuer addressing (`{issuer}` path resolution, RFC 8615 insertion).
- RFC 8414 — OAuth 2.0 Authorization Server Metadata.
- RFC 9728 — OAuth 2.0 Protected Resource Metadata (`/.well-known/oauth-protected-resource`).
- `internal/server/api_out_of_band.go` — `WellKnownOAuthAuthorizationServerHandler`,
  `buildAuthorizationServerMetadata`, `fetchUpstreamAuthorizationServerMetadata`.
- `pkg/wellKnownSupport/well_known.go` — `FetchOAuthAuthorizationServerRaw`.
- `pkg/ssfModels/model_authorization_server_metadata.go` — `AuthorizationServerMetadata`.
