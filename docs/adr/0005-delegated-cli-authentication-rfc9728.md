<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Delegated CLI authentication via RFC 9728 (no built-in AS)

The `goSignals` CLI authenticates a human against a server's management plane by
**delegating** to an external OAuth/OIDC authorization server, discovered through
the server's **RFC 9728 Protected Resource Metadata (PRM)**. goSignals does not
ship its own authorization server, browser-based login UI, or password store. It
is purely an OAuth *protected resource*: it advertises which authorization
servers it trusts and which public client the CLI should use, and validates the
access tokens those authorization servers issue (`OAUTH_SERVERS` →
`I2SIG_AUTH_OAUTH_SERVERS`, validated in
`internal/authUtil/auth_token.go:ValidateAuthorizationAny`).

The login flow (`cmd/goSignals/login.go`, `discovery.go`, `device.go`):

1. `add server <alias>` is **connect-only**. It does SSF discovery, fetches the
   PRM (`/.well-known/oauth-protected-resource`), and caches the advertised
   `authorization_servers` on the local server record. It mints no credential.
2. `login <alias>` fetches the PRM, resolves the issuer (the sole advertised AS,
   or `--issuer`) and the public `client_id`
   (`buildProtectedResourceMetadata` advertises `I2SIG_CLI_CLIENT_ID`, default
   `gosignals-cli`, or `--client-id`), then discovers the issuer's OpenID
   Provider configuration.
3. With a browser and a bindable loopback listener available, it runs a
   `docker login`-style **OAuth authorization code + PKCE** flow (RFC 6749 /
   RFC 7636) over an ephemeral `127.0.0.1` listener with a CSRF `state`.
4. On a headless host (no browser, or no bindable loopback), or with `--device`,
   it falls back to the **RFC 8628 device-code** flow
   (`selectLoginMethod` in `device.go`).
5. The resulting session (access + refresh token, identity claims) is stored
   per-issuer in `credentials.json` (mode `0600`), separate from `config.json`.
   Management calls present the access token, silently refreshing via the
   RFC 6749 refresh-token grant (`cmd/goSignals/bearer.go`); `logout` makes a
   best-effort RFC 7009 revocation.

Sessions are keyed by **issuer (realm)**, not by server alias, so a single login
serves every server that trusts that realm, and one server may accumulate
sessions across several realms (last-login-wins active-issuer defaulting,
`cmd/goSignals/realm.go:selectIssuerForServer`).

## Status

Accepted. Shipped across PRD #120 slices #122 (single-realm PKCE), #124
(device-code fallback), #125 (multi-realm sessions / `whoami` / `logout` /
`use server`).

## Considered options

- **Build a first-party authorization server / password login into goSignals.**
  Rejected: re-implements a security-critical component (token issuance, MFA,
  account lifecycle, brute-force protection) that mature IdPs already provide;
  contradicts the project's role as an SSF *protected resource*; and forces every
  deployment to manage another credential store. Delegating to Keycloak (or any
  OIDC AS) is strictly less code and less attack surface.
- **Long-lived static admin tokens pasted into the CLI (`--token` only).**
  Rejected as the *primary* path: long-lived bearer tokens on disk are a standing
  liability, can't be silently refreshed, and give no per-user identity for
  audit. Retained as a *non-interactive* escape hatch for SSF servers and CI.
- **A device-code-only flow for every host.** Rejected: the loopback PKCE flow is
  a materially better UX on a desktop (no copy-paste of a user code), so the CLI
  prefers it and only falls back to device-code when the host can't support it.
- **Out-of-band issuer/client configuration on the CLI (flags or a config file
  the operator fills in).** Rejected as the default: the server already knows
  which AS it trusts, so advertising it via RFC 9728 PRM removes a configuration
  step and a class of mismatched-issuer errors. `--issuer`/`--client-id` remain
  as overrides.

## Consequences

- goSignals must advertise PRM (`ProtectedResourceMetadataHandler` in
  `internal/server/api_out_of_band.go`) and validate externally-issued access
  tokens — it already does both, routing by token `kid`.
- The CLI gains an OAuth client implementation (PKCE, device-code, refresh,
  revocation) but no server-side auth code; the protocol libraries stay free of
  `internal/` imports.
- Tokens never land in `config.json`; only the non-secret active issuer and
  advertised servers are cached there. `credentials.json` is `0600`.
- A deployment must run/trust an OIDC AS and configure
  `I2SIG_AUTH_OAUTH_SERVERS` (+ optionally `I2SIG_CLI_CLIENT_ID`). Where no human
  or AS is available (CI, demo bootstrap), the bootstrap-secret path
  (ADR 0006) covers the gap.
- Operator-facing documentation lives in [`docs/cli_login.md`](../cli_login.md)
  and [`docs/security_model.md`](../security_model.md); this ADR is the design
  record.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
