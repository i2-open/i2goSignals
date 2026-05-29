<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# The `key` scope and closing anonymous `/iat`

Historically `GET /iat` was **anonymous**: any unauthenticated caller could mint
an Initial Access Token and thereby start a project and register a client. That
is a standing un-authenticated write surface. This ADR records (a) closing that
door and (b) introducing a narrow `key` scope so unattended deployments can still
bootstrap themselves without it.

## Closing anonymous `/iat`

`GET /iat` and `POST /key/<issuer>` now require a bearer with one of
`{key, admin, root}` (`IssuerProjectIatHandler` / `CreateKeyHandler` in
`internal/server/api_out_of_band.go`, via
`ValidateAuthorizationAny([]string{ScopeKey, ScopeStreamAdmin, ScopeRoot})`).
A missing or invalid bearer is rejected. There is no longer an
unauthenticated path to either endpoint — the change **fails closed**.

## The `key` scope

`authSupport.ScopeKey` (`"key"`, `pkg/authSupport/auth_token.go`) is a new scope
sitting **between `reg` and `admin`**:

- A `key`-scoped caller may mint a **new** issuer signing key, but a key
  **takeover** — `force=replace`, `force=rotate`, or `?rotate` — is denied for a
  caller that holds *only* `key` (no `admin`/`root`). The guard is `keyScopeOnly`
  + `requestIsKeyTakeover` in `api_out_of_band.go:CreateKeyHandler`. This prevents
  substituting an attacker key under an existing issuer and forging events.
- A `key`-scoped caller may obtain an IAT, but the minted IAT is always
  **`reg`-only** — `IssueProjectIat` always sets `Roles: [reg]`. The
  key/admin capability does not propagate into the IAT.
- `key` carries **no** stream/event capability.

`reg` itself is privilege-ceilinged at the registration door: a `reg` caller's
self-registration caps at `stream`+`event` (`RegisterClientHandler` silently
drops `admin`/unknown scopes). The tiers form a ladder — `key` → `reg` →
`stream`/`event`, with `admin` provisioned out of band.

## The bootstrap secret as the `key`-scope grant

The shared secret `I2SIG_BOOTSTRAP_TOKEN` is how an unattended deployment obtains
`key` scope without a JWT. `AuthIssuer.resolveBootstrapBearer`
(`internal/authUtil/bootstrap_resolver.go`) runs **before** any JWT/kid
classification in `ValidateAuthorizationAny`: a presented bearer that
**constant-time-equals** the configured secret is synthesized into a `key`-scope
`AuthContext`. When the env var is unset, the resolver short-circuits and returns
`nil` (so an empty bearer can never match an empty secret) — the bootstrap path is
closed. The PRM advertises `key` among `scopes_supported`.

The secret is an **app-layer** authorization mechanism, independent of and
coexisting with transport-layer identity (TLS / SPIFFE mTLS): SPIFFE secures the
connection, the secret authorizes the narrow capability.

## Status

Accepted. Shipped in PRD #120 slice #121, generalized across all compose variants
in slice #123. The demo stacks bootstrap via `config/scim/scripts/register.sh` +
`auto-reg.gosignals` using `I2SIG_BOOTSTRAP_TOKEN`.

## Considered options

- **Keep `/iat` anonymous.** Rejected: an un-authenticated endpoint that creates
  projects and registration tokens is an obvious abuse and resource-exhaustion
  vector, and is incompatible with the delegated-auth model (ADR 0005).
- **Require full `admin` for `/iat` and `/key`.** Rejected: forces an unattended
  bootstrap (CI, init container, demo `scimSsfSetup`) to either run a human login
  or hold an over-broad admin credential. The whole point of `key` is to grant
  *exactly* "seed an issuer key + a reg IAT" and nothing more.
- **Let the bootstrap secret grant `admin`/`root`.** Rejected: a shared static
  secret with full administrative power is too dangerous; capping it at create-only
  `key` (no takeover, no stream/event, reg-only IAT) bounds the blast radius if the
  secret leaks.
- **A dedicated bootstrap endpoint instead of reusing `/iat` + `/key`.**
  Rejected: needless new surface; the existing endpoints already do exactly what
  bootstrap needs once they require a credential, and the scope check is the right
  place to express "create-only".

## Consequences

- New scope constant `ScopeKey`; `IsScopeMatch`/`IsAuthorized` continue to treat
  `root` as a superset.
- `CreateKeyHandler` gains the takeover guard; `IssuerProjectIatHandler` accepts
  `{key, admin, root}` and always mints `reg`-only IATs.
- A new fail-closed code path (`resolveBootstrapBearer`) runs ahead of JWT
  validation; an unset secret accepts no bootstrap bearer.
- Deployments must set `I2SIG_BOOTSTRAP_TOKEN` (server **and** CLI/automation env)
  to bootstrap unattended; the demo default `dev-bootstrap-secret` is for demos
  only and must be replaced in production.
- IAT default lifetime tightened to 24h (`I2SIG_IAT_LIFETIME`,
  `defaultIatLifetime` in `auth_token.go`), down from a hard-coded 90 days —
  IATs are short-lived bootstrap credentials.
- Operator-facing documentation lives in
  [`docs/security_model.md`](../security_model.md) and
  [`docs/cli_login.md`](../cli_login.md); this ADR is the design record.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
