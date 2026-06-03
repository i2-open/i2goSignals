<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 12. Authorization scope checks read shape-aware predicates, not `AuthContext.Eat`

Date: 2026-06-02

## Status

Accepted

## Context

External OIDC bearer-token validation (`validateOAuthToken` in
`internal/authUtil/auth_token.go`) returns `Eat: nil` for **every** OAuth/STS
caller — the granted scopes live elsewhere on the `AuthContext`. Several
authorization gates read scope directly off `AuthContext.Eat`, so they silently
misbehaved for every OAuth caller regardless of the scope the AS actually
granted. This bug class bit three times:

- **#128** — token-admin endpoints (`GET /token`, `DELETE /token/{jti}`,
  `POST /introspect`) were no-ops for an admin caller whose token came via
  STS/OAuth (the GoSignalsAdmin console): `ProjectScope` derived "admin sees
  all" from `Eat`, and `ProjectScope(nil)` fell through to the fail-closed
  empty-project branch.
- **#139** — `tx_alias` stream-create returned an opaque 403 to an OAuth admin.
- **#150** — the same denial against a *foreign* transmitter.

In the worst case the `Eat`-only shape did not merely deny — the create-only key
guard (`keyScopeOnly`) returned `false` for OAuth callers (`Eat == nil`), which
*exempted* an OAuth key-only caller from the guard and granted full key
takeover: a latent privilege escalation.

Separately (#144), external bearer validation accepted any signing algorithm,
never checked audience, and honoured a foreign realm role literally named `root`
as a cluster-wide grant.

## Decision

**Never scope-check via `AuthContext.Eat` directly.** Two shape-aware predicates
in `internal/authUtil/auth_token.go` are the only sanctioned way to scope-check a
caller:

- `AuthContext.HasScope(scopes...)` — OR semantics; reads `GrantedScopes` for
  OAuth callers and the EAT for local tokens.
- `AuthContext.IsAuthorizedForStream(streamId, scopes...)` — the stream-bound
  companion; preserves the EAT's stream-id binding for local tokens and reduces
  to `HasScope` for OAuth callers (the bearer carries no per-stream bind).

Supporting decisions:

- **OAuth-granted scopes are recorded on `AuthContext.GrantedScopes`**, and
  `services.ProjectScope` takes the whole `*AuthContext` (not just the EAT) so an
  OAuth `admin` grant earns the unrestricted token-admin view. `ProjectScope` is
  the single source of truth for list/revoke/introspect. Fail-closed posture is
  preserved: a non-admin OAuth caller still sees nothing.
- **OAuth callers are gated on `admin`, never on a foreign `root`.** The root
  super-power is reserved for our own locally issued tokens; an external token
  with a role literally named `root`/`admin` does not escalate. Consistent across
  #128, #144, and #150.
- **`tx_alias` provisioning needs `admin` OR the full `reg`+`stream`+`event`
  set.** A `tx_alias` stream drives a remote stream's entire lifecycle (create,
  start, poll), so a partial subset is not enough. Plain (non-`tx_alias`) stream
  create is unchanged and still accepts any of `reg`/`stream`/`admin`. `reg` is a
  first-class create scope, not a legacy IAT-only path.
- **OAuth bearer validation is hardened** (#144): the signing-algorithm
  allow-list is pinned to the asymmetric set (`RS*`, `PS*`, `ES*`) via
  `jwt.WithValidMethods`, explicitly excluding symmetric `HS*` to close
  algorithm-confusion; audience is enforced via `jwt.WithAudience` when
  `I2SIG_AUTH_OAUTH_AUDIENCE` is configured (fail-open with a one-time WARN when
  unset, to preserve existing deployments); the bare-`root`-role shortcut is
  removed for external tokens only.
- **The `scope` claim is a single space-separated string, never an array**
  (Keycloak interop). The Go backend (`OidcClaims`, `EventAuthToken`) will not
  parse array-valued `scope`; issuers must emit the OIDC-compliant string form
  (the `gosignals` realm uses a script-based protocol mapper to join roles into a
  space-separated string).

The three direct-`Eat` sites migrated onto the predicates are the `tx_alias`
gate (`canProvisionTxAlias`), the `StreamUpdate` payload re-check, and the
create-only key guard (`keyScopeOnly`).

## Consequences

**Positive**

- One house pattern; the `Eat == nil` denial/exemption class is closed at the
  predicate layer rather than at each call site.
- The `keyScopeOnly` migration closed the latent OAuth key-takeover escalation
  (locked by `TestKeyScopeOnly`).
- Algorithm-confusion is closed even for JWKS that omit `alg`, and audience
  pinning is available as an opt-in.

**Negative**

- A `tx_alias` or token-admin flow that previously used a non-admin OAuth/IAT
  credential now needs `admin` (or the full `reg`+`stream`+`event` set for
  tx_alias). Intended tightening, but a behavioural change.
- Audience is fail-open-with-WARN, so a deployment that does not set
  `I2SIG_AUTH_OAUTH_AUDIENCE` gets defence-in-depth on algorithm but not on
  audience until it opts in.

## Related

- ADR 0009 — foreign-server provisioning requires admin (the `/server` and
  `tx_alias` rule this anchors to).
- ADR 0006 — the scope ladder (`key` → `reg` → `stream`/`event`, `admin` out of
  band).
- Issues #128, #139, #144, #150.
- `internal/authUtil/auth_token.go` — `HasScope`, `IsAuthorizedForStream`,
  `GrantedScopes`, `validateOAuthToken`; `docs/security_model.md` — endpoint →
  scope table.
