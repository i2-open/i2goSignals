<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# GoSignals Security Model

## Shared Signals Framework and GoSignals
The current model is based on the OpenID SSF specification, which enables clients to register to receive events. 
The client may be given an Initial Access Token (IAT) which permits registration. When successful, the client receives
a permanent token used to retrieve events and manage its stream. Of particular note, the SSF endpoints
use a common endpoint with no direct stream identifier; instead, the stream identifier is typically encoded in the access token.

## Management plane vs data plane

goSignals authorization splits into two planes:

- **Management plane** — administering a server: defining streams, creating
  issuer keys, minting IATs, registering clients. Authorized by either a
  delegated-OAuth user session (interactive humans) or the shared bootstrap
  secret / configured admin token (automation).
- **Data plane** — moving events: a transmitter pushing SETs, a receiver polling
  for them. Authorized by per-stream/per-client tokens carrying the
  `stream`/`event` scopes, scoped to a project.

The two are independent. Logging in (management plane) never grants event
delivery, and a stream's delivery token cannot administer the server.

## Authorization scopes

The server recognises a small set of scopes (roles claim or OAuth `scope`
claim; `root` matches everything):

| Scope    | Constant            | Capability |
| :------- | :------------------ | :--------- |
| `event`  | `ScopeEventDelivery`| Deliver / receive events on a stream (data plane). |
| `stream` | `ScopeStreamMgmt`   | Manage a stream's own configuration (data plane / self-service). |
| `reg`    | `ScopeRegister`     | Register a client using an IAT. Capped at `stream`+`event` — a `reg` caller cannot self-grant `admin`. |
| `key`    | `ScopeKey`          | **Create a new issuer signing key, and obtain a `reg`-only IAT.** Create-only: denied key takeover. No stream/event capability. |
| `admin`  | `ScopeStreamAdmin`  | Full project administration (management plane). |
| `root`   | `ScopeRoot`         | Superset; matches every scope check. |

### The `key` scope and machine tiers

`key` is a narrow capability sitting between `reg` and `admin`, intended for an
unattended deployment that must bootstrap itself without a human:

- A `key`-scoped caller may `POST /key/<issuer>` to mint a **new** issuer signing
  key, but a key **takeover** (`force=replace`, `force=rotate`, or `?rotate`) is
  rejected for a key-scope-only caller — preventing key substitution / event
  forgery.
- A `key`-scoped caller may `GET /iat` to obtain an IAT, but the minted IAT is
  always **`reg`-only**: the `key`/admin capability does not propagate into it.

This is the machine tier ladder: a bootstrap identity (`key`) seeds an issuer key
and a `reg` IAT; the `reg` IAT registers a client that caps at `stream`+`event`;
`admin` clients are provisioned out of band, not through the registration door.

### Foreign-server provisioning (endpoint → scope)

Provisioning a *foreign* SSF transmitter is a privileged, management-plane
operation and requires `admin` (`root` rides free). See ADR 0009.

| Endpoint | Required scope |
| :------- | :------------- |
| `POST/GET/PUT/DELETE /server`, `GET /server` (list) | `admin` (`root` free) — `reg`/`stream` are rejected. |
| `POST /stream` **without** `tx_alias` | `stream` (base `reg`/`stream`/`admin` gate) — the SCIM-receiver / unattended-IAT-bootstrap local-only path, unchanged. |
| `POST /stream` **with** `tx_alias` | `admin` (`root` free) — resolves a stored foreign-server credential and provisions a stream remotely. |

The `/server` endpoints stay distinct from `/stream` (they are not folded into
stream creation) so a foreign transmitter's credential keeps an independent
lifecycle, which goSignalsAdmin's console depends on.

### The bootstrap secret

`I2SIG_BOOTSTRAP_TOKEN` is a shared secret. On the server, a bearer that
**constant-time-equals** the configured value is synthesized into a `key`-scope
context before any JWT validation runs. When the variable is **unset**, the
bootstrap path is closed and no bootstrap bearer is ever accepted (fail closed).
The bootstrap secret is an app-layer authorization mechanism: it is orthogonal to
transport-layer identity (TLS / SPIFFE mTLS) and coexists with it.

> [!IMPORTANT]
> **The anonymous `/iat` endpoint is removed.** `GET /iat` now requires a
> `{key, admin, root}` bearer; a missing/invalid bearer is rejected. With
> `I2SIG_BOOTSTRAP_TOKEN` unset there is no door at all — the endpoint fails
> closed. `POST /key` likewise requires `{key, admin, root}`.

The advertised public client for the interactive CLI login is named by
`I2SIG_CLI_CLIENT_ID` (default `gosignals-cli`) in the server's RFC 9728
Protected Resource Metadata, which also advertises the supported scopes
(including `key`).

## GoSignals Command Line

The `goSignals` CLI authorizes management calls one of two ways, detailed in the
[CLI Login Guide](cli_login.md):

1. **Delegated OAuth login** — `add server <alias>` connects to a server
   (connect-only, no credential minted) and caches its advertised OAuth
   authorization servers; `login <alias>` then runs a browser PKCE (or
   device-code) flow and stores a per-realm session in `credentials.json`.
   Subsequent management calls present that session's access token, silently
   refreshing it as needed.
2. **Non-interactive bootstrap** — for CI/automation, `I2SIG_BOOTSTRAP_TOKEN`
   (or a configured `--token`/`--client-secret`/`--iat`) authorizes
   `create key` / `create iat` directly.

```shell
goSignals> add server gs1 https://goSignals1:8888
goSignals> login gs1
```

## Docker Compose Set Up

In the demo scenario, there are 2 SCIM servers configured to run as replicas with
synchronization carried out via goSignals. Both SCIM servers in the cluster use
goSignals1:8888 as the common events server, so an event issued by one is
received by the replica for synchronization.

The SCIM servers need an issuer key and an IAT to auto-register. The
`scimSsfSetup` service runs the goSignals CLI **unattended** using the bootstrap
secret (`I2SIG_BOOTSTRAP_TOKEN`, injected by compose). The `key`-scope secret
authorizes `create key` + `create iat` without any anonymous endpoint
(`config/scim/scripts/auto-reg.gosignals`):

```shell
add server gosignals1 https://goSignals1:8888
add server gosignals2 https://goSignals2:8889
create iat gosignals1 --output=/scim/iat-gosignals1.jwt
create bundle --output=/scim/spire-bundle.pem
create key gosignals1 cluster.scim.example.com --file=/scim/cluster-scim-issuer.pem
exit
```

When complete, the setup script distributes the minted issuer key and IAT to the
`scim_cluster1` / `scim_cluster2` data directories; on startup those services
auto-register with goSignals1. The six compose variants (base / dev / cluster /
cluster-dev / spiffe / spiffe-dev) all wire the bootstrap secret the same way;
see the [CLI Login Guide](cli_login.md#3-docker-compose-variant-matrix) for the
full matrix.

## Limitations

The current goSignals command line only knows about streams that is has configured to facilitate a demo. 
At present the `show server` command only shows the locally known information and streams. For example, you might choose to 
create a push receiver on goSignals2 and a push publisher on goSignals1 using the `create push connection` command. If you specify
the same audience as the SCIM cluster, you will find that goSignals1 starts automatically forwarding events to goSignals2.
You can monitor the events by creating a poll publisher on goSignals2 and then using the poll command to display incoming events
to the command line utility.

## SPIFFE/SPIRE Mutual TLS

As part of a defense-in-depth strategy, i2goSignals supports [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone)
for cryptographic workload identity, implemented via [SPIRE](https://spiffe.io/docs/latest/spire-about/)
and the [`go-spiffe`](https://github.com/spiffe/go-spiffe) library. SPIFFE **augments** the existing
HMAC and OAuth2 mechanisms; deployments without SPIRE continue to operate unchanged.

### What SPIFFE Replaces

| Concern | Without SPIFFE | With SPIFFE |
|---|---|---|
| Inter-cluster wake-up calls | HMAC shared secret (`I2SIG_CLUSTER_INTERNAL_TOKEN`) | X.509-SVID mutual TLS; HMAC retained as fallback |
| SSF stream management (outbound) | OAuth2 CC or static token | SPIFFE mTLS (if `SpiffeConfig` set on server record) |
| MongoDB connections | Username/password | X.509-SVID client certificate (opt-in via `I2SIG_SPIFFE_MONGO_ENABLED`) |

### How It Works

Each node requests its SVID (a short-lived X.509 certificate with a SPIFFE URI SAN) from the
local SPIRE agent via the Workload API. The go-spiffe library watches for rotations automatically;
no restarts are required when SVIDs expire.

**Inter-cluster communication (WakeTransmitter):**
When `SPIFFE_ENDPOINT_SOCKET` is set, the event router builds an mTLS HTTP transport for outbound
wake-up calls using the node's SVID. The receiving `WakeTransmitter` handler checks whether the
TLS connection carries a peer certificate. If the certificate is a valid SVID belonging to the
cluster trust domain (`I2SIG_SPIFFE_TRUST_DOMAIN`), the request is accepted without an HMAC token. If
no certificate is presented, the existing HMAC path is used. This allows a phased rollout.

**SSF stream management (oauthClient):**
Setting `SpiffeConfig` on a `Server` database record causes `GetClientForServer()` to build a
SPIFFE mTLS client. The remote server's SPIFFE ID or trust domain is used to authorize the peer.
If the SPIRE agent is unavailable, the function falls through to OAuth2 or static token auth.

**MongoDB mTLS:**
When `I2SIG_SPIFFE_MONGO_ENABLED=true` and `SPIFFE_ENDPOINT_SOCKET` is set, the MongoDB driver is
configured to use the node's SVID as the client certificate. MongoDB must be configured with the
SPIRE CA bundle as the trusted root. Falls back to password auth if SPIRE is unavailable.

### SPIRE Federation

[SPIRE federation](https://spiffe.io/docs/latest/architecture/federation/readme/) extends the
trust model across organizational boundaries, enabling SPIFFE mTLS for SSF streams that cross
domain boundaries. See [`docs/spiffe_support_plan.md`](spiffe_support.md) and
[`config/spire/registration/register.sh`](../config/spire/registration/register.sh) for setup
instructions.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | _(unset)_ | SPIRE agent socket path. Enables all SPIFFE features. |
| `I2SIG_SPIFFE_TRUST_DOMAIN` | `cluster.i2gosignals.internal` | Trust domain for cluster peer verification. |
| `I2SIG_SPIFFE_MONGO_ENABLED` | `false` | Enable SPIFFE mTLS for MongoDB. |

See [`docs/configuration_properties.md`](configuration_properties.md) for full details.

## SSF §9 Subject Filtering Security Posture

The OpenID Shared Signals Framework §9 raises three security concerns about the
subject-filtering endpoints. goSignals' posture is summarised below; the
removal-grace mitigation that addresses §9.3 is implemented by the PRD #97
work and is described in [`CONTEXT.md`](../CONTEXT.md) ("Removal grace
period"), with the env var and per-stream override in
[`configuration_properties.md`](configuration_properties.md) and the storage
shape in [`adr/0003-split-subject-filter-storage.md`](adr/0003-split-subject-filter-storage.md).

### §9.1 Subject Probing

§9.1 warns that a receiver can use Add Subject as an oracle to test whether a
subject is known to the transmitter — a `404 subject not found` response is the
attacker's signal. goSignals offers no such oracle:

- It maintains **no subject directory** to probe. The local per-stream filter
  table is opt-in delivery state, not a record of "subjects known to the
  transmitter"; populating it is the receiver's own act.
- `Add Subject` is treated as a **statement of interest**, not a directory
  lookup. The server records the subject and returns `200` regardless of
  whether the subject has ever been seen on the wire (`defaultSubjects` is
  policy, not a delivery guarantee — see PRD #89).
- The endpoints' only `404` is **feature-disabled** (subject filtering is not
  enabled server-wide, the endpoints are not advertised in discovery, and the
  router refuses to honour them). It is a capability statement, not a
  per-subject answer, and so is not a probing oracle.

### §9.1 on the Relay Path

When a downstream receiver Adds or Removes a subject on a `PASSTHRU` or
`HYBRID` stream, goSignals relays the change to the upstream transmitter.
That upstream may have its own §9.1 mitigation and may answer `404` (or any
other 4xx/5xx). goSignals **logs the upstream response at `WARN` and returns
success to the downstream receiver** — surfacing the upstream status verbatim
would re-create the §9.1 oracle goSignals itself does not expose. The local
filter write (for `HYBRID`) and the receiver's expression of interest are
authoritative; the upstream subscription is best-effort. The receiver's
request is never failed by an upstream's §9.1 posture.

### §9.2 Information Harvesting

§9.2 warns that an attacker who has compromised a receiver can harvest events
by registering subjects of interest and waiting for delivery. goSignals does
not solve this — it is a property of the receiver's authorization model — but
its design contains the blast radius:

- A receiver token is scoped to a single stream; a compromised receiver cannot
  enumerate or harvest from another stream's filter.
- Subject filtering is **opt-in server-wide** (`I2SIG_SUBJECT_FILTERING`), so
  deployments that do not want the harvesting surface can disable it
  entirely.
- The review endpoint that exposes filter state is bound to the goSignals
  **admin scope**, distinct from the per-stream receiver scope used by the
  SSF Add/Remove endpoints. A compromised receiver cannot read the filter.

Active mitigations (rate-limiting Add Subject, anomaly detection on filter
growth) are out of scope.

### §9.3 Malicious Subject Removal

§9.3 — instant blinding by a malicious or coerced subject removal — is
addressed by the removal-grace mechanism described in
[`CONTEXT.md`](../CONTEXT.md) ("Removal grace period"). A removal stamps the
affected filter entry with `enforceAt = now + grace`; delivery continues for
the grace window so a hostile removal cannot blind a receiver instantly. The
grace defaults to zero (no behaviour change unless the operator opts in); the
`I2SIG_SUBJECT_REMOVAL_GRACE` server-wide default and per-stream override are
documented in [`configuration_properties.md`](configuration_properties.md),
and the storage shape (sparse `enforce_at` index, lazy-purge lifecycle) is in
[`adr/0003-split-subject-filter-storage.md`](adr/0003-split-subject-filter-storage.md).

## Token administration

The server tracks the management-plane tokens it issues (IATs and
stream/client tokens) so an operator can inventory, introspect, and revoke
them. The CLI surface is documented in
[gosignals_tool.md](gosignals_tool.md#token-administration); the durable
decisions are recorded in
[ADR 0007](adr/0007-track-token-redemption-not-issuance.md) and
[ADR 0008](adr/0008-two-revocation-endpoints.md).

- **Inventory — `GET /token`.** Caller-scoped: the project scope is derived
  from the caller's `AuthContext` (admin/root see every project; everyone else
  is confined to their own project) and is **never** taken from a
  client-supplied query parameter. Supports composable `type=IAT|STREAM` and
  `active=true|false` filters. Each row is enriched with provenance.
- **Provenance — redemption, not issuance (ADR 0007).** A token record carries
  `last_redemption_ip` / `last_redemption_at` / `redemption_count` and an
  immediate-`parent` JTI (an IAT is the lineage root; a stream-client token's
  parent is the redeemed IAT; a delivery token's parent is the issuing
  stream-client token). Recording redemption is best-effort — a failed write
  logs at WARN and never blocks the operation.
- **Introspection — `POST /introspect` (RFC 7662).** Reports `active`, the
  RFC 7662 `token_type`, scopes, and the additive provenance extensions. A
  cross-project, unknown, expired, or revoked target reports `active:false` —
  no existence oracle.
- **Revocation — two endpoints (ADR 0008).**
  `DELETE /token/{jti}` is the admin-by-identifier path (revoke a named token
  you can see in the inventory); a non-admin caller acting on another project's
  token gets `403`. `POST /revoke` is the RFC 7009 self-service path where a
  token holder presents the token string; per RFC 7009 §2.2 it **always**
  returns HTTP 200 (unknown / already-revoked / expired / unparseable /
  cross-project all look identical), so token existence is never leaked.
- **Auto-expiry.** Expired records age out of the token collection via a
  MongoDB TTL index measured from the token's `exp`, retained for
  `I2SIG_TOKEN_RETENTION` (default 30 days). A revoked-but-unexpired record
  stays visible (reporting `active:false`) until retention lapses, keeping
  revocations auditable. Mongo-only; see
  [configuration_properties.md](configuration_properties.md).

## Inbound bearer-token validation (OAuth audience + algorithm allow-list)

goSignals accepts two kinds of bearer token on its management and SSF endpoints:
**locally issued** tokens minted by this cluster (project IATs, ADMIN tokens —
HMAC-signed against the cluster's own key) and **external OIDC** tokens issued by
a third-party IdP and validated against the discovery URLs in
`I2SIG_AUTH_OAUTH_SERVERS`. The hardening below (issue #144) applies to the
**external** path only — `validateOAuthToken` in
`internal/authUtil/auth_token.go`. Locally issued tokens are unaffected.

External tokens are subject to three controls.

### 1. Audience enforcement

When `I2SIG_AUTH_OAUTH_AUDIENCE` is set, an external token whose `aud` claim does
not contain that value is rejected (`jwt.WithAudience`). This stops a token
minted for some *other* relying party in the same IdP from being replayed
against goSignals (the token-substitution / confused-deputy case).

When the variable is **unset**, audience is not checked and a one-time `WARN` is
logged:

```
OAuth audience validation is DISABLED (I2SIG_AUTH_OAUTH_AUDIENCE unset);
external OIDC tokens are accepted without an aud check
```

This **fail-open-with-warning** default preserves existing deployments that
configured `I2SIG_AUTH_OAUTH_SERVERS` without an audience. **Operators running
external OIDC in production should set `I2SIG_AUTH_OAUTH_AUDIENCE`** to the value
their IdP stamps for goSignals; leaving it unset is a known-weaker posture, not a
supported steady state.

### 2. Signing-algorithm allow-list (algorithm-confusion defense)

External OIDC tokens are restricted to **asymmetric** signing algorithms —
`RS256/384/512`, `PS256/384/512`, `ES256/384/512` — and symmetric HMAC (`HS*`) is
rejected (`jwt.WithValidMethods`). The security property is *excluding `HS*`*,
which closes the classic JWT algorithm-confusion attack (an attacker re-signing a
token with `HS256` using the IdP's public key as the HMAC secret). Allowing the
full asymmetric set, rather than pinning a single variant, avoids breaking
legitimate non-Keycloak IdPs that sign with ECDSA or RSA-PSS.

This is **defense-in-depth**: the JWKS keyfunc already rejects HS256 (it returns
an `*rsa.PublicKey`, so HMAC verification fails on key type), but
`WithValidMethods` rejects the algorithm *before* the keyfunc runs and so closes
the gap even for a JWKS that omits the `alg` parameter.

### 3. No bare-`root` escalation from foreign realms

`oidcRolesMatchScopes` requires an external token's realm role to match the
specific accepted scope name. A foreign-realm role literally named `root`
(`authSupport.ScopeRoot`) **no longer** confers cluster-wide privilege — a
third-party-administered IdP must not be able to escalate into goSignals simply
by defining a role with a privileged-sounding name. The `root` super-power
remains intentional and unchanged for goSignals' **own** locally issued tokens
(`EventAuthToken.IsScopeMatch`).

The environment variables are catalogued in
[configuration_properties.md](configuration_properties.md#auth); the decision
record is [ADR 0012](adr/0012-scope-checks-via-hasscope-not-eat.md).

## Admin UI Issues

The current command line stores local state and tokens in a local configuration file. The use of tokens for stream management 
is influenced by the SSF specification itself.  When building the admin UI, we need to implement more traditional access control
and API design so we can do things like list all streams.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
