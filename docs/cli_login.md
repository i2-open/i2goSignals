<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# goSignals CLI Login &amp; Bootstrap Guide

This guide walks the two ways the `goSignals` CLI authenticates against a
server's **management plane**:

1. **Delegated OAuth login** (`login`) — an interactive, `docker login`-style
   browser flow (RFC 9728 Protected Resource Metadata → OAuth authorization
   code + PKCE, RFC 7636) that produces a per-realm session. This is the path
   for humans.
2. **Unattended bootstrap** (`I2SIG_BOOTSTRAP_TOKEN`) — a shared secret that a
   CI/automation context presents directly as a bearer to mint an issuer signing
   key and an Initial Access Token (IAT). This is the path for scripts and the
   demo compose stacks.

> [!IMPORTANT]
> The anonymous `/iat` endpoint is **closed**. A request to `/iat` (or
> `/key`) with no usable bearer is rejected. Either log in (delegated OAuth)
> or present the bootstrap secret.

See [`security_model.md`](security_model.md) for the underlying auth model and
[`gosignals_tool.md`](gosignals_tool.md) for the full command reference.

---

## 1. Delegated OAuth login (interactive)

This is the end-to-end path from a clean checkout.

### Build the CLI

```shell
make console-build      # builds cmd/goSignals
# or:
go build -o goSignals ./cmd/goSignals
```

### `add server` — connect only

`add server` is **connect-only**: it performs SSF discovery
(`/.well-known/ssf-configuration`), caches the advertised OAuth
`authorization_servers` from the server's Protected Resource Metadata, and
records the server under a local alias. It mints **no** credential.

```shell
goSignals> add server gs1 https://goSignals1:8888
```

On success the CLI prints the discovered authorization server(s) and prompts
you to log in:

```
Discovered authorization server(s): [https://keycloak:9080/realms/gosignals]
Run 'login gs1' to authenticate.
```

If the server advertises no `authorization_servers`, the CLI tells you to use
`--bootstrap` or `--token` instead (the non-interactive paths below).

### `login` — browser PKCE

```shell
goSignals> login gs1
```

The CLI:

1. Fetches the server's RFC 9728 Protected Resource Metadata and resolves the
   issuer (the single advertised authorization server, or `--issuer` if several
   are advertised) and the public `client_id` (advertised, or `--client-id`).
2. Discovers the issuer's OpenID Provider configuration (authorization, token,
   revocation, and device-authorization endpoints).
3. Generates a PKCE `code_verifier`/`code_challenge` (S256) and a CSRF `state`,
   starts an ephemeral `127.0.0.1` loopback listener, and opens your browser at
   the authorization endpoint:

   ```
   Opening browser to log in:
     https://keycloak:9080/realms/gosignals/protocol/openid-connect/auth?...
   ```

4. Receives the authorization-code redirect on the loopback listener, exchanges
   the code (with the PKCE verifier) at the token endpoint, and stores the
   resulting session.

On a **headless host** (no browser / no bindable loopback listener), or when you
pass `--device`, the CLI automatically falls back to the RFC 8628 device-code
flow, printing a verification URL and user code to complete on another device:

```
To complete login, on any device open:
  https://keycloak:9080/realms/gosignals/device?user_code=ABCD-EFGH
Waiting for authorization...
```

Tokens are written to `credentials.json` (mode `0600`) keyed by **issuer**, next
to `config.json`. The non-secret active issuer and advertised servers are cached
on the server record in `config.json`; **tokens are never written to
`config.json`**.

```
Logged in to gs1 as issuer=https://keycloak:9080/realms/gosignals subject=alice <alice@example.com> scopes=[...] expires=... clientId=gosignals-cli
```

### `whoami` — show sessions

With an alias, `whoami` shows the active realm session for that server:

```shell
goSignals> whoami gs1
```

With no alias, it lists every stored realm session (gcloud `auth list`-style),
including which configured server aliases trust each realm:

```shell
goSignals> whoami
2 active realm session(s):
  issuer=https://keycloak:9080/realms/gosignals  subject=alice <alice@example.com>  scopes=[openid email profile]  expires=...  status=valid  servers=[gs1]
```

### Run a management command

Once logged in, management calls present the realm session's access token as the
bearer, silently refreshing it (RFC 6749 refresh-token grant) when expired:

```shell
goSignals> get stream config <streamAlias>
goSignals> create stream push receiver gs1 ...
```

If the session has expired and its refresh token is dead, the CLI surfaces a
clear "re-login required" message — run `login gs1` again.

### `logout`

A realm logout drops the session for that realm everywhere it is used:

```shell
goSignals> logout gs1                 # the server's active issuer
goSignals> logout --issuer https://keycloak:9080/realms/gosignals
goSignals> logout --all               # every stored realm session
```

Logout makes a best-effort RFC 7009 refresh-token revocation against the IdP,
deletes the local session, and clears the `ActiveIssuer` pointer on every server
that referenced that realm. An empty `logout` with no target is an error so you
never accidentally wipe every session.

### Multi-realm sessions

`credentials.json` accumulates one session **per issuer (realm)**. A single
server may trust several realms; `login` adds a session without disturbing
others. Which realm authorizes a call to a given server is resolved as:

1. the server's `ActiveIssuer` pointer, when it has a live session; otherwise
2. the most-recently-logged-in realm the server trusts (**last-login-wins**).

Set the active realm explicitly with `use server`:

```shell
goSignals> use server gs1 --issuer https://keycloak:9080/realms/gosignals
```

A non-advertised issuer is accepted with a warning so manual overrides remain
possible.

---

## 2. Unattended bootstrap (non-interactive)

When there is no human and no browser — CI, the demo compose stacks, an
init container — use the shared **bootstrap secret**. Set
`I2SIG_BOOTSTRAP_TOKEN` on **both** the server (so it accepts the secret) and
the CLI's environment (so it presents it).

On the server, a bearer that constant-time-equals `I2SIG_BOOTSTRAP_TOKEN`
resolves to the narrow **`key` scope**: enough to create a *new* issuer signing
key and obtain a `reg`-only IAT, but **not** to take over an existing key
(`force=replace`/`rotate` is denied) and **not** any stream/event capability.
When `I2SIG_BOOTSTRAP_TOKEN` is unset on the server, the bootstrap path is closed
and no bootstrap bearer is ever accepted (fail closed).

### `add server --bootstrap`

`--bootstrap` opts in to minting an IAT at `add server` time using the secret:

```shell
export I2SIG_BOOTSTRAP_TOKEN=dev-bootstrap-secret
goSignals> add server gs1 https://goSignals1:8888 --bootstrap
```

This presents `Bearer $I2SIG_BOOTSTRAP_TOKEN` to `/iat`, records the returned
`reg`-only IAT on the server entry, and skips client auto-registration.
`--bootstrap` errors out if `I2SIG_BOOTSTRAP_TOKEN` is unset.

### `create key` and `create iat`

`create key` and `create iat` present a bearer resolved as: a configured client
token if one exists, otherwise the `I2SIG_BOOTSTRAP_TOKEN` secret. With neither,
the (now non-anonymous) server rejects the request.

```shell
export I2SIG_BOOTSTRAP_TOKEN=dev-bootstrap-secret
goSignals> create key gs1 cluster.scim.example.com --file=issuer.pem
goSignals> create iat gs1
```

This is exactly what the demo stacks do. The `scimSsfSetup` container exports
`I2SIG_BOOTSTRAP_TOKEN` and runs `config/scim/scripts/auto-reg.gosignals`:

```
add server gosignals1 https://goSignals1:8888
add server gosignals2 https://goSignals2:8889
create iat gosignals1 --output=/scim/iat-gosignals1.jwt
create bundle --output=/scim/spire-bundle.pem
create key gosignals1 cluster.scim.example.com --file=/scim/cluster-scim-issuer.pem
exit
```

### Which credential does each scenario use?

| Scenario                              | Credential presented                                  | Server-side scope |
| :------------------------------------ | :---------------------------------------------------- | :---------------- |
| `login` then management command       | Per-realm OAuth access token (from `credentials.json`)| Whatever the IdP grants the user |
| `add server --bootstrap` → IAT        | `I2SIG_BOOTSTRAP_TOKEN` secret                        | `key` → mints `reg`-only IAT |
| `create key` / `create iat` (no token)| `I2SIG_BOOTSTRAP_TOKEN` secret                        | `key` (create-only) |
| `create key` / `create iat` (token)   | Stored `ClientToken` (`--token`/`--client-secret`)    | as the token's scope |
| `add server --token` / `--iat`        | Supplied admin token / IAT, stored on the server entry| as supplied |

---

## 3. Docker Compose variant matrix

There are six compose variants. All of them share the same auth model — the
bootstrap secret is wired the same way; the SPIFFE variants add transport-layer
mTLS that coexists with (and is independent of) the app-layer bootstrap secret.

| File                              | Adds over base                                                                 | Login &amp; bootstrap behavior |
| :-------------------------------- | :----------------------------------------------------------------------------- | :----------------------------- |
| `docker-compose.yml`              | Base demo: 2 goSignals nodes + `goSsfServer`, MongoDB replica set, Keycloak, Prometheus/Grafana, 2 i2scim nodes. | goSignals nodes read `I2SIG_BOOTSTRAP_TOKEN` + `I2SIG_CLI_CLIENT_ID` from their `config/*.env` files; `scimSsfSetup` injects `I2SIG_BOOTSTRAP_TOKEN` and bootstraps via `register.sh`. Interactive `login` works against the `gosignals` Keycloak realm. |
| `docker-compose-dev.yml`          | Dev image (`i2gosignals-dev`), source mounted, Delve on `2345`/`2346`/`2347`, Loki/Alloy log stack. | Same bootstrap secret; goSignals services additionally set `I2SIG_BOOTSTRAP_TOKEN` + `I2SIG_CLI_CLIENT_ID` inline in compose. Uses `register-dev.sh`. |
| `docker-compose-cluster.yml`      | Nginx load balancer + redundant nodes (`goSignals1`, `goSignals1b`, `goSignals2`, `goSsfServer`) for HA; `I2SIG_CLUSTER_NODE_ID` per node. | Same bootstrap model; `scimSsfSetup` injects `I2SIG_BOOTSTRAP_TOKEN`. Login flows route through the Nginx front door. |
| `docker-compose-cluster-dev.yml`  | Cluster topology on the dev image; `goSsfServer` runs under Delve (`dlv debug … :2345`). | Same as cluster, dev build. |
| `docker-compose-spiffe.yml`       | SPIRE server/agent + workload registration; MongoDB and inter-node calls use SPIFFE X.509-SVID mTLS (`SPIFFE_ENDPOINT_SOCKET`, `I2SIG_SPIFFE_TRUST_DOMAIN`). | SPIFFE secures the **transport**; the app-layer bootstrap secret is **independent** and still required to mint keys/IATs (`I2SIG_BOOTSTRAP_TOKEN` set in `*-spiffe.env`). The two coexist. |
| `docker-compose-spiffe-dev.yml`   | SPIFFE topology on the dev image; Delve on `2345`/`2346`/`2347`, `goSsfServer` under `dlv debug`, `cluster-monitor` via `go run`. | Same as spiffe, dev build. |

> [!NOTE]
> `I2SIG_BOOTSTRAP_TOKEN` defaults to `dev-bootstrap-secret` in the compose
> files (`${I2SIG_BOOTSTRAP_TOKEN:-dev-bootstrap-secret}`). This is a **demo**
> value — set a real secret in production and never commit it.

---

## See also

- [GoSignals Administration Tool](gosignals_tool.md) — full CLI command/flag reference.
- [Security Model](security_model.md) — management-plane vs data-plane auth, the `key` scope, machine tiers.
- [Configuration Properties](configuration_properties.md) — `I2SIG_BOOTSTRAP_TOKEN`, `I2SIG_CLI_CLIENT_ID`, `I2SIG_IAT_LIFETIME`.
