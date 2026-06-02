<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Hands-on Guide: Experimental Shared Signals Framework (SSF) on Keycloak with Docker

This guide gets you from zero to a working Keycloak SSF transmitter that emits CAEP and RISC Security Event Tokens (SETs) over **both** PUSH (RFC 8935) and POLL (RFC 8936) to a receiver client you register yourself.

> [!IMPORTANT]
> **What ships today vs. what is on hold.** The pieces that ship in the
> i2goSignals CLI today are the ones you need to point **goSignals** at a
> Keycloak SSF transmitter: `add server --client-id` (stage a foreign SSF
> transmitter for the OAuth client-credentials grant) and
> `create stream poll receive --tx-alias` (auto-register and wire a POLL
> receiver). These are PRD #83 slices #85/#86, merged in #134, and the
> end-to-end goSignals flow is in [§5c](#5c-point-gosignals-at-the-keycloak-ssf-transmitter-shipped-cli-path).
>
> The PRD #83 work that turns Keycloak into a *bundled* SSF transmitter in the
> demo docker-compose stacks — the Keycloak PoC-extension image, the auto-wiring
> of goSignals2 as a POLL receiver on `make run`, and the dev/cluster-stack
> extension (issues **#84 / #87 / #88**) — is **on hold and not yet available**,
> pending a Keycloak release with native SSF support. This guide therefore
> describes the **manual** Keycloak setup (the identitytailor PoC you stand up
> yourself), not a turnkey `make run` target.

> **Honesty note up front.** Two pieces of information in this guide could not be fetched verbatim from source and are reconstructed from the SSF 1.0 spec + the identitytailor PoC's design doc / README: (a) the exact contents of the PoC's `requests/*.http` files (the GitHub `requests/` directory listing was blocked by `robots.txt`), and (b) some admin-UI tab/label names. Wherever I'm reconstructing rather than quoting, I say so explicitly. The HTTP request shapes shown follow OpenID SSF 1.0 Final §7.1 and the design doc's published endpoint table, which the PoC implements — but you should double-check against the PoC sources before using these in production.

---

## 1. Which path is runnable today: PoC vs. upstream feature flag

**Recommendation: use the [`identitytailor/keycloak-ssf-support`](https://github.com/identitytailor/keycloak-ssf-support) PoC.** It is the only path that does **not** require building Keycloak itself from source.

Context from the two community discussions:

* **keycloak/keycloak#14217 — "Support RISC and CAEP events / Shared Signals and Events"** is the long-running tracking discussion (open since 2022). In it Thomas Darimont explicitly says he created the identitytailor PoC because "adding SSF support to Keycloak directly posed a bit of a challenge, as it was unclear how SSF should be adopted." Side-comments in the same thread make it clear authentik shipped an SSF transmitter in 2025 while Keycloak still had not.
* **keycloak/keycloak#28427 — "Shared Signals Framework support"** is a smaller Q&A discussion (April 2024) asking the same question for the Apple Business / School Manager use case; it was closed with "I suggest closing this discussion and upvoting #14217."

| | identitytailor PoC | Upstream `Profile.Feature.SSF` |
|---|---|---|
| Distribution | Self-contained extension JAR loaded into a stock `quay.io/keycloak/keycloak` image | Lives on a feature branch in `keycloak/keycloak` (per the design doc, branch `issue/gh-xxx-ssf-tx-support-v1`) |
| Status (May 2026) | Working PoC, repo last touched 2026, 27 commits, ships a `docker-compose.yml` and an importable `ssf-demo` realm | Not in any released Keycloak. As of mid-May 2026, PRs labelled `area/ssf` are still being opened (e.g. PR #48943, "SSF: Track stream origin via ManagedBy marker", opened 12 May 2026). The latest Keycloak release is 26.6.1 (April 2026); its release notes make no mention of SSF |
| Keycloak version required | 26.1.4 per the repo's README; the committed `docker-compose.yml` actually pins `quay.io/keycloak/keycloak:26.4.0` (use that — it works and is what CI tests against) | Whatever HEAD is on the SSF branch; you'd need a JDK + Maven + a full `./mvnw clean install` of the whole tree |
| Activation | Drop the JAR into `/opt/keycloak/providers` — the SPI files register everything automatically. `KC_FEATURES=ssf` is **not** required for the PoC | `--features=ssf` (preview) plus a realm-level "transmitter enabled" attribute |
| Endpoints exposed | `/.well-known/ssf-configuration`, `/realms/{realm}/ssf/transmitter/streams`, etc. — same wire-level shape the design doc describes | Same |

So: the PoC is the right answer today for "I want to play with SSF without a Keycloak build environment." The upstream design doc on the gist (last touched 6 May 2026) is the right answer for "I want to know what the supported, in-tree implementation will look like once it lands."

---

## 2. Project layout and the docker-compose stack

Create a working directory and clone the PoC into it:

```bash
mkdir keycloak-ssf-demo && cd keycloak-ssf-demo
git clone https://github.com/identitytailor/keycloak-ssf-support.git
cd keycloak-ssf-support
```

The repo already ships its own `docker-compose.yml`. Reproduced below verbatim from `main` at the time of writing — note the image is `26.4.0` even though the README says 26.1.4. Use 26.4.0; that is what the JAR is built against on `main`.

```yaml
# docker-compose.yml  (identitytailor/keycloak-ssf-support, main)
services:
  keycloak-db:
    image: postgres:15.7
    environment:
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak
      POSTGRES_DB: keycloak
    command:
      - "-c"
      - "shared_preload_libraries=pg_stat_statements"
      - "-c"
      - "pg_stat_statements.track=all"
      - "-c"
      - "max_connections=200"
    ports:
      - "45432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
      interval: 10s
      timeout: 5s
      retries: 5
    volumes:
      - keycloak-db-data:/var/lib/postgresql/data:z

  keycloak:
    image: quay.io/keycloak/keycloak:26.4.0
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: admin
      KC_FEATURES: preview,workflows
      KC_SPI_EVENTS_LISTENER_WORKFLOW_EVENT_LISTENER_STEP_RUNNER_TASK_INTERVAL: 1000
      KC_LOG_LEVEL: INFO,com.identitytailor.keycloak:debug
      KC_HTTP_RELATIVE_PATH: "auth"
      KC_HOSTNAME_URL: https://id.acme.test:1443/auth
      KC_PROXY_HEADERS: xforwarded
      KC_TLS_HOSTNAME_VERIFIER: ANY
      KC_DB: postgres
      KC_DB_URL_PROPERTIES: "?ApplicationName=keycloak"
      KC_DB_URL_HOST: keycloak-db
      KC_DB_URL_DATABASE: keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloak
      KC_DB_SCHEMA: public
      JAVA_OPTS_APPEND: "--show-version"
      KC_DEBUG: "true"
    ports:
      - "18080:8080"
      - "18443:8443"
      - "18787:8787"
      - "19000:9000"
    extra_hosts:
      - "localhost.emobix.co.uk:host-gateway"
      - "receiver.example.com:host-gateway"
    volumes:
      - ./target/keycloak-ssf-support.jar:/opt/keycloak/providers/keycloak-ssf-support.jar:z
      - ./scratch/data:/opt/keycloak/data:z
      - ./scratch:/imex:z
    command:
      - "--verbose"
      - "start-dev"
      - "--import-realm"

  proxy:
    image: nginx:1.29.1-alpine
    volumes:
      - ./proxy/nginx.conf:/etc/nginx/conf.d/default.conf
      - ./certs/acme.test+1.pem:/etc/tls/cert.pem
      - ./certs/acme.test+1-key.pem:/etc/tls/cert-key.pem
    ports:
      - "1443:1443"

volumes:
  keycloak-data:
    name: keycloak-ssf-data
  keycloak-db-data:
    name: keycloak-db-ssf-data
```

A few things worth understanding about this file:

* **No `ssf` feature flag.** `KC_FEATURES: preview,workflows` is what the repo ships. The PoC activates itself via `META-INF/services/...` once `keycloak-ssf-support.jar` is in `/opt/keycloak/providers/`. The `Profile.Feature.SSF` flag mentioned in the design doc is for the future upstream implementation and does **not** apply to this PoC.
* **`KC_HTTP_RELATIVE_PATH=auth`** means everything Keycloak serves is under `/auth/...`. Combined with the `proxy` service (nginx terminating TLS on `https://id.acme.test:1443/auth`) this gives you HTTPS, which SSF receivers require per spec §3.2 (TLS 1.2+).
* **`extra_hosts`** maps `receiver.example.com` to your host so a containerised Keycloak can push to a receiver running on the docker host (we'll use this for the PUSH example).
* **The nginx config and TLS cert files** (`proxy/nginx.conf`, `certs/acme.test+1*.pem`) are in the repo. The certs are `mkcert`-generated for the local hostname `acme.test`. Add `127.0.0.1 id.acme.test` to your `/etc/hosts` before bringing the stack up.

### 2.1 A reasonable `proxy/nginx.conf` if you need to recreate it

The committed `proxy/nginx.conf` was not fetchable through web search, but for an SSF transmitter the proxy only needs to terminate TLS on `:1443` and forward to Keycloak on `:8080`. A minimal working file:

```nginx
# proxy/nginx.conf
server {
    listen 1443 ssl;
    server_name id.acme.test;

    ssl_certificate     /etc/tls/cert.pem;
    ssl_certificate_key /etc/tls/cert-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Reasonable upload size for SSF management calls
    client_max_body_size 1m;

    location / {
        proxy_pass         http://keycloak:8080;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_set_header   X-Forwarded-Host  $host;
        proxy_set_header   X-Forwarded-Port  1443;
    }

    # Optional RFC-8615 rewrite — see Caveats §8.1
    location = /.well-known/ssf-configuration {
        rewrite ^ /auth/realms/ssf-demo/.well-known/ssf-configuration break;
        proxy_pass http://keycloak:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

If you do not want the HTTPS proxy and are willing to test against plain HTTP on `http://localhost:18080/auth`, you can comment out the `proxy:` service and set `KC_HOSTNAME_URL=http://localhost:18080/auth`. PUSH delivery will then need either the `allow-insecure-push-targets` SPI flag flipped on (see §8.4) or you'll need to point pushes at a non-loopback host.

---

## 3. Build, run, verify

### 3.1 Build the extension JAR

The PoC is a single-module Maven project (`pom.xml` at repo root, sources under `src/main/java/com/identitytailor/keycloak/ssf/`):

```bash
# from inside the repo
mvn clean verify
```

This produces `target/keycloak-ssf-support.jar`, which is precisely what the compose file mounts into the Keycloak container. The README only says `mvn clean verify`; there is no published prebuilt artifact in the repo's GitHub Releases page ("No releases published" as of mid-May 2026), so building locally is the only option.

You need:

* JDK 17+ (Keycloak 26.x toolchain)
* Maven 3.9+
* Internet access for Maven Central + Keycloak BOMs

### 3.2 Bring the stack up

```bash
# add to /etc/hosts:   127.0.0.1   id.acme.test
docker compose up
```

After a minute or so you should see Keycloak logs ending with `Profile (prod) features... Listening on: http://0.0.0.0:8080`. Open:

* **Admin console (direct):** http://localhost:18080/auth/admin (admin / admin)
* **Admin console (via TLS proxy):** https://id.acme.test:1443/auth/admin
* **Account console for the demo user:** http://localhost:18080/auth/realms/ssf-demo/account/ — login as `tester` / `test` (the `ssf-demo` realm is auto-imported because of `--import-realm`)

### 3.3 Verify the SSF transmitter metadata endpoint

Per the design doc, the transmitter metadata document is published at **two** URL shapes per realm (only the realm-prefixed one will work here, because the compose file sets `KC_HTTP_RELATIVE_PATH=auth` — see the §8.1 caveat on the RFC 8615 root form):

```bash
# Realm-prefixed (always works)
curl -sS http://localhost:18080/auth/realms/ssf-demo/.well-known/ssf-configuration | jq .
```

Expected (abridged) response per the design doc's "Transmitter metadata" section:

```json
{
  "issuer": "http://localhost:18080/auth/realms/ssf-demo",
  "jwks_uri": "http://localhost:18080/auth/realms/ssf-demo/protocol/openid-connect/certs",
  "delivery_methods_supported": [
    "urn:ietf:rfc:8935",
    "urn:ietf:rfc:8936",
    "https://schemas.openid.net/secevent/risc/delivery-method/push",
    "https://schemas.openid.net/secevent/risc/delivery-method/poll"
  ],
  "configuration_endpoint":  "http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/streams",
  "status_endpoint":         "http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/streams/status",
  "verification_endpoint":   "http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/verify",
  "add_subject_endpoint":    "http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/subjects/add",
  "remove_subject_endpoint": "http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/subjects/remove",
  "authorization_schemes":   [{ "spec_urn": "urn:ietf:rfc:6749" }],
  "default_subjects":        "NONE",
  "critical_subject_members":["user"],
  "spec_version":            "1_0"
}
```

If this returns 200 with JSON, the extension is loaded and the SSF SPI is wired in. If it returns 404, check `docker compose logs keycloak | grep -i ssf` — the SPI service files in the JAR must be discovered at startup.

> Per the design doc the legacy **SSE** subset is also published at `/.well-known/sse-configuration` (gated by SPI flag `spi-wellknown--sse-configuration--enabled`), which is what Apple Business Manager / School Manager use.

---

## 4. Create the receiver client and configure SSF on it

The PoC uses the *Keycloak client* object to model an "SSF Receiver" — exactly as the design doc describes. The activation marker is the client attribute **`ssf.enabled=true`**.

> Whether you do this through the admin UI or via the Admin REST API is a matter of taste. The UI labels below ("SSF" tab, sub-tabs Receiver / Stream / Subjects / Event Search / Emit Events) come from the design doc; the in-repo admin UI screens may not be identical to the upstream design doc since the PoC predates several refactors. Treat the names as approximate.

### 4.1 Create an OIDC client of confidential type

In the `ssf-demo` realm (or any realm you create) → **Clients** → **Create client**:

* Client type: **OpenID Connect**
* Client ID: `caep-dev-receiver` (name is arbitrary; we use this one throughout)
* Client authentication: **On** (we need a client secret for the receiver-side service account)
* Standard flow: off
* Service accounts roles: **On** (the receiver authenticates to Keycloak's SSF management API with `client_credentials`)
* Valid redirect URIs: leave empty — SSF receivers don't redirect users

Save. On the **Credentials** tab note the **Client secret** — call it `$RECV_SECRET` in the examples below.

### 4.2 Flip the SSF receiver toggle

Go to the client's **SSF** tab (the tab appears only because the extension JAR is loaded). Per the design doc, this tab has five sub-tabs:

| Sub-tab | What it does |
|---|---|
| Receiver | All `ssf.*` client attributes (profile, signature alg, subject format, default subjects, …) |
| Stream | One-stream-per-receiver lifecycle: create / verify / delete / status-flip / delivery-method swap |
| Subjects | Add / remove / "ignore" subjects for this receiver |
| Event Search | Outbox lens — look up SETs by `jti` |
| Emit Events | Fire a synthetic SET on demand for testing |

On the **Receiver** sub-tab, set (these are the names of the client attributes the design doc lists under `ssf.*`):

| Field | Attribute key | Value |
|---|---|---|
| SSF enabled | `ssf.enabled` | `true` |
| Profile | `ssf.profile` | `SSF_1_0` |
| Signature algorithm | `ssf.signatureAlgorithm` | `RS256` (matches realm's default RSA key) |
| User subject format | `ssf.userSubjectFormat` | `iss_sub` |
| Default subjects | `ssf.defaultSubjects` | `ALL` (so every realm user is implicitly a subject — easier for testing) |
| Supported events | `ssf.supportedEvents` | `CaepSessionRevoked,CaepCredentialChange,RiscAccountCredentialChangeRequired` |
| Allowed delivery methods | `ssf.allowedDeliveryMethods` | `push##poll` (note the `##` separator — `Constants.CFG_DELIMITER`) |
| Valid push URLs | `ssf.validPushUrls` | `http://receiver:9999/events##http://receiver:9999/events/*` (only needed if you'll test PUSH; this is the SSRF allow-list) |

Save. If your admin UI uses different labels (PoC vs design-doc divergence), the corresponding *attributes* are still the right thing to set — you can always confirm by inspecting the client via the Admin REST API at `GET /admin/realms/ssf-demo/clients/{uuid}`.

If you prefer plain REST instead of clicking, the equivalent attribute payload is:

```bash
# Get an admin access token first
ADMIN_TOKEN=$(curl -s -X POST \
  http://localhost:18080/auth/realms/master/protocol/openid-connect/token \
  -d 'grant_type=password' -d 'client_id=admin-cli' \
  -d 'username=admin' -d 'password=admin' | jq -r .access_token)

# Find the internal UUID for the client
CLIENT_UUID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  'http://localhost:18080/auth/admin/realms/ssf-demo/clients?clientId=caep-dev-receiver' \
  | jq -r '.[0].id')

# Patch the SSF attributes
curl -s -X PUT \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "ssf.enabled":"true",
      "ssf.profile":"SSF_1_0",
      "ssf.signatureAlgorithm":"RS256",
      "ssf.userSubjectFormat":"iss_sub",
      "ssf.defaultSubjects":"ALL",
      "ssf.supportedEvents":"CaepSessionRevoked,CaepCredentialChange,RiscAccountCredentialChangeRequired",
      "ssf.allowedDeliveryMethods":"push##poll",
      "ssf.validPushUrls":"http://receiver:9999/events"
    }
  }' \
  http://localhost:18080/auth/admin/realms/ssf-demo/clients/$CLIENT_UUID
```

### 4.3 Signing keys / JWKS

You do **not** need to upload anything. Keycloak signs each emitted SET with the realm's active RS256 signing key, and the `jwks_uri` in the transmitter metadata points at the realm's standard `/protocol/openid-connect/certs` endpoint. Receivers fetch it from there. The `ssf.signatureAlgorithm` knob picks which realm key to use (RS256 / RS384 / ES256 / etc.).

---

## 5. Create a stream as the receiver

The receiver authenticates to the SSF management API with **its own service-account access token** (client_credentials grant on the receiver client we just created). All paths below are documented in the design doc's "Receiver-facing" endpoint table.

```bash
# As the receiver: obtain a bearer token via client_credentials
RECV_SECRET=...   # from the Credentials tab
RECV_TOKEN=$(curl -s -X POST \
  http://localhost:18080/auth/realms/ssf-demo/protocol/openid-connect/token \
  -u "caep-dev-receiver:$RECV_SECRET" \
  -d "grant_type=client_credentials" | jq -r .access_token)
```

The base URL we'll use for SSF endpoints (from the metadata document above) is:

```
http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter
```

---

## 5a. Worked example A — POLL delivery (RFC 8936)

POLL is the simpler case because there's no outbound HTTP call from Keycloak: the receiver pulls events from a Keycloak-owned endpoint. The receiver omits `endpoint_url` (and per SSF §7.1.1 the transmitter fills it in on the response).

### Create the stream

```bash
curl -sS -X POST \
  http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/streams \
  -H "Authorization: Bearer $RECV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "delivery": {
      "method": "urn:ietf:rfc:8936"
    },
    "events_requested": [
      "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
      "https://schemas.openid.net/secevent/caep/event-type/credential-change",
      "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
    ],
    "format": "iss_sub",
    "description": "demo POLL stream"
  }' | jq .
```

Expected response (shape per SSF 1.0 §7.1.1; the transmitter stamps `stream_id`, `iss`, `aud`, `events_supported`, `events_delivered`, and — for POLL — `delivery.endpoint_url`):

```json
{
  "stream_id": "a3f8c5b2-...",
  "iss": "http://localhost:18080/auth/realms/ssf-demo",
  "aud": ["caep-dev-receiver"],
  "delivery": {
    "method": "urn:ietf:rfc:8936",
    "endpoint_url": "http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/receivers/caep-dev-receiver/streams/a3f8c5b2-.../poll"
  },
  "events_supported": [
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
  ],
  "events_requested":  [ "...same three..." ],
  "events_delivered":  [ "...same three..." ],
  "format": "iss_sub"
}
```

Capture the poll URL:

```bash
POLL_URL=http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/receivers/caep-dev-receiver/streams/<stream_id>/poll
```

### Trigger a verification event

```bash
curl -sS -X POST \
  http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/verify \
  -H "Authorization: Bearer $RECV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"state":"hello-verify-1"}'
# 200 with no body — the SET is now in the poll outbox
```

### Poll it

```bash
curl -sS -X POST "$POLL_URL" \
  -H "Authorization: Bearer $RECV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "maxEvents": 10,
    "returnImmediately": true,
    "ack": []
  }' | jq .
```

The response shape per RFC 8936 §2.4.2 (and what the PoC implements per design doc "POLL delivery"):

```json
{
  "sets": {
    "<jti-1>": "eyJhbGciOiJSUzI1NiIsInR5cCI6InNlY2V2ZW50K2p3dCIsImtpZCI6Ii4uLiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjE4MDgwL2F1dGgvcmVhbG1zL3NzZi1kZW1vIiwiYXVkIjpbImNhZXAtZGV2LXJlY2VpdmVyIl0sImlhdCI6MTcxNjA2NjQwMCwianRpIjoiPGp0aS0xPiIsInN1Yl9pZCI6eyJmb3JtYXQiOiJvcGFxdWUiLCJpZCI6IjxzdHJlYW1faWQ-In0sImV2ZW50cyI6eyJodHRwczovL3NjaGVtYXMub3BlbmlkLm5ldC9zZWNldmVudC9zc2YvZXZlbnQtdHlwZS92ZXJpZmljYXRpb24iOnsic3RhdGUiOiJoZWxsby12ZXJpZnktMSJ9fX0.SIGN..."
  },
  "moreAvailable": false
}
```

Each value is a compact-JWS-encoded SET. Decode the body of the first one to confirm:

```bash
echo "<the_jws_compact_string>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

You'll see the verification event payload:

```json
{
  "iss": "http://localhost:18080/auth/realms/ssf-demo",
  "aud": ["caep-dev-receiver"],
  "iat": 1716066400,
  "jti": "<jti-1>",
  "sub_id": { "format": "opaque", "id": "<stream_id>" },
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/verification": {
      "state": "hello-verify-1"
    }
  }
}
```

### Acknowledge

You **must** ack each delivered `jti` so Keycloak deletes the row from the outbox; otherwise the next poll returns the same event again. NACKs go in `setErrs` and transition the row to `DEAD_LETTER`:

```bash
curl -sS -X POST "$POLL_URL" \
  -H "Authorization: Bearer $RECV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "maxEvents": 0,
    "returnImmediately": true,
    "ack": ["<jti-1>"]
  }'
# 200 — ack-only request returns no new events
```

A NACK example (mark a SET as unprocessable):

```bash
curl -sS -X POST "$POLL_URL" \
  -H "Authorization: Bearer $RECV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ack": [],
    "setErrs": {
      "<jti-2>": { "err": "invalid_key", "description": "signature did not verify" }
    }
  }'
```

> **Caveat per the design doc:** long-polling (`returnImmediately=false`, `maxWait`) is parsed but not honoured — every poll returns immediately. Configure your receiver to poll on its own cadence (e.g. every 5 s).

---

## 5b. Worked example B — PUSH delivery (RFC 8935)

For PUSH, the receiver supplies an `endpoint_url` and Keycloak POSTs each signed SET to it as `application/secevent+jwt`. Acceptance is "any 2xx" per the design doc.

We'll first stand up a tiny Flask receiver that verifies the JWS against Keycloak's JWKS and prints the decoded event. Then we'll create the stream.

### Minimal Python Flask receiver

Add this service to a sibling `receiver/` directory **inside** the cloned repo (so the relative build context lines up with the compose file).

`receiver/app.py`:

```python
# pip install flask requests pyjwt[crypto]
from flask import Flask, request, jsonify
import jwt
from jwt import PyJWKClient
import json, os, sys

KC_ISSUER = os.environ.get(
    "KC_ISSUER",
    "http://keycloak:8080/auth/realms/ssf-demo"
)
JWKS_URL = KC_ISSUER + "/protocol/openid-connect/certs"
AUDIENCE = os.environ.get("KC_AUD", "caep-dev-receiver")

jwks_client = PyJWKClient(JWKS_URL)
app = Flask(__name__)

@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/events", methods=["POST"])
def receive_set():
    body = request.get_data(as_text=True)
    if not body:
        return "missing SET", 400
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(body).key
        claims = jwt.decode(
            body,
            signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256"],
            audience=AUDIENCE,
            issuer=KC_ISSUER,
        )
    except Exception as e:
        print("VERIFY FAILED:", e, file=sys.stderr, flush=True)
        return jsonify({"err": "invalid_key", "description": str(e)}), 400

    print("\n--- SET received ---")
    print(json.dumps(claims, indent=2))
    sys.stdout.flush()
    # Per RFC 8935: 202 Accepted is fine; any 2xx is treated as success by the PoC.
    return "", 202

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9999)
```

`receiver/Dockerfile`:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask requests "pyjwt[crypto]==2.9.0"
COPY app.py .
EXPOSE 9999
CMD ["python", "app.py"]
```

Add the receiver to the compose file (append to `services:`):

```yaml
  receiver:
    build: ./receiver
    container_name: ssf-receiver
    environment:
      KC_ISSUER: http://keycloak:8080/auth/realms/ssf-demo
      KC_AUD:    caep-dev-receiver
    ports:
      - "9999:9999"
```

Because both containers are on the same default docker-compose network, Keycloak can reach the receiver as `http://receiver:9999/events`. Confirm `ssf.validPushUrls` matches:

```bash
ssf.validPushUrls = http://receiver:9999/events
```

Bring it all up:

```bash
docker compose up --build
```

### Create the PUSH stream

```bash
curl -sS -X POST \
  http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/streams \
  -H "Authorization: Bearer $RECV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "delivery": {
      "method": "urn:ietf:rfc:8935",
      "endpoint_url": "http://receiver:9999/events"
    },
    "events_requested": [
      "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
      "https://schemas.openid.net/secevent/caep/event-type/credential-change",
      "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
    ],
    "format": "iss_sub"
  }' | jq .
```

If `ssf.validPushUrls` does not include the supplied URL you'll get **HTTP 400** with the design doc's `SsfPushUrlValidator.Reason` codes in the server log (e.g. `NOT_IN_ALLOWLIST`, `SCHEME_INSECURE`, `HOST_PRIVATE`). The 400 body deliberately doesn't echo the URL — check `docker compose logs keycloak | grep SsfPushUrlValidator` for the actual reason. The design doc even has the server emit a suggested `ssf.validPushUrls` entry in its WARN log, so copy that, fix the client attribute, and retry.

### Trigger a verification event over PUSH

```bash
curl -sS -X POST \
  http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/verify \
  -H "Authorization: Bearer $RECV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"state":"push-hello"}'
```

Within a few seconds the Flask receiver prints the decoded claims (you'll see this in `docker compose logs receiver`):

```
--- SET received ---
{
  "iss": "http://localhost:18080/auth/realms/ssf-demo",
  "aud": ["caep-dev-receiver"],
  "iat": 1716066499,
  "jti": "5d9c...",
  "sub_id": { "format": "opaque", "id": "<stream_id>" },
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/verification": {
      "state": "push-hello"
    }
  }
}
```

Note the JWS `typ` header is `secevent+jwt` per RFC 8417 §2.3.

> If you want to point Keycloak at a hosted test receiver instead of running your own, the PoC's README points at **caep.dev** — register/log in there, generate a stream-receiver token, and pass it back to Keycloak as the `delivery.authorization_header` field in the create-stream body. The same SSF Stream-Create request shape applies.

---

## 5c. Point goSignals at the Keycloak SSF transmitter (shipped CLI path)

Worked examples A and B used raw `curl` against the Keycloak transmitter to
illustrate the wire protocol. In practice you let an **i2goSignals** receiver
node pull those events for you. This is the part of PRD #83 that ships today
(slices #85/#86, merged in #134); the Keycloak side is still the manual PoC
setup from §1–§4 (the bundled-image slices #84/#87/#88 are on hold — see the
note at the top).

Two CLI steps:

### 5c.1 Stage the Keycloak transmitter (`add server --client-id`)

Register the Keycloak SSF transmitter as a foreign server using the OAuth
client-credentials grant. Use the receiver client you created in §4.1
(`caep-dev-receiver` + `$RECV_SECRET`) and Keycloak's realm token endpoint:

```shell
goSignals> add server kc-ssf https://id.acme.test:1443/auth/realms/ssf-demo \
    --client-id=caep-dev-receiver \
    --client-secret=$RECV_SECRET \
    --token-url=https://id.acme.test:1443/auth/realms/ssf-demo/protocol/openid-connect/token \
    --scopes=ssf
```

`add server` interrogates the transmitter's `/.well-known/ssf-configuration`,
infers the server type from its metadata, and stages the **non-secret** OAuth
fields (`client_id`, `token_url`, `scopes`) into `config.json`. The
`--client-secret` is held in memory only and is **never** written to
`config.json`. No registration call is made yet, and the staged transmitter does
**not** become your selected (management) server.

### 5c.2 Create a POLL receiver against it (`create stream poll receive --tx-alias`)

On your goSignals receiver node (the management server you are logged in to —
e.g. `go2`), create a POLL receive stream that auto-registers the staged
transmitter:

```shell
goSignals> create stream poll receive go2 \
    --tx-alias=kc-ssf \
    --events=*
```

`--tx-alias` makes the **node** register the transmitter (`POST /server`) and
the server-side auto-registration path discovers the Keycloak transmitter's
poll endpoint, provisions the upstream stream, and wires it in. The receiver
then polls Keycloak on its own cadence; the CAEP/RISC SETs you trigger in §6
land in goSignals.

> [!IMPORTANT]
> `--tx-alias` requires an **admin** credential (not the registration IAT) — it
> POSTs to the admin-only `/server` endpoint. Log in with an admin session
> (`login go2`) or configure an admin client token first, or the CLI fails fast
> with an admin-scope message. See
> [Security Model](security_model.md#foreign-server-provisioning-endpoint--scope).

The OAuth client secret for the transmitter is resolved staged → `--secret`
flag → environment and rides on the registration request body only; it is never
persisted to `config.json`.

---

## 6. Add a subject and trigger real CAEP / RISC events

So far we've only generated verification SETs. To generate real CAEP events you need a **subject** wired in and a real Keycloak event to happen.

### 6.1 Subject management

If `ssf.defaultSubjects=ALL` (which we set in §4.2) every realm user is implicitly a subject, and `subjects/add` is unnecessary. If you switch to `NONE`, you must subscribe each user explicitly:

```bash
# Add the `tester` user as a subject for the stream
curl -sS -X POST \
  http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/subjects/add \
  -H "Authorization: Bearer $RECV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {
      "format": "email",
      "email": "tester@example.com"
    }
  }'
# Silent 200 — the design doc explicitly notes "no existence oracle"
```

To unsubscribe later, POST the same shape to `/ssf/transmitter/subjects/remove`.

### 6.2 Trigger a `CaepSessionRevoked` event (logout)

Per the design doc's "Event mapping" section, the native Keycloak event `LOGOUT` is mapped to **`CaepSessionRevoked`** with a complex subject (`user` + `session` facets).

Easiest way to trigger one:

1. In an incognito browser, log `tester / test` into `http://localhost:18080/auth/realms/ssf-demo/account/`.
2. Back in the admin UI as `admin`, go to **realm `ssf-demo` → Sessions** and click **Sign out all active sessions** (or sign out only the `tester` session).

Keycloak fires `LOGOUT`, the `SsfTransmitterEventListener` picks it up, and a SET like the following lands on the receiver:

```json
{
  "iss": "http://localhost:18080/auth/realms/ssf-demo",
  "aud": ["caep-dev-receiver"],
  "iat": 1716066700,
  "jti": "9f4c...",
  "sub_id": {
    "format": "complex",
    "user":    { "format": "iss_sub",
                 "iss":  "http://localhost:18080/auth/realms/ssf-demo",
                 "sub":  "<tester-user-uuid>" },
    "session": { "format": "opaque", "id": "<session-id>" }
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1716066700,
      "reason_admin":    { "en": "Admin sign-out" }
    }
  }
}
```

### 6.3 Trigger a `CaepCredentialChange` event (password reset)

Per the design doc: `RESET_PASSWORD` → `CaepCredentialChange` with `change_type=UPDATE`, `credential_type=password`.

* In the admin UI, **Users → tester → Credentials → Reset password**, set a new password, and uncheck *Temporary*.
* Or trigger via the account console: log in as `tester` at `/realms/ssf-demo/account/`, change the password from the *Account security → Signing in* panel.

Either action emits a SET with `events` containing the CAEP credential-change URI:

```json
"events": {
  "https://schemas.openid.net/secevent/caep/event-type/credential-change": {
    "event_timestamp": 1716066900,
    "credential_type": "password",
    "change_type":     "update"
  }
}
```

### 6.4 Trigger a RISC event via the synthetic emitter

RISC's `account-credential-change-required` has no native Keycloak source. Use the **admin synthetic emit** endpoint described in the design doc (admin path, not the receiver-facing one — requires admin token):

```bash
curl -sS -X POST \
  http://localhost:18080/auth/admin/realms/ssf-demo/ssf/clients/caep-dev-receiver/events/emit \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required",
    "sub_id": {
      "format": "email",
      "email":  "tester@example.com"
    },
    "event": {
      "event_timestamp": 1716067000
    }
  }'
# 200 {"status":"dispatched","jti":"..."}
```

The receiver will see the corresponding signed SET arrive over the configured delivery channel.

---

## 7. Stream lifecycle: status, update, delete

These come straight from the design doc's "Stream status" section (and SSF 1.0 §7.1.2). All use the receiver bearer token.

```bash
# Read status
curl -sS http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/streams/status \
  -H "Authorization: Bearer $RECV_TOKEN"

# Pause (new events go to HELD in the outbox)
curl -sS -X POST .../streams/status \
  -H "Authorization: Bearer $RECV_TOKEN" -H "Content-Type: application/json" \
  -d '{"status":"paused","reason":"maintenance"}'

# Resume
... -d '{"status":"enabled"}'

# Disable (drops all PENDING + HELD per spec)
... -d '{"status":"disabled"}'

# Delete the stream entirely
curl -sS -X DELETE http://localhost:18080/auth/realms/ssf-demo/ssf/transmitter/streams \
  -H "Authorization: Bearer $RECV_TOKEN"
```

PATCH/PUT to `/streams` let you update receiver-writable fields (notably `events_requested` and `delivery.endpoint_url`). Transmitter-controlled fields (`stream_id`, `iss`, `aud`, `events_supported`, `events_delivered`, anything `kc_*`) are stamped by the server and will be rejected with HTTP 400 if you try to send them.

---

## 8. Caveats and gotchas

### 8.1 The well-known root-of-domain issue (the topic of keycloak/keycloak#14217's neighbour discussion)

RFC 8615 says `.well-known/<suffix>` MUST be at the origin root. The compose file ships with `KC_HTTP_RELATIVE_PATH=auth`, which means Keycloak only serves `https://id.acme.test:1443/auth/realms/ssf-demo/.well-known/ssf-configuration` — **not** `https://id.acme.test:1443/.well-known/ssf-configuration/realms/ssf-demo`, because `/.well-known/...` is outside Keycloak's context root and Keycloak can't route it itself. The design doc spells this out:

> "When Keycloak is deployed under a relative path such as `/auth` (`KC_HTTP_RELATIVE_PATH=/auth`), only the realm-prefixed form is served; the RFC 8615 shape would need to live at `https://KC_HOSTNAME/.well-known/...` which sits outside the Keycloak context root and is not something Keycloak can route by itself."

(Keycloak has shipped some accommodations for `.well-known` discovery at the root — recent Keycloak versions document an RFC 8414 root endpoint for OAuth Authorization Server Metadata, and the upstream guidance is "expose the path `/.well-known/` in your reverse proxy configuration." The exact bug originally tracked in the older issue threads, including the spirit of the #14217 conversation, is still that without a reverse-proxy rewrite, strict RFC-8615 receivers like Apple Business Manager / Apple School Manager won't be able to discover the SSF metadata.)

If you have such a receiver, you have two options:

* **Remove the relative path.** Set `KC_HTTP_RELATIVE_PATH=` (empty), drop `auth` from `KC_HOSTNAME_URL`, and the host-rooted form starts being served by Keycloak directly.
* **Rewrite at the proxy.** The `location = /.well-known/ssf-configuration` block in the `proxy/nginx.conf` shown in §2.1 is exactly this rewrite. Per-realm dispatch from a single root well-known URL requires deciding on a "default realm" or sniffing a query parameter, since there's only one `/.well-known/ssf-configuration` per origin.

### 8.2 Experimental status — heavy caveat

* The PoC is explicitly a proof of concept (repo name, README, 11 GitHub stars at time of writing, 27 commits, no published releases). Issue/discussion #28427 (April 2024) and discussion #14217 are the upstream community threads tracking this; both make it clear that an officially-supported in-tree implementation is "still planned" as of mid-2026 — see also Andrew Doering's May 2026 blog series, which states bluntly that "Keycloak has no native SSF transmitter. A community receiver PoC exists, but the transmitter side is still planned."
* The design doc on the gist describes the planned upstream version as "experimental, opt-in, hidden behind `Profile.Feature.SSF`" and lists deferred items (long-polling, multi-stream per receiver, native source for `device-compliance-change`).
* The DB schema (`OUTBOX_ENTRY` / Liquibase changeset `26.7.0-outbox` in the design doc) is **not** identical to whatever schema the PoC currently ships — earlier revisions of the design doc referenced a table called `SSF_PENDING_EVENT`, so expect breaking changes between the PoC and the eventual upstream merge. Treat anything you build against the PoC's API as throwaway.
* The PoC's README says **Keycloak 26.1.4** but its committed `docker-compose.yml` uses **26.4.0**. The Java sources were last touched well after 26.1.4 was released, so the JAR almost certainly works fine against 26.4.0 (which is what CI runs). If you hit a missing-symbol error at startup, fall back to `26.1.4`.

### 8.3 Authentication for the SSF management API

* **Receiver-facing endpoints** (`/realms/{r}/ssf/transmitter/...`) require an **OAuth bearer** belonging to the receiver client. We obtained it via `client_credentials` against the receiver client itself — i.e. its service account. Per the design doc, `ssf.requireServiceAccount=true` would *enforce* that (reject user-delegated tokens).
* **Admin-facing endpoints** (`/admin/realms/{r}/ssf/...`) require an admin bearer with `manage-realm` / `view-realm` (or fine-grained equivalents). The synthetic-emit endpoint additionally allows a trusted-emitter service account, gated per receiver by `ssf.allowEmitEvents=true` + `ssf.emitEventsRole`.
* TLS is mandated by SSF 1.0 §3.2. For local hacking the PoC's nginx proxy gives you that; for any non-local target either keep the proxy or set the SPI flag `allow-insecure-push-targets` (production: don't).

### 8.4 JWKS / signing keys

* SETs are signed by the realm's active signing key for the algorithm picked in `ssf.signatureAlgorithm` (default `RS256`).
* Receivers must fetch JWKS from the `jwks_uri` in the transmitter metadata. The Flask receiver above uses PyJWT's `PyJWKClient`, which caches keys; remember to honour the cache TTL or `Cache-Control` on the JWKS endpoint so a Keycloak realm-key rotation doesn't take the receiver offline.
* Per the design doc, the outbox stores the **already-signed** payload — so a key rotation between enqueue and a retried PUSH doesn't change the `jti` or the signature of a retried row. Receivers can safely dedupe on `jti`.

### 8.5 Endpoint paths

The design doc shows endpoint paths rooted at `/realms/{realm}/ssf/transmitter/...`. Earlier revisions of the PoC may have used different roots (e.g. without the `transmitter` segment). If the paths above 404, fetch `/.well-known/ssf-configuration` and use the URLs it advertises — those are authoritative for whatever the loaded JAR actually exposes.

### 8.6 The PoC vs. the gist design

The gist by Thomas Darimont describes the **upstream design**, not the PoC. Many of the polished features described — split-storage `ssf.stream.*` attributes, the `SsfPushUrlValidator.Reason` enum, the `metrics-enabled` SPI flag and Prometheus meters, the explicit `Profile.Feature.SSF` gating, the synthetic-emit subject-shorthand DSL, the SSF §9.3 grace-window tombstones — are *aspirational* for the upstream port and may or may not be present in the PoC JAR you build today. Use the gist as a reference for the wire-protocol shape and as a preview of where this is heading; for the PoC, treat the README + the source under `src/main/java/com/identitytailor/keycloak/ssf/` as ground truth.

---

## 9. Quick troubleshooting reference

| Symptom | Likely cause |
|---|---|
| `/.well-known/ssf-configuration` 404s | JAR not in `/opt/keycloak/providers`, or the volume mount path doesn't match `./target/keycloak-ssf-support.jar`. Check `docker compose logs keycloak \| grep -i 'ssf\|provider'`. |
| `POST /ssf/transmitter/streams` returns 401 | The bearer token is admin or wrong-client. Make sure you used `client_credentials` against `caep-dev-receiver` and that the client has Service-account roles enabled. |
| `POST /streams` returns 400 with no body | The receiver-supplied `delivery.endpoint_url` failed `ssf.validPushUrls` matching. Look in Keycloak logs for `StreamService.logPushUrlRejection` — it suggests the exact `ssf.validPushUrls` entry to add. |
| Flask receiver gets `signature verification failed` | JWKS cache is stale (key rotation), or `KC_ISSUER` env var doesn't match the `iss` claim in the SET. Make sure both use the *same* externally-resolvable URL Keycloak uses to mint the `iss`. |
| Push fires once then never again | The PUSH outbox row hit `DEAD_LETTER` after retries. Default budget per design doc is `outbox-drainer-max-attempts=8`. Inspect via the admin `Event Search` sub-tab, or `GET /admin/realms/ssf-demo/ssf/clients/caep-dev-receiver/events/stats`. |
| POLL returns the same `jti` every call | You're not acking. Send `ack:["<jti>"]` in the next poll request. |

---

## 10. Where to go next

* **OpenID SSF 1.0 Final** — `https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html` — canonical wire spec; the design doc and PoC track this.
* **CAEP Interop Profile 1.0 (draft)** — `https://openid.github.io/sharedsignals/openid-caep-interoperability-profile-1_0.html` — the interop subset Apple and CAEP early-adopters check against.
* **OpenID RISC Profile 1.0** — for the full RISC event-type catalog (`account-credential-change-required`, `account-purged`, `account-disabled`, …).
* **caep.dev** — public test receiver. Generate a stream-receiver token there and point the PoC at it for a "real" PUSH receiver without writing one yourself.
* **Thomas Darimont's KCDD25 deck** — `https://keycloak-day.dev/assets/files/KCDD25-Strengthening_Security_in_Keycloak-ThomasDarimont.pdf` — slide-level overview of SSF in Keycloak, including the diagrams the design doc text refers to.
* **intension.de interview with Thomas Darimont** — "Keycloak and the Shared Signals Framework" — confirms the PoC role and the fact that "the details of the implementation have not yet been finalized — the community is still debating whether the SSF functionality should be integrated directly into the core of Keycloak or developed as a separate add-on."
* **Upstream Keycloak SSF design doc** — `https://gist.github.com/thomasdarimont/75b14d423ee47392d10f86643244b2a2` — definitive source for where this is heading once it lands in mainline Keycloak (almost certainly where you should be reading PRs under the `area/ssf` label once that work starts merging).

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
