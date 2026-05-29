<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# i2goSignals Server Configuration Properties

All server configuration is environment-variable driven; there is no config
file. This document is the canonical reference. Section names match the
v0.11.0 prefix taxonomy described in
[`DECISIONS_LOG.md`](../DECISIONS_LOG.md).

## Migrating from pre-v0.11.0 names

v0.11.0 rationalises environment-variable names under an `I2SIG_<AREA>_*`
taxonomy. Every old name is still read at runtime through the
[`internal/envcompat`](../internal/envcompat/envcompat.go) shim and triggers
a single WARN per process when used. The deprecated names will be **removed
in v0.12.0+**.

| Old name (pre-v0.11.0)                  | New name (v0.11.0)                          |
|-----------------------------------------|---------------------------------------------|
| `MIN_VERIFICATION_INTERVAL`             | `I2SIG_STREAM_MIN_VERIFICATION_INTERVAL`    |
| `MAX_INACTIVITY_TIMEOUT`                | `I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT`       |
| `I2SIG_ISSUER`                          | `I2SIG_ISSUER_DEFAULT`                      |
| `I2SIG_TOKEN_ISSUER`                    | `I2SIG_ISSUER_TOKEN`                        |
| `SSEF_ADMIN_ROLE`                       | `I2SIG_AUTH_ADMIN_ROLE`                     |
| `OAUTH_SERVERS`                         | `I2SIG_AUTH_OAUTH_SERVERS`                  |
| `STS_TOKEN_URL`                         | `I2SIG_AUTH_STS_TOKEN_URL`                  |
| `STS_CLIENT_ID`                         | `I2SIG_AUTH_STS_CLIENT_ID`                  |
| `STS_CLIENT_SECRET`                     | `I2SIG_AUTH_STS_CLIENT_SECRET`              |
| `STS_AUDIENCE`                          | `I2SIG_AUTH_STS_AUDIENCE`                   |
| `STS_RESOURCE`                          | `I2SIG_AUTH_STS_RESOURCE`                   |
| `STS_SCOPES`                            | `I2SIG_AUTH_STS_SCOPES`                     |
| `NODE_ID`                               | `I2SIG_CLUSTER_NODE_ID`                     |
| `I2SIG_TRANSMITTER_BACKFILL_INTERVAL`   | `I2SIG_PUSH_BACKFILL_INTERVAL`              |
| `I2SIG_TRANSMITTER_BACKFILL_BATCH`      | `I2SIG_PUSH_BACKFILL_BATCH`                 |
| `I2SIG_MONGO_WATCH_ENABLED`             | `I2SIG_STORE_MONGO_WATCH_ENABLED`           |
| `DBNAME` (also `I2SIG_DBNAME`)          | `I2SIG_STORE_MONGO_DBNAME`                  |
| `MONGO_WATCH_FILE`                      | `I2SIG_STORE_MONGO_RESUME_FILE`             |
| `MONGO_FAILTOMEM`                       | `I2SIG_STORE_MONGO_FALLBACK_MEM`            |
| `MONGO_BACKGROUND_RECONNECT`            | `I2SIG_STORE_MONGO_BACKGROUND_RECONNECT`    |
| `MEM_DIRECTORY`                         | `I2SIG_STORE_MEM_DIRECTORY`                 |
| `MEM_SAVE_RATE`                         | `I2SIG_STORE_MEM_SAVE_RATE`                 |
| `I2SIG_PUSH_STATUS_CHECK_INTERVAL`      | `I2SIG_PUSH_PROBE_INTERVAL`                 |
| `I2SIG_PUSH_UNAUTHORIZED_RETRY_DELAY`   | `I2SIG_PUSH_AUTH_RETRY_DELAY`               |
| `I2SIG_PUSH_UNAUTHORIZED_RETRY_LIMIT`   | `I2SIG_PUSH_AUTH_RETRY_LIMIT`               |
| `I2SIG_PUSH_IDLE_VERIFY_INTERVAL`       | `I2SIG_PUSH_KEEPALIVE_INTERVAL`             |
| `POLL_STATUS_CHECK_INTERVAL`            | `I2SIG_POLL_PROBE_INTERVAL`                 |
| `POLL_RETRY_BASE_DELAY`                 | `I2SIG_POLL_RETRY_BASE_DELAY`               |
| `POLL_RETRY_MAX_DELAY`                  | `I2SIG_POLL_RETRY_MAX_DELAY`                |
| `POLL_RETRY_BACKOFF_FACTOR`             | `I2SIG_POLL_RETRY_BACKOFF_FACTOR`           |
| `POLL_RETRY_LIMIT`                      | `I2SIG_POLL_RETRY_LIMIT`                    |
| `POLL_UNAUTHORIZED_RETRY_DELAY`         | `I2SIG_POLL_AUTH_RETRY_DELAY`               |
| `POLL_UNAUTHORIZED_RETRY_LIMIT`         | `I2SIG_POLL_AUTH_RETRY_LIMIT`               |
| `POLL_SRV_BEHAVIOR` *(value change)*    | `I2SIG_POLL_RESPECT_STATUS`                 |
| `POLL_DEFAULT_TIMEOUT`                  | `I2SIG_POLL_DEFAULT_TIMEOUT`                |
| `POLL_MAX_TIMEOUT`                      | `I2SIG_POLL_MAX_TIMEOUT`                    |
| `TLS_ENABLED`                           | `I2SIG_TLS_ENABLED`                         |
| `SERVER_KEY_PATH`                       | `I2SIG_TLS_KEY_PATH`                        |
| `SERVER_CERT_PATH`                      | `I2SIG_TLS_CERT_PATH`                       |
| `CA_CERT` (also `CERT_CA_PUB_KEY`)      | `I2SIG_TLS_CA_CERT`                         |
| `SPIFFE_TRUST_DOMAIN`                   | `I2SIG_SPIFFE_TRUST_DOMAIN`                 |
| `SPIFFE_MONGO_ENABLED`                  | `I2SIG_SPIFFE_MONGO_ENABLED`                |

### Value translation

One rename also changes the value vocabulary:

| Var                      | Old value      | New value                          |
|--------------------------|----------------|------------------------------------|
| `POLL_SRV_BEHAVIOR` (old) | `MODE`        | `I2SIG_POLL_RESPECT_STATUS=true`   |
| `POLL_SRV_BEHAVIOR` (old) | `ALWAYSON`    | `I2SIG_POLL_RESPECT_STATUS=false`  |

`envcompat.LookupWithTranslate` runs the translator whenever the value came
from the old name. The new name accepts only `true`/`false`.

## Industry-standard exemptions

Seven variables intentionally keep their bare (un-prefixed) names because
they are conventions external operators expect and tooling already
understands. They are documented in their natural section below.

| Name                     | Why exempt                                                                              |
|--------------------------|-----------------------------------------------------------------------------------------|
| `PORT`                   | Universal HTTP container/service convention.                                            |
| `BASE_URL`               | Read by external clients and reverse-proxy tooling; renaming would surprise operators. |
| `LOG_LEVEL`              | Standard 12-factor logging convention.                                                  |
| `LOG_FORMAT`             | Same 12-factor logging convention; parsed by log shippers.                              |
| `POD_NAME`               | Kubernetes Downward API field name. Cannot be renamed without losing the binding.      |
| `MONGO_URL`              | Standard Mongo driver convention; documented in Mongo's own ecosystem.                 |
| `SPIFFE_ENDPOINT_SOCKET` | SPIFFE Workload API spec; consumed by `go-spiffe` and other SPIFFE libraries.          |

## Server

| Variable                       | Description                                                                                                              | Default                            |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| `PORT`                         | Port the server listens on.                                                                                              | `8888`                             |
| `BASE_URL`                     | Public host:port the server presents (e.g. `127.0.0.1:8888`).                                                            | `127.0.0.1:<PORT>` or `127.0.0.1:8888` |
| `LOG_LEVEL`                    | Logging level: `debug`, `info`, `warn`, `error`.                                                                         | `info`                             |
| `LOG_FORMAT`                   | `text` for human-readable key=value, `json` for one-object-per-line consumption by Alloy / Fluent Bit / CloudWatch agent. See [`observability.md`](observability.md). | `text` |

## Stream

| Variable                                  | Description                                                                                | Default |
|-------------------------------------------|--------------------------------------------------------------------------------------------|---------|
| `I2SIG_STREAM_MIN_VERIFICATION_INTERVAL`  | Minimum interval, in seconds, between verification requests a receiver may demand.         | `300`   |
| `I2SIG_STREAM_MAX_INACTIVITY_TIMEOUT`     | Maximum inactivity timeout, in seconds, before a stream connection is considered idle.     | `3600`  |
| `I2SIG_SUBJECT_FILTERING`                 | Enables SSF subject filtering (Add/Remove Subject, §8.1.3) server-wide. `ENABLED` advertises the `add_subject_endpoint` / `remove_subject_endpoint` in SSF discovery and makes the per-stream `defaultSubjects` knob settable; `DISABLED` omits both endpoints, returns `404` from the Add/Remove Subject handlers, and silently ignores `defaultSubjects`. | `DISABLED` |
| `I2SIG_SUBJECT_REMOVAL_GRACE`             | Server-wide default for the SSF §9.3 ("Malicious Subject Removal") removal grace period, in **seconds**. `0` (or unset) means immediate enforcement — no behavior change. Per-transmitter-stream overrides can be set via `subject_removal_grace_seconds` on the stream's `StreamStateRecord` (set via the management API; an override on a receiver stream is ignored with a `WARN`). Negative or non-integer values fall back to `0`. On `LOCAL` and `HYBRID` streams a delivery-stopping change is deferred for the grace window before it takes effect; on `HYBRID` the upstream `remove` relay is also deferred to the same deadline and fired by the push-transmitter lease owner's backfill sweep, so the upstream keeps feeding events during the window. `PASSTHRU` adds no grace of its own — the upstream transmitter's §9.3 handling is authoritative. | `0` |

## Issuer

| Variable                | Description                                                                       | Default     |
|-------------------------|-----------------------------------------------------------------------------------|-------------|
| `I2SIG_ISSUER_DEFAULT`  | Default issuer identifier for the server.                                         | `{BASE_URL}` |
| `I2SIG_ISSUER_TOKEN`    | Issuer identifier used for tokens generated by this server.                       | `DEFAULT`   |

## Auth

| Variable                          | Description                                                                                                  | Default |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------|---------|
| `I2SIG_AUTH_ADMIN_ROLE`           | Role identifier that grants administrative rights within a project.                                          | `ADMIN` |
| `I2SIG_AUTH_OAUTH_SERVERS`        | Comma-separated list of OAuth/OIDC discovery URLs used to validate external bearer tokens.                   | _none_  |
| `I2SIG_AUTH_STS_TOKEN_URL`        | OAuth2 client-credentials token endpoint used for outbound auth to upstream SSF/SCIM servers.                | _none_  |
| `I2SIG_AUTH_STS_CLIENT_ID`        | Client ID for the outbound OAuth2 client-credentials grant.                                                  | _none_  |
| `I2SIG_AUTH_STS_CLIENT_SECRET`    | Client secret for the outbound OAuth2 client-credentials grant.                                              | _none_  |
| `I2SIG_AUTH_STS_AUDIENCE`         | `audience` parameter requested from the STS (RFC 8693).                                                      | _none_  |
| `I2SIG_AUTH_STS_RESOURCE`         | `resource` parameter requested from the STS (RFC 8707).                                                      | _none_  |
| `I2SIG_AUTH_STS_SCOPES`           | Space-separated scopes requested from the STS.                                                               | _none_  |
| `I2SIG_BOOTSTRAP_TOKEN`           | Shared bootstrap secret. A bearer that constant-time-equals this value resolves to the narrow `key` scope (create a new issuer key + obtain a `reg`-only IAT). When unset, the anonymous `/iat` path is closed and no bootstrap bearer is accepted (fail closed). | _none_  |
| `I2SIG_IAT_LIFETIME`              | Validity of minted Initial Access Tokens (IATs), as a Go duration (e.g. `24h`, `30m`). Invalid/empty falls back to the default. | `24h`   |

## Cluster

| Variable                          | Description                                                                                                                                                                          | Default                                       |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| `I2SIG_CLUSTER_NODE_ID`           | Unique identifier for this server node in the cluster.                                                                                                                              | `POD_NAME` if set, else `hostname-timestamp`  |
| `POD_NAME`                        | Kubernetes Downward API binding; used as fallback for `I2SIG_CLUSTER_NODE_ID` when running on k8s.                                                                                  | _none_                                        |
| `I2SIG_CLUSTER_INTERNAL_TOKEN`    | Shared HMAC secret for intra-cluster wake-up calls. Required for clustered wake-ups when SPIFFE is not used.                                                                        | _none_                                        |
| `I2SIG_CLUSTER_INTERNAL_PORT`     | Port for the internal cluster wake-up API. If unset, the main server port is reused.                                                                                                 | _none_                                        |
| `I2SIG_CLUSTER_NAME`              | Logical cluster identifier emitted as the `cluster_name` attribute on every log record. Observability metadata only — does not affect lease semantics. Omitted from logs when empty.| _none_                                        |

## Store_Mongo

| Variable                                  | Description                                                                                                                                  | Default                                                |
|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| `MONGO_URL`                               | MongoDB connection URL. Should be a clustered replica set in production.                                                                     | `mongodb://root:dockTest@0.0.0.0:8880` _(testing only)_ |
| `I2SIG_STORE_MONGO_DBNAME`                | Name of the database used by goSignals.                                                                                                      | `ssef`                                                 |
| `I2SIG_STORE_MONGO_RESUME_FILE`           | Path to the file where MongoDB resume tokens are stored.                                                                                     | `resources/mongo_token.json`                           |
| `I2SIG_STORE_MONGO_FALLBACK_MEM`          | If `false`, the server fails to start when it cannot connect to MongoDB. If `true`, it falls back to the in-memory provider.                 | `true`                                                 |
| `I2SIG_STORE_MONGO_BACKGROUND_RECONNECT`  | If `true`, the server starts even when MongoDB is unreachable and retries the connection in the background. Used with `_FALLBACK_MEM=true`.  | `false`                                                |
| `I2SIG_STORE_MONGO_WATCH_ENABLED`         | If `true`, the server uses MongoDB Change Streams to watch for new events. Deprecated in favour of cluster wake-ups + backfill.              | `false`                                                |

## Store_Mem

| Variable                       | Description                                                                                              | Default                       |
|--------------------------------|----------------------------------------------------------------------------------------------------------|-------------------------------|
| `I2SIG_STORE_MEM_DIRECTORY`    | Directory where the memory provider persists state to disk.                                              | `config/{dbName}`             |
| `I2SIG_STORE_MEM_SAVE_RATE`    | Interval in seconds between periodic saves. `0` means write on every change.                             | `30`                          |

## Push

Defaults shown as Go `time.Duration` strings (e.g. `1s`, `5m`, `6h`).

| Variable                              | Description                                                                                                                  | Default |
|---------------------------------------|------------------------------------------------------------------------------------------------------------------------------|---------|
| `I2SIG_PUSH_BACKFILL_INTERVAL`        | Interval at which the transmitter re-reads pending JTIs from MongoDB when its in-memory buffer is empty.                     | `1s`    |
| `I2SIG_PUSH_BACKFILL_BATCH`           | Maximum number of events fetched in one backfill operation.                                                                  | `100`   |
| `I2SIG_PUSH_RETRY_BASE_DELAY`         | Initial delay between `/status` probes when push enters TransportBackoff recovery (transport errors / HTTP 5xx).             | `1s`    |
| `I2SIG_PUSH_RETRY_BACKOFF_FACTOR`     | Multiplier applied to the delay after each TransportBackoff probe.                                                           | `2.0`   |
| `I2SIG_PUSH_RETRY_MAX_DELAY`          | Cap on a single TransportBackoff sleep — exponential growth never exceeds this between probes.                               | `5m`    |
| `I2SIG_PUSH_RETRY_LIMIT`              | Total elapsed wall time inside TransportBackoff before the stream is disabled.                                               | `6h`    |
| `I2SIG_PUSH_AUTH_RETRY_DELAY`         | Sleep between `/status` probes while in AuthBounded recovery (HTTP 401 path).                                                | `15s`   |
| `I2SIG_PUSH_AUTH_RETRY_LIMIT`         | Maximum AuthBounded probe attempts before the stream is disabled.                                                            | `10`    |
| `I2SIG_PUSH_PROBE_INTERVAL`           | Cadence at which recoveryLoop re-checks `/status` once it has confirmed the receiver is paused (PausedByRemote mode).        | `30s`   |
| `I2SIG_PUSH_KEEPALIVE_INTERVAL`       | Idle period after which the push loop generates a real SSF verification SET as a keepalive. Set to `0` to disable.            | `5m`    |

## Poll

Receiver-side polling against an upstream SSF transmitter. Defaults shown
as floating-point seconds.

| Variable                            | Description                                                                                                                  | Default        |
|-------------------------------------|------------------------------------------------------------------------------------------------------------------------------|----------------|
| `I2SIG_POLL_PROBE_INTERVAL`         | Interval in seconds to re-check transmitter `/status` while the stream is paused.                                            | `30`           |
| `I2SIG_POLL_RETRY_BASE_DELAY`       | Base delay in seconds for exponential backoff during polling retries.                                                        | `1.0`          |
| `I2SIG_POLL_RETRY_MAX_DELAY`        | Maximum delay in seconds for exponential backoff during polling retries.                                                     | `300.0`        |
| `I2SIG_POLL_RETRY_BACKOFF_FACTOR`   | Factor by which the delay increases during exponential backoff.                                                              | `2.0`          |
| `I2SIG_POLL_RETRY_LIMIT`            | Maximum total time, in seconds, to keep retrying before disabling the stream.                                                | `21600` (6 h)  |
| `I2SIG_POLL_AUTH_RETRY_DELAY`       | Sleep, in seconds, between auth-rejection retries on the poll path.                                                          | `15`           |
| `I2SIG_POLL_AUTH_RETRY_LIMIT`       | Max auth-rejection retry attempts before disabling the stream.                                                               | `10`           |
| `I2SIG_POLL_RESPECT_STATUS`         | `true` (default) — pause polling when the transmitter reports `paused`/`disabled`. `false` — keep polling regardless.        | `true`         |

### Poll transmitter — long-poll timeouts

Inbound poll requests served by this transmitter. Read once at server startup;
must be set uniformly across cluster nodes to avoid receiver-visible variance.

| Variable                       | Description                                                                                                                                                                                                                                                       | Default |
|--------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `I2SIG_POLL_DEFAULT_TIMEOUT`   | Integer seconds. Long-poll timeout applied when the receiver omits `timeoutSecs` (or sends `0`). Set to `0` to disable implicit long-polling — empty buffer + omitted `timeoutSecs` returns immediately.                                                          | `30`    |
| `I2SIG_POLL_MAX_TIMEOUT`       | Integer seconds. Cap applied to receiver-supplied `timeoutSecs`. Values above this are silently clamped (RFC8936 §2.4 makes `timeoutSecs` a SHOULD, so clamping is spec-compliant). Set to `0` to disable the cap entirely.                                       | `300`   |

## TLS

| Variable               | Description                                                                                                       | Default                          |
|------------------------|-------------------------------------------------------------------------------------------------------------------|----------------------------------|
| `I2SIG_TLS_ENABLED`    | Set to `true` to enable HTTPS.                                                                                    | `false`                          |
| `I2SIG_TLS_CERT_PATH`  | Path to the PEM-encoded server certificate.                                                                       | `config/certs/server-cert.pem`   |
| `I2SIG_TLS_KEY_PATH`   | Path to the PEM-encoded server private key.                                                                       | `config/certs/server-key.pem`    |
| `I2SIG_TLS_CA_CERT`    | Path to the CA certificate PEM file. Used to trust the server in clients and to sign certificates via `genTlsKeys`. | `config/certs/ca-cert.pem`      |

## SPIFFE

| Variable                       | Description                                                                                                                                  | Default                        |
|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| `SPIFFE_ENDPOINT_SOCKET`       | Path to the SPIRE agent Unix socket. Setting this enables all SPIFFE features; unset, the server uses HMAC/OAuth mode.                       | _none_ (SPIFFE disabled)       |
| `I2SIG_SPIFFE_TRUST_DOMAIN`    | SPIFFE trust domain for this cluster. Used to authorise peer SVIDs in inter-cluster calls and inbound WakeTransmitter requests.              | `cluster.i2gosignals.internal` |
| `I2SIG_SPIFFE_MONGO_ENABLED`   | If `true`, use SPIFFE X.509-SVID mTLS for MongoDB connections instead of username/password. Requires `SPIFFE_ENDPOINT_SOCKET`.                | `false`                        |

## Dev-only flags

| Variable              | Description                                                                                          | Default |
|-----------------------|------------------------------------------------------------------------------------------------------|---------|
| `PAUSE_FOR_DEBUG`     | Mongo provider pauses for a debugger attach if set to `TRUE`. Development use only — never set in production. | _unset_ |

## `goSignals` CLI

| Variable            | Description                                                                            | Default                    |
|---------------------|----------------------------------------------------------------------------------------|----------------------------|
| `GOSIGNALS_HOME`    | Path to the local administration configuration data.                                   | `~/.goSignals/config.json` |
| `GOSIGNALS_SCRIPT`  | Path to a script file containing goSignals commands to be executed on startup.         | _none_                     |
| `LOG_LEVEL`         | Logging level for the CLI.                                                             | `info`                     |

## `genTlsKeys` dev tool

The `genTlsKeys` tool generates self-signed certificates for development.
Run it via `make generate-certs`.

| Variable          | Description                                                              | Default                    |
|-------------------|--------------------------------------------------------------------------|----------------------------|
| `CERT_DIRECTORY`  | Directory where certificates will be generated and stored.               | `config/certs`             |
| `AUTO_SELFSIGN`   | If `true`, certificates are auto-generated when missing.                 | `true`                     |
| `SERVER_DNS_NAME` | Comma-separated list of DNS names for the server certificate.            | _internal defaults_        |
| `CA_KEYFILE`      | Path where the CA private key will be saved/loaded.                      | `config/certs/ca-key.pem`  |
| `CERT_ORG`        | Organisation name for generated certificates.                            | `goSignals Organization`   |
| `CERT_COUNTRY`    | Country code (e.g. `CA`).                                                | `CA`                       |
| `CERT_PROV`       | Province/State (e.g. `BC`).                                              | `BC`                       |
| `CERT_LOCALITY`   | Locality/City (e.g. `Vancouver`).                                        | `Vancouver`                |

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
