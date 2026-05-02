# Architectural Decision & Regression Log

## [2026-04-10] SPIFFE Dual-Validation Strategy (Resilient MTLS)

### Problem
Strict SPIFFE ID validation in `NewClusterMTLSClientConfig` (using `tlsconfig.AuthorizeMemberOf(td)`) caused regressions for:
1.  **External Connections**: Standard HTTPS endpoints (e.g., JWKS, Public APIs) were rejected because they lack SPIFFE SVIDs.
2.  **Legacy Nodes**: Internal nodes not yet participating in the SPIRE mesh were rejected.
3.  **Hostname Validation**: Hostname checks were often bypassed entirely without a secure alternative for non-SPIFFE connections.

### Solution
Implemented a "Dual-Validation" strategy in `NewResilientMTLSClientConfig`:
1.  **SPIFFE Path**: Attempts to extract a SPIFFE ID from the peer certificate. If the ID belongs to the cluster trust domain, it's validated against the SPIRE trust bundle.
2.  **Standard Path**: If the peer is not a member of the trust domain, it falls back to standard X.509 verification (hostname + chain) using the combined Root CA pool (System + Global CA + SPIRE bundle).

### Invariants
*   Internal `http.Client` instances and database providers MUST use the "Resilient" config when SPIFFE is enabled.
*   The `VerifyConnection` callback MUST NOT return `nil` without performing either a valid SPIFFE check or a valid hostname check.

### Regression Verification (Manual or Test)
1.  Verify connectivity to internal SPIFFE-enabled nodes (e.g., node-to-node wake-ups).
2.  Verify connectivity to external HTTPS endpoints (e.g., `https://google.com` or JWKS loaders).
3.  Verify connectivity to internal nodes using only file-based certificates (Global CA).

---

## [2026-04-10] MongoDB Certificate Rotation Resilience

### Problem
When a MongoDB node's certificate expired, the renewal script's `mongosh` call would fail to connect, preventing it from issuing the `rotateCertificates` command to load a new, valid certificate from disk.

### Solution
Added `--tlsAllowInvalidCertificates` to the `mongosh` command in `config/mongo/mongo_spiffe_init.sh`. This allows the renewal script to "force" a certificate rotation even if the current server certificate is expired.

---

## [2026-04-10] MongoProvider Resource Leak Fix

### Problem
Reconnecting to MongoDB during a SPIRE rotation or network event was leaking `mongo.Client` instances because the previous client was not disconnected.

### Solution
Modified `MongoProvider.connect()` to explicitly call `Disconnect()` on the existing client (if any) before creating a new one.

---

## [2026-04-10] Server-Side Dual-Certificate Strategy (SPIFFE + File-based)

### Problem
Java clients (e.g. `scim_cluster1`) and other legacy tools performing strict hostname verification failed when connecting to `goSignals1` over SPIFFE mTLS. This occurred because the SPIFFE SVID presented by the server during the TLS handshake often lacks the DNS SANs (like `goSignals1`) required by standard `HostnameChecker` implementations, especially when SNI is missing.

### Solution
Enhanced the `GetCertificate` callback in `InitTransportLayerSecurity` to use a "Dual-Certificate" selection strategy:
1.  **SNI Match**: If the client provides an SNI, we try to match it against the SPIFFE SVID first, then the file-based certificate.
2.  **Fallback/Default**: If no SNI is provided or no match is found, we now prefer the **file-based certificate** as the default (if available). Since the file-based certificate (signed by the Global CA) contains all necessary DNS SANs, it ensures compatibility with legacy hostname-based clients.
3.  **SPIFFE Compatibility**: Internal SPIFFE-aware nodes (using our "Resilient" client config) correctly handle receiving the file-based certificate by falling back to standard X.509 verification against the combined CA pool (which includes the Global CA).

### Invariants
*   The server MUST be configured with both `TLS_ENABLED=true` and `SPIFFE_ENDPOINT_SOCKET` to enable this dual-certificate behavior.
*   The file-based certificate (`server-cert.pem`) MUST contain the hostnames (DNS SANs) used by legacy clients.

---

## [2026-04-12] SPIFFE/MongoDB Cluster Health Monitoring & Resilience

### Problem
A crash in `spire-agent` (caused by `join_token` re-attestation failure) stopped the certificate renewal loop for MongoDB. This eventually led to certificate expiration and a full cluster outage as the replica set nodes could no longer communicate.

### Solution
1.  **Automated Recovery**: Added `restart: unless-stopped` to `spire-agent` and all MongoDB nodes in `docker-compose-spiffe-dev.yml`. This ensures that if the agent or a database node crashes, Docker will attempt to restart it automatically.
2.  **Cluster Health Monitor**: Implemented a new `cluster-monitor` service (`cmd/cluster-monitor`) that periodically checks:
    - SPIRE Agent health (Workload API connectivity).
    - MongoDB Replica Set status and node health.
    - On-disk certificate expiration (`mongo.pem`, `ca.pem`).
3.  **Enhanced Renewal Loop**: Improved `config/mongo/mongo_spiffe_init.sh` to log detailed errors when the agent is unreachable or when `rotateCertificates` fails, facilitating faster diagnosis.

### Invariants
*   Critical infrastructure services (`spire-agent`, `mongodb`) MUST have an automated restart policy.
*   The `cluster-monitor` MUST have access to the SPIRE agent socket and the certificate volume to perform its checks.

---

## [2026-04-12] SPIRE Agent Self-Healing (Bootstrap Trust)

### Problem
After a full docker restart, the `spire-agent` would fail to re-attest with error `x509: certificate signed by unknown authority`. This occurred because the agent persisted its old trust bundle and node data from a previous run, which did not match the (potentially reset) SPIRE server's new CA. Since `insecure_bootstrap` only works when no bundle exists, the agent became stuck.

### Solution
Modified the `spire-agent` entrypoint in `docker-compose-spiffe-dev.yml` to automatically clear ALL persisted state files in the data directory if:
1.  A new `joinTokenFile` is present.
2.  `insecure_bootstrap = true` is configured in `agent.conf`.
This ensures a truly clean state (removing `agent-data.json`, `keys.json`, etc.) and forces the agent to perform a fresh, insecure bootstrap from the server, fetching the new trust bundle and resolving the TLS mismatch.

### Regression Verification
1.  Verified that `cmd/cluster-monitor` unit tests pass, ensuring core health check logic is stable.
2.  Self-healing logic in `docker-compose-spiffe-dev.yml` ensures cluster recovery after full environment resets by removing both binary (`.der`, `.pem`) and JSON (`agent-data.json`, `keys.json`) state files.

---

## [2026-04-12] Cluster Monitor SPIFFE/mTLS Alignment

### Problem
The `cluster-monitor` failed to connect to MongoDB with a TLS error: `x509: certificate is not valid for any names`. This occurred because the monitor was using standard hostname verification on SPIFFE SVIDs that lack DNS SANs. Additionally, its certificate health check incorrectly reported trust bundles as "expired" if an old CA certificate preceded valid ones in the same file.

### Solution
1.  **Resilient Configuration**: Updated `cluster-monitor` to use the `tlsSupport.NewResilientMTLSClientConfig` for MongoDB health checks. This aligns its connection logic with the rest of the application, skipping hostname verification for peers within the cluster trust domain.
2.  **Multi-Certificate Bundle Support**: Enhanced `checkCertificate` to parse all PEM blocks in a file. A file is only reported as expired if ALL certificates within it are expired, reflecting the real-world behavior of trust bundles.
3.  **Proactive Monitoring**: Enabled `SPIFFE_MONGO_ENABLED=true` for the monitor in `docker-compose-spiffe-dev.yml` to ensure it uses mTLS for all health checks.

### Regression Verification
1.  Verified that `cmd/cluster-monitor` unit tests pass, including a new test case for multi-certificate bundles.
2.  Validated that the monitor correctly reports "Healthy" when a bundle contains both an expired and a valid CA certificate.

## [2026-04-12] SPIFFE/Cluster Monitoring Documentation

### Problem
New cluster resilience features (Cluster Monitor, Self-healing Agent, etc.) were added to the codebase but not documented in the main SPIFFE support guide, making it difficult for developers and operators to understand and use these tools effectively.

### Solution
Updated `docs/spiffe_support.md` to include:
1.  **Cluster Health Monitoring**: A new section detailing the `cluster-monitor` service, its monitored areas (SPIRE, MongoDB, Certs), and its configuration.
2.  **Self-healing Bootstrap**: Documented the agent's new entrypoint logic that clears stale state during fresh bootstraps.
3.  **Troubleshooting with Monitor**: Added a troubleshooting subsection on how to use `cluster-monitor` logs to diagnose outages.
4.  **Environment Variables**: Added `MONITOR_INTERVAL` to the reference table.

### Invariants
*   Major cluster changes MUST be documented in `docs/spiffe_support.md`.
*   Operational notes and troubleshooting guides MUST be kept up-to-date with new resilience features.

---

## [2026-04-13] SPIRE Agent & MongoDB Rotation Deadlock Fix

### Problem
1.  **SPIRE Agent Restart Loop**: The self-healing logic added on 2026-04-12 caused an infinite restart loop. It cleared agent state on every restart if a `joinTokenFile` existed. Since tokens are single-use and the file persisted in the volume, subsequent restarts failed to attest, leading to continuous crashes.
2.  **MongoDB Rotation Deadlock**: When certificates expired during SPIRE agent downtime, the renewal script could not reconnect to MongoDB to issue `rotateCertificates` because MongoDB rejects expired client certificates.
3.  **Renewal Loop Fragility**: The background renewal loop in `mongo_spiffe_init.sh` could exit silently due to `set -e` on transient errors, and it blindly picked the first SVID returned by the agent.

### Solution
1.  **Join Token Idempotency**: Modified `spire-agent` entrypoint to move the join token to `.used` and pass it to the agent via `-joinToken` ONLY if the agent's data directory appears empty. This version explicitly sanitizes the token (removing potential whitespaces/newlines) and uses the direct token value to ensure robust attestation across bootstrap retries, while still preventing "token already used" errors once the agent is successfully bootstrapped and restarted.
2.  **Robust Renewal Loop**:
    - Added `set +e` to the background loop in `mongo_spiffe_init.sh` to prevent it from exiting.
    - Implemented SPIFFE ID validation to find the correct `workload/mongodb` SVID among multiple returned identities.
    - Improved `rotateCertificates` to try both the "previous" and "current" certificates, increasing the chance of a successful hot-reload.
    - Added explicit logging for rotation failures, noting that node restarts (triggered by healthcheck failures) will eventually resolve expiration deadlocks if the certs on disk are updated.
    - Modified `spire-agent` script to put in proper escaping in TOKEN_VAL calculation  (docker reported a phantom TOKEN_ARG unset error)

### Invariants
*   The `spire-agent` MUST NOT clear its data directory unless a fresh, unused join token is present.
*   The MongoDB renewal script MUST continue its loop even if individual rotation calls or agent fetches fail.

---

## [2026-04-13] Hardened Container Health Checks (No-curl strategy)

### Problem
The project switched to Chainguard "hardened" images (`cgr.dev/chainguard/bash`) for production builds. These images lack `curl`, `wget`, and other standard network utilities, which broke the `docker-compose-spiffe.yml` health checks that relied on `curl` to verify application health.

### Solution
1.  **Custom Health Check Tool**: Created a minimal Go-based health check utility in `cmd/healthcheck/main.go`. This tool performs HTTP(S) GET requests, supports insecure TLS (for internal mTLS endpoints), and has configurable timeouts.
2.  **Built-in Binary**: Added the `healthcheck` binary to the `Dockerfile` and `build.sh` so it is always available in the `i2gosignals` container without adding extra OS-level dependencies.
3.  **Composition Alignment**: Updated `docker-compose-spiffe.yml` to use `/app/healthcheck` for `goSignals1`, `goSignals2`, and `goSsfServer`.
4.  **Image Standardisation**: Updated `docker-compose-spiffe.yml` to use the official `independentid/i2gosignals:latest` image for all project-related services, ensuring they run the same hardened environment.

### Invariants
*   Health checks in hardened images MUST NOT depend on external OS packages like `curl`.
*   The `healthcheck` tool MUST be included in all production-ready images built from `Dockerfile`.

---

## [2026-04-14] MongoDB Replica Set Startup & Auth Fix (docker-compose-dev)

### Problem
In `docker-compose-dev.yml` and `docker-compose.yml`, MongoDB services (`mongo1`, `mongo2`, `mongo3`) and the `mongo-init` setup job failed to start properly because:
1.  **Script Permissions**: `config/mongo/mongo_init.sh` was not executable on the host, causing "Permission denied" in the container.
2.  **TLS Mismatch**: `mongo_init.sh` unconditionally waited for TLS certificates and used `--tls` for `mongosh`, but the dev environment is non-TLS.
3.  **Auth Initialization Bypass**: The `command` for MongoDB nodes used `exec mongod`, which bypassed the official image's `docker-entrypoint.sh` logic. This prevented the `MONGO_INITDB_ROOT_USERNAME` from being processed, leading to "UserNotFound" errors when `mongo-init` tried to connect.

### Solution
1.  **Robust Initialization Script**: Updated `config/mongo/mongo_init.sh` to:
    -   Use `set -e` for better error handling.
    -   Check for certificates and only use TLS if they exist.
    -   Implement a retry loop for the initial connection to allow `mongod` time to initialize.
2.  **Entrypoint Alignment**: Updated `docker-compose-dev.yml` and `docker-compose.yml` to:
    -   Execute `mongo_init.sh` via `bash` to avoid permission issues.
    -   Call `/usr/local/bin/docker-entrypoint.sh mongod ...` instead of `mongod ...` directly. This ensures that the root user is created during the first-run initialization.
3.  **Permissions**: Made `config/mongo/mongo_init.sh` executable on the host.

### Invariants
*   The `mongo-init` service MUST use `bash /scripts/mongo_init.sh` to execute the setup script.
*   MongoDB node `command` overrides MUST call `docker-entrypoint.sh` if `MONGO_INITDB` environment variables are used for user creation.
*   `mongo_init.sh` MUST support both TLS and non-TLS modes based on the presence of certificates.

---

## [2026-04-27] MongoDB Initialization Deadlock Fix (docker-compose-dev)

### Problem
The `mongo-init` service in `docker-compose-dev.yml` would sometimes hang indefinitely with "Waiting for primary" logs. This was caused by several issues in `config/mongo/mongo_init.sh`:
1.  **Invalid Shell Helper**: The script used `rs.isMaster().ismaster` in a `while` loop. `rs.isMaster` is not a standard helper in `mongosh`, and its incorrect use led to an infinite loop.
2.  **Invalid API Usage**: `rs.initiate` was called with a second argument `{ force: true }`, which is only valid for `rs.reconfig`.
3.  **Lack of Idempotency**: The script attempted to call `rs.initiate` without checking if the replica set was already initiated, leading to errors on subsequent runs.
4.  **Single-Host Connection**: User creation was attempted on a single host (`mongo1`) which might not have been the primary.

### Solution
Refactored `config/mongo/mongo_init.sh` to align with the more robust patterns used in `mongo_spiffe_init.sh`:
1.  **Idempotency Check**: Added a check using `rs.status()` to skip initiation if the replica set is already configured.
2.  **Correct API Usage**: Removed the invalid `{ force: true }` argument from `rs.initiate`.
3.  **Robust Primary Wait**: Replaced the Javascript-based wait loop with a Bash-based `until` loop using `db.hello().isWritablePrimary` and a multi-host replica set connection string.
4.  **Primary-Aware User Creation**: Updated user creation commands to use a multi-host connection string, ensuring they are executed on the primary node.
5.  **SPIFFE Alignment**: Corrected a similar invalid `{ force: true }` argument in `mongo_spiffe_init.sh`.

### Invariants
*   The `mongo-init` script MUST be idempotent and check `rs.status()` before initiating.
*   Waiting for primary SHOULD use `db.hello().isWritablePrimary` as it is the modern replacement for `isMaster`.
*   Commands requiring primary (like user creation) MUST use a connection string that includes all replica set members.

## [2026-04-30] Keycloak Scope Claim Array Fix (Realm Config)

### Problem
Keycloak was emitting the `scope` claim as a JSON array because it was using the `oidc-usermodel-realm-role-mapper` with `multivalued: true` to map realm roles to scopes. This caused parsing errors in the Go backend which strictly expects a space-separated string for interoperability and OIDC compliance.

### Solution
1.  **Realm Configuration Fix**: Modified `gosignals-realm.json` to replace the problematic `roles-as-scope` mapper with an `oidc-script-based-protocol-mapper`. The script explicitly joins the user's realm roles into a single space-separated string, fulfilling the interoperability requirement while still conveying role-based permissions in the `scope` claim.
2.  **Strict Go Types**: Maintained the `string` type for `Scope` in `OidcClaims` and `EventAuthToken` structs. Reverted any attempts to use flexible parsing (e.g., `ScopeClaim` type) to ensure the codebase remains aligned with OIDC standards.

### Invariants
*   The `scope` claim MUST ALWAYS be a single string.
*   The Go backend will NOT support array-based `scope` claims; production configurations must ensure the issuer provides the correct format.

---

## [2026-04-30] Keycloak Client Scope & Role Fix

### Problem
Service clients `goSignalsAdminService` and `goSignalsClient` were not receiving realm roles or standard scopes (profile, email) in their tokens. This prevented them from having roles similar to the `adminui` client, even when performing token exchange or acting as service accounts.

### Solution
1.  **Full Scope Enabled**: Set `fullScopeAllowed: true` for both `goSignalsAdminService` and `goSignalsClient`. This allows the clients to access realm roles without needing explicit scope mappings for every role.
2.  **Default Scopes**: Added `web-origins`, `profile`, `roles`, and `email` to `defaultClientScopes` for both clients to match the configuration of `adminui`.

### Invariants
*   Service clients that need to represent users or perform administrative tasks MUST have `fullScopeAllowed: true` or explicit scope mappings for required roles.
*   Standard OIDC scopes (`profile`, `email`, `roles`) SHOULD be included in `defaultClientScopes` if the client expects these claims in the token.

### Regression Verification
1.  Verify `config/keycloak/realm/gosignals-realm.json` has `fullScopeAllowed: true` for the affected clients.
2.  Verify `defaultClientScopes` includes `roles`, `profile`, and `email` for these clients.

