# Architectural Decision & Regression Log

## [2026-05-06] Mongo DAOs hold rebindable collections; swap-on-reconnect retired

### Change
Each Mongo DAO now holds its `*mongo.Collection` behind an
`atomic.Pointer[mongo.Collection]` (wrapped in a tiny `collectionRef`
helper, `internal/dao/mongo/collection_ref.go`). Each DAO exposes
`SetCollection(*mongo.Collection)` (or `SetCollections(...)` for
`EventDAOMongo`'s three-collection case).

`MongoProvider.initialize()` no longer constructs new DAOs and a new
`*BaseProvider` on every reconnect. Instead it rebinds the existing
DAOs' collection pointers in place:

```go
m.BaseProvider.GetStreamDAO().(*mongodao.StreamDAOMongo).SetCollection(m.streamCol)
m.BaseProvider.GetEventDAO().(*mongodao.EventDAOMongo).SetCollections(eventCol, pendingCol, deliveredCol)
// ... etc
```

The same long-lived `BaseProvider`, services, and `AuthIssuer` survive
across reconnects; only their underlying collections are rotated.

### Why this carries weight
- **Eliminates the swap-on-reconnect race window.** Previously, every
  reconnect replaced `m.BaseProvider` behind an `RWMutex`. A caller
  holding a method reference (`sa.Provider.GetStreamDAO()`) could end
  up calling against a stale BaseProvider whose collection pointers
  had been freed. The atomic-pointer rebind path doesn't have this
  shape: in-flight callers see either the old or the new collection,
  never a partial state, and the `*BaseProvider` value is stable.
- **Drops the wrapper-method tax.** With BaseProvider stable, the ~160
  wrapper methods on `MongoProvider` that existed solely to mediate
  the swap can go away in #47.
- **Unblocks the BaseProvider deletion.** With DAO collections rebound
  in place, "delete `BaseProvider`, hold services directly" becomes a
  consumer-side rewire only (#47 scope).

### Invariants
- A long-held DAO reference (e.g. `provider.GetKeyDAO()`) remains
  operational across `ResetDb(true)`. Verified by
  `mongo_provider/test/rebind_test.go::TestKeyDAOSurvivesReset`.
- Concurrent writes during a `ResetDb` storm complete or fail cleanly
  with no panics and no nil-pointer dereferences. Verified by
  `TestConcurrentWritesDuringRebind` under `-race`.
- Post-`ResetDb`, the `AuthIssuer` instance is *the same object* (no
  more swap) but its signing material is fresh. The behavioural test
  (`TestNewApplication_LazyAuthRefresh`) was updated to assert key
  freshness instead of object identity.

### Regression Verification
- `go test -race -timeout 300s ./internal/...` — green incl. the new
  `RebindTestSuite` and the updated `LazyAuthRefresh` test.
- `go test -race -timeout 600s ./pkg/...` — green incl. the server
  integration suite (~125s).
- `go vet ./...` — pre-existing warnings only.

---

## [2026-05-06] CreateStream logic lifted from BaseProvider into StreamService

### Change
Two pieces of logic moved out of `common.BaseProvider.CreateStream` and
into `services.StreamService.CreateStream`:

1. **`tx_alias` resolution.** `StreamService` now holds an optional
   `*ServerService` (set via `SetServerService`). `BaseProvider` wires
   the dependency at construction time. When a `StreamConfiguration`
   carries `TxAlias`, the service resolves it to a `Server` before the
   rest of the pipeline runs.
2. **Case-insensitive `IssuerJWKSUrl == "NONE"` normalisation.** SCIM
   servers signal "key is internal" with NONE; downstream code expects
   empty.

After the lift, `BaseProvider.CreateStream` is a pass-through:
auth-context plumbing + service call + `notifyWrite` fan-out.

### Why this carries weight
The two pieces of logic are the only real behaviour `BaseProvider`
carried beyond pure delegation. Lifting them is the prerequisite for
deleting `BaseProvider` outright in #47 — once it's a pure
pass-through, removing it is a consumer-side rewire only.

### Regression Verification
- New unit tests in `internal/services/stream_service_txalias_test.go`
  cover unknown-alias error, known-alias resolution, and NONE
  normalisation, all without spinning up a provider.
- Existing `internal/services/...` and
  `internal/providers/dbProviders/...` suites unchanged.

---

## [2026-05-06] Cluster coordination and storage extracted as their own seams

### Change
The provider chain previously bundled cluster lease/node-registry methods,
storage lifecycle, services, and auth bridges behind one god-interface
(`DbProviderInterface`). PR slice 3 of PRD #39 splits the cluster and
lifecycle concerns into their own narrow interfaces:

- New `internal/providers/cluster.ClusterCoordinator` interface owns the
  seven lease + node-registry methods (TryAcquireOrRenewLease, ReleaseLeaseIfOwned,
  GetLeaseOwner, RegisterNode, GetActiveNodeCount, GetActiveNodes, GetNode).
- New `internal/providers/storage.Storage` interface owns the five lifecycle
  methods (Name, Check, Close, ResetDb, SetBaseUrl).
- New `dbProviders.Persistence` composition record bundles
  `{ Provider, Coordinator, Storage }`. `OpenPersistence(url, db)` returns it;
  `OpenProvider(...)` is preserved as a thin wrapper for legacy callers.
- New `MongoCoordinator` (`mongo_provider/cluster_coordinator.go`) holds the
  existing Mongo `FindOneAndUpdate` lease logic verbatim. Collections are
  rebound atomically via `SetCollections` after each (re)connect, eliminating
  the BaseProvider-swap dance for cluster ops.
- New `MemoryCoordinator` (`memory_provider/cluster_coordinator.go`) replaces
  the old single-node stub with **real** lease semantics: atomic acquire under
  a mutex, time-based expiry, strict fencing-token monotonicity per resource,
  and compare-and-release for `ReleaseLeaseIfOwned`. Five new unit tests pin
  these invariants down (mutual exclusion under 50-goroutine contention,
  takeover after expiry, fencing-token monotonicity, release semantics, and
  60s active-window node filtering).
- Consumers (`SignalsApplication`, `SsfApplication`, EventRouter, prometheus
  collector, api_receiver poll-receiver lease loop) now call `sa.Coordinator.X`
  / `r.coordinator.X` instead of `sa.Provider.X`. The provider methods remain
  in place as thin delegators so existing tests and the legacy
  `DbProviderInterface` continue to compile until PR 4 deletes the interface.

### Why this carries weight
- **Cluster invariants are now unit-testable.** Mutual exclusion, expiry, and
  fencing-token monotonicity were previously only exercised by docker-compose
  suites; the MemoryCoordinator tests run in <5s under `-race`.
- **Reconnect simplifies.** `MongoCoordinator` uses `atomic.Pointer[mongo.Collection]`
  for its lease/node collection refs. PR 4 will use the same pattern across
  all DAOs to drop the swap-`*BaseProvider` pattern entirely.
- **The bson import vanishes from the cluster surface.** `cluster.ClusterCoordinator`
  and its callers depend only on `pkg/ssfModels` types — no Mongo driver
  reachable from `eventRouter`, `application.go`, `api_receiver.go`, or the
  prometheus collector.

### Scope held back
`DbProviderInterface` *still carries* the cluster and lifecycle method
declarations. Removing them would propagate to ~30 call sites that already
have the new seams available; that diff is rolled forward to PR 4 (BaseProvider
deletion) where the entire interface goes away. Until then, callers may use
either path; the seam is the canonical one.

### Invariants
- `MemoryCoordinator` and `MongoCoordinator` honour the same contract — mutual
  exclusion, monotonic fencing tokens, owner-only release, 60s active-window.
- Both providers expose `Coordinator() cluster.ClusterCoordinator`. Type
  assertion at the consumer boundary stays clean.
- `Persistence.Coordinator` and `Persistence.Storage` are guaranteed non-nil
  after `OpenPersistence` succeeds.

### Regression Verification
- `go test -race -timeout 300s ./internal/...` (incl. Mongo integration suite)
- `go test -race -timeout 600s ./pkg/...` (incl. server integration suite)
- `go vet ./...` — no new warnings (pre-existing warnings in pkg/goScim,
  pkg/ssfModels, cmd/cluster-monitor unchanged).

---

## [2026-05-06] String IDs across persistence interfaces; bson.ObjectID becomes Mongo-internal

### Change
Persistence interfaces and DAO types no longer expose `bson.ObjectID`:

- `DbProviderInterface.AddEventToStream(jti, streamId)` and `WatchPending` now take string IDs.
- `interfaces.EventDAO.AddPending` and `interfaces.EventDAO.WatchPending` callback take string IDs.
- `interfaces.JwkKeyRec.Id` and `interfaces.DeliverableEvent.StreamId` are now `string`.
- `provider_interface.go` and `dao_interfaces.go` no longer import `go.mongodb.org/mongo-driver/v2/bson`.

The Mongo adapter keeps `bson.ObjectID` as the on-disk storage type for backward
compatibility with existing data. New private doc types (`keyDoc`, `pendingDoc`,
`deliveredDoc`) inside `internal/dao/mongo/` mirror the public records but carry
`bson.ObjectID` for `_id`/`sid`. Conversion happens at the read/write boundary.

A new helper package `internal/dao/ids` provides `ids.NewObjectID() string` —
a 24-character lowercase hex string generated from `crypto/rand`. Memory and
service callers use this helper instead of `bson.NewObjectID().Hex()`. The
format matches MongoDB ObjectID hex so existing IDs remain round-trip safe
through `mongo.ParseObjectID`.

### Out of scope (deferred to PRD #39 PR 4)
The bson type leak remains in `pkg/ssfModels` for `StreamStateRecord.Id`,
`SsfClient.Id`, and `Server.Id`. Those public model types are migrated as
part of the BaseProvider deletion / handler refactor in PR 4. Until then,
callers must continue to use `record.Id.Hex()` to produce the string form
when calling persistence methods that take string IDs. EventRouter already
does this at all four call sites (`event_router.go:201, 527, 554, 586`).

### Invariants
- The DAO interface and provider interface have NO Mongo driver dependency.
  Adding a Postgres or etcd adapter no longer requires importing bson to
  satisfy the seam.
- Mongo storage shape is unchanged: `_id` is `bson.ObjectID`, `sid` is
  `bson.ObjectID`. Existing data round-trips identically.
- Memory DAOs use string IDs natively — no parse / convert step on the hot
  path.
- ID generation in service-layer code (key minting, kid suffixes) goes
  through `ids.NewObjectID()`. Direct `bson.NewObjectID()` calls remain only
  for `StreamStateRecord.Id` minting in `StreamService.CreateStream` (PR 4).

### Regression Verification
- `go test -race -timeout 300s ./internal/... ./pkg/...`
- `go vet ./...` (no new warnings)
- Mongo round-trip: `internal/providers/dbProviders/mongo_provider/test/...`
  exercises Insert→Find paths over the new private doc types.

---

## [2026-05-06] Receiver-stream predicate lifted from DAOs into `StreamService`

### Change
The "find receiver streams" filter previously lived in both stream DAOs and had drifted:
- `StreamDAOMongo.FindReceiverStreams` filtered `route_mode == "import"`.
- `StreamDAOMemory.FindReceiverStreams` filtered `state.IsReceiver()` (delivery method
  is `ReceivePush` or `ReceivePoll`).

These predicates are not equivalent. `RouteMode` describes routing intent (publish /
import / forward) and is independent of delivery direction. A `ReceivePush` stream
may legitimately be in any RouteMode, and a `DeliveryPush` stream in `RouteModeForward`
is not a receiver but is also not import-mode.

`FindReceiverStreams` is removed from `StreamDAO` and both implementations. The
canonical predicate is `StreamStateRecord.IsReceiver()`, applied once in the new
`StreamService.ListReceiverStreams` (a pure query) and reused by the existing
`StreamService.LoadReceiverStreams` (load + warm cache + JWKS).

### DAO audit (sibling concern)
Audit of remaining DAO methods for adapter-divergent behaviour:
- `EventDAO.WatchPending` — Mongo opens a change stream; memory blocks on `ctx.Done()`.
  Intentional divergence: change streams are a Mongo-only capability. The memory
  no-op is correct because file-backed memory mode has no equivalent push-notification
  primitive; recovery there relies on the backfill ticker.
- All other DAO methods (CRUD + simple project/stream-id equality matches) behave
  equivalently across adapters.

### Invariants
- DAOs hold storage operations only — no business predicates beyond field-equality
  filters that map directly to a Mongo query expression and a memory linear scan.
- The receiver-stream predicate (`IsReceiver()`) is the only place that decides
  whether a stream is a receiver. Future code MUST consult `StreamStateRecord.IsReceiver()`
  or `StreamService.ListReceiverStreams` rather than re-deriving the predicate from
  `RouteMode` or `Delivery.Method`.

### Regression Verification
- `go test -race ./internal/services/... -run TestStreamService_ListReceiverStreams`
- `go test -race ./internal/dao/...`
- `go test -race ./internal/...`

---

## [2026-05-06] Stream `remote_address` field on StreamStateRecord

### Change
`StreamStateRecord` now carries a `*RemoteIP` (`pkg/ssfModels`) populated for all four
delivery modes — `ReceivePush`, `DeliveryPoll` (inbound, from `r.RemoteAddr` and
`X-Forwarded-For`/`X-Real-IP`), and `DeliveryPush`, `ReceivePoll` (outbound, captured
via `httptrace.WithClientTrace` on the resolved TCP peer). It surfaces in stream
state JSON as `remote_address` with `protocol`, `ip`, and `forwarded` sub-fields,
omitted on streams that have never had a successful connection.

### Invariants
- Capture happens only after authorization succeeds — unauthenticated probes never
  pollute the field.
- `X-Forwarded-For` / `X-Real-IP` are stored as informational metadata only; no auth
  or trust path consumes them.
- Mongo persistence uses a `$set` scoped to `remote_address`, so it does not race
  with concurrent `UpdateStreamStatus` writes on the same document.
- `pushEvent` and `runPollLoop` mirror the persisted value back into their local
  stream pointer after a successful update so the only-when-changed guard on the
  next iteration short-circuits instead of issuing redundant DB writes (see
  regression #27).

### Regression Verification
- `go test ./pkg/ssfModels/...`
- `go test ./internal/eventRouter/... -run TestPushEvent_`
- `go test ./pkg/goSignals/server/test/... -run TestRemoteAddressSuite`

---

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

