# i2goSignals — Architecture Glossary

This file captures the vocabulary that emerged from the PRD #39 provider-chain
collapse. New contributors and AI agents should share these terms when reading
or modifying the persistence layer.

## Provider chain (post-collapse)

The persistence chain is now flat:

    handlers / event router → service (StreamService, EventService, …) → DAO → driver

There is no longer a god-interface (`DbProviderInterface`) or a god-object
(`common.BaseProvider`) sitting between handlers and services. Each consumer
depends on the narrowest seam it actually uses.

## Vocabulary

### Persistence record

`*dbProviders.Persistence` — the composition root returned by
`dbProviders.OpenPersistence(url, dbName)`. It bundles the per-domain
services, the cluster coordinator, and the lifecycle storage seam:

```go
type Persistence struct {
    StreamService *services.StreamService
    KeyService    *services.KeyService
    EventService  *services.EventService
    ClientService *services.ClientService
    ServerService *services.ServerService
    TokenService  *services.TokenService

    Coordinator cluster.ClusterCoordinator
    Storage     storage.Storage
}
```

Callers should depend on the narrowest field they need (one service, or
`Coordinator`, or `Storage`) — not pull the whole record around.

### ClusterCoordinator

`internal/providers/cluster.ClusterCoordinator` — the seam that owns
distributed-lease and node-registry state. Two implementations:

- **`MongoCoordinator`** — production. Uses MongoDB
  `FindOneAndUpdate` for atomic acquire/renew/release, with monotonic
  fencing tokens and 30s leases (10s heartbeats). Backed by
  `cluster_leases` and `cluster_nodes` collections.
- **`MemoryCoordinator`** — in-process. Real semantics, not a stub:
  mutual exclusion under concurrent acquire, lease takeover after
  expiry, fencing-token monotonicity, `ReleaseLeaseIfOwned` semantics,
  active-node filtering by heartbeat freshness. Used by unit tests to
  exercise lease invariants without docker.

### Storage seam

`internal/providers/storage.Storage` — the lifecycle surface (`Name`,
`Check`, `Close`, `ResetDb`, `SetBaseUrl`). Decoupled from data access
so health checks and shutdown paths don't drag the whole god-interface
in. One implementation per adapter (`MemoryStorage`, `MongoStorage`).

### PushDelivery

`internal/eventRouter/delivery.PushDelivery` — the one-attempt push-side
delivery seam consumed by the router's push loop. One method:
`Deliver(ctx, PushRequest) PushOutcome` "given a stream config, an event
record, a signing key, and a kid, sign-or-forward the SET, push it to
the receiver, return the goSetPush.Classification + captured peer
address + (possibly-rotated) key and kid."

Two adapters, prior art `ClusterCoordinator` from PRD #39:

- **`HTTPAdapter`** — production. Owns JWT signing, httptrace peer
  capture, `goSetPush.PushSET`, `goSetPush.ClassifyResult`, the
  stream's RemoteAddress persistence via `StreamService`, and the
  RFC8935 §2.4 `jws_signature_failed` rotate-and-retry sub-policy
  (one retry, via the injected `KeyReloader`). For forward-mode
  streams the retry is skipped (no local signing material to rotate).
- **`MemoryAdapter`** — tests. Returns scripted `PushOutcome`s
  (single value or a sequence). Goroutine-safe. Used by router-level
  tests that want deterministic classification outcomes without
  standing up an HTTP receiver.

Scope discipline: the seam covers one delivery attempt. Recovery
cadence, lease heartbeats, retry policy, backfill, and cluster
wake-ups stay in the router — the router consumes the classification
and decides what to do next. `PollDelivery` (the symmetric poll-side
seam) is deferred to a follow-up PRD.

### EventService.MatchesStream

`(*EventService).MatchesStream(stream, event) bool` — the SET-to-stream
routing predicate. Owns the direction/iss/aud/event-type filter that
decides whether a given `AgEventRecord` should be delivered to a given
`StreamStateRecord`. Pure predicate: touches no DAO state.

Previously a free function `eventRouter.StreamEventMatch` in the
router package. Lifted into `EventService` so the predicate sits next
to the rest of the event-routing surface and can be unit-tested
without constructing a router. Same fat-services / thin-DAOs rule
that brought the receiver-stream predicate together under
`StreamService` in PRD #39.

### Fat services / thin DAOs

The architectural principle: business logic, predicates, caching, and
cross-DAO coordination belong in services. DAOs are storage operations
only — no predicates, no `if`-trees, no domain reasoning.

This rule has historical weight. Before PRD #39 the receiver-stream
predicate had drifted between adapters
(`StreamDAOMongo.FindReceiverStreams` filtered on `route_mode == "import"`;
`StreamDAOMemory.FindReceiverStreams` used `state.IsReceiver()` —
different predicates that the memory adapter's tests covered while the
Mongo path silently diverged). Lifting predicates into the service is
the structural fix that keeps the two adapters in lockstep.

### Fencing token

Monotonically increasing per-resource counter handed back from
`TryAcquireOrRenewLease`. Callers tag externally-visible operations
(e.g. ack-event, push-receipt) with the fencing token so a stale node
that lost its lease can be rejected at the boundary even if it's still
trying to write. The `MemoryCoordinator`'s contract guarantees the
token never moves backward across the lifetime of a coordinator
instance, even after takeover.

### Rebindable collection

The atomic-pointer pattern Mongo DAOs use to survive a
`ResetDb(true)` / reconnect without invalidating service references.
Each Mongo DAO holds its `*mongo.Collection` behind an
`atomic.Pointer[mongo.Collection]`. On reconnect the provider calls
`SetCollection(newCol)` on each DAO; in-flight readers see either the
old or the new collection, never a partial state. Replaces the
pre-PRD #39 swap-on-reconnect path that rebuilt the entire
`*BaseProvider` behind an `RWMutex`.

### Notifying DAO (memory)

Per-DAO decorator wrappers used only by the in-memory adapter. Each
wraps an `interfaces.X` DAO and fires a `notify()` callback after
every successful mutation. Used by `MemoryProvider` to drive
file-backed persistence (`MarkDirty` → save loop). Mongo carries no
decorator and pays no overhead — the memory adapter is the only path
that needs after-mutation hooks.

Replaces the `WriteHook` / `SetWriteHook` / `afterWrite` /
`notifyWrite` plumbing previously threaded through ~25 BaseProvider
methods.

## What got deleted

- **`DbProviderInterface`** (`internal/providers/dbProviders/provider_interface.go`)
  — the 50-method god-interface. Bundled four unrelated concerns
  (service-shaped data access, cluster coordination, lifecycle, auth
  bridges) and forced any change to ripple through both adapters.
- **`common.BaseProvider`** (`internal/providers/dbProviders/common/base_provider.go`)
  — a 323-line pass-through whose only real logic was two lines
  inside `CreateStream` (since lifted into `StreamService`). Every
  other method delegated to a service. Embedded by both providers
  solely to satisfy the god-interface.
- **`OpenProvider`** — replaced by `OpenPersistence`. New callers
  should always reach for the latter.

## Package boundaries

The server handler tree (`application.go`, `routers.go`, `api_*.go`, and
their tests) lives in `internal/server`. `pkg/goSignals/` retains only
genuinely library-shaped contents: the OpenAPI client (`api/`), the
swagger UI assets (`swagger-ui/`, `swagger.go`), and the `Dockerfile`.

Known debt: `pkg/goSsfServer/ssf-application.go` (a demo receiver)
imports `internal/server`, crossing the `pkg/` → `internal/` boundary.
Reabsorbing `pkg/goSsfServer` into `internal/` (or `cmd/goSsfServer/`)
is deferred — recorded in PRD #50 Out of Scope.

## Adding a new persistence method

1. Add the method to the appropriate **DAO interface**
   (`internal/dao/interfaces/`). DAOs are storage-only.
2. Implement it in **both** DAO adapters (`internal/dao/memory/` and
   `internal/dao/mongo/`). Keep them mechanically equivalent — any
   business logic that varies between adapters is a service-level
   concern, not a DAO concern.
3. Add the corresponding method to the **service** that owns the
   business surface (`StreamService`, `EventService`, etc.). This is
   where predicates, caching, and cross-DAO coordination live.
4. Handlers depend on the service, not on the DAO.

## Adding a new persistence adapter (e.g. Postgres)

Implement the three small seams:

- DAO interfaces in `internal/dao/interfaces/`.
- `cluster.ClusterCoordinator`.
- `storage.Storage`.

Then wire `dbProviders.OpenPersistence` to dispatch based on URL
prefix. The interfaces are free of `bson.ObjectID` and other
Mongo-specific types — string IDs only.
