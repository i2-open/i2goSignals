<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 10. Provider decomposition — the god-interface and god-object are retired

Date: 2026-05-07

## Status

Accepted

## Context

The persistence layer was a single god-interface (`DbProviderInterface`, ~50
methods) backed by a god-object (`common.BaseProvider`), with a Mongo
wrapper-method tax (~160 thin delegating methods on `MongoProvider`) layered on
top. Three structural problems compounded:

- **`bson.ObjectID` leaked across the interface.** The persistence seam and DAO
  types exposed a Mongo driver type, so any alternative adapter (Postgres, etcd)
  would have had to import `bson` just to satisfy the contract.
- **Reconnect swapped the whole `*BaseProvider` behind an `RWMutex`.** A caller
  holding a method reference could call against a stale BaseProvider whose
  collection pointers had been freed — a real race window.
- **Adding a persistence method touched five files** (DAO, service, BaseProvider
  façade, MongoProvider wrapper, interface) and risked silent persistence drift
  (a missed `notifyWrite`).

PRD #39 (slices #44, #46, #47, finished in #45) decomposed this in coordinated
moves rather than one big-bang rewrite.

## Decision

We retire the god-interface and god-object in favour of narrow, per-concern
seams composed in one record:

1. **String IDs across the persistence interfaces.** `bson.ObjectID` becomes
   Mongo-internal; conversion happens at the read/write boundary via private doc
   types. `internal/dao/ids.NewObjectID()` produces a 24-char hex string that
   round-trips through `mongo.ParseObjectID`. The DAO and provider interfaces no
   longer import `bson`.
2. **Mongo DAOs hold rebindable collections** behind `atomic.Pointer[mongo.Collection]`
   (`collection_ref.go`). Reconnect rebinds the existing DAOs' collection
   pointers in place instead of constructing a new `*BaseProvider` — the
   swap-on-reconnect race is retired; in-flight callers see either the old or new
   collection, never a partial state.
3. **Cluster coordination and storage become their own seams.**
   `cluster.ClusterCoordinator` owns the seven lease + node-registry methods;
   `storage.Storage` owns the five lifecycle methods. `MemoryCoordinator` gains
   *real* lease semantics (atomic acquire, time-based expiry, monotonic
   fencing tokens, compare-and-release).
4. **`CreateStream` business logic lifts into `StreamService`** — `tx_alias`
   resolution (via an injected `*ServerService`) and case-insensitive
   `IssuerJWKSUrl == "NONE"` normalisation. BaseProvider's `CreateStream` becomes
   a pure pass-through, the prerequisite for deleting it.
5. **The receiver-stream predicate lifts into `StreamService`.** The two DAOs had
   drifted (`route_mode == "import"` vs `state.IsReceiver()`); `IsReceiver()` is
   now the single canonical predicate, applied once in
   `StreamService.ListReceiverStreams`.
6. **Memory persistence becomes a DAO-level decorator** (`notifying_dao.go`): six
   small wrappers fire one `notify()` after every successful mutation. The
   `WriteHook`/`SetWriteHook`/`notifyWrite`/`afterWrite` plumbing threaded through
   ~25 BaseProvider methods is removed; Mongo carries no decorator and pays
   nothing.
7. **The MongoProvider wrapper-method tax (~160 methods) is deleted.** Production
   consumers call services directly (`sa.StreamService`, `sa.KeyService`, …)
   rather than `sa.GetProvider().X(...)`; lifecycle calls go through `sa.Storage`.
8. **`DbProviderInterface` and `common.BaseProvider` are deleted.** The public
   composition entry point is `dbProviders.OpenPersistence(url, dbName)
   (*Persistence, error)`, returning a record of the six per-domain services plus
   `Coordinator` and `Storage`. `eventRouter.NewRouter(RouterDeps, nodeId)` takes
   only the four services it actually uses.

## Consequences

**Positive**

- Adding a persistence method now touches one DAO (per adapter) and one service —
  three files instead of five. No wrapper tax, no dispatch tax (no
  `provider.(serviceSource)` assertions).
- Cluster invariants (mutual exclusion under contention, expiry takeover,
  fencing-token monotonicity, owner-only release) are now unit-testable via
  `MemoryCoordinator` in under five seconds under `-race`, where they previously
  needed a docker-compose suite.
- No Mongo driver is reachable from `eventRouter`, `application.go`, or
  `api_receiver.go`; a future Postgres/etcd adapter need not import `bson`.
- The reconnect race window is structurally eliminated — the `*BaseProvider`
  value is stable and only collection pointers rotate.
- Test fixtures depend on the same seams as production (`*Persistence`).
  `Persistence.Refresh()` re-pulls service references after
  `Storage.ResetDb(true)` on the in-memory adapter (a structural no-op on Mongo,
  which rebinds in place).

**Negative**

- A large refactor spanning ~280 test sites; every consumer had to be rewired to
  take the narrowest seam it uses.
- The memory adapter and Mongo adapter present a uniform "reset is safe
  mid-test" contract only because `Refresh()` exists — a small piece of
  adapter-specific knowledge a caller must remember after a reset.

## Related

- PRD #39 — slice #44 (DAO decorator), #46 (rebindable collections), #47
  (wrapper-method tax), #45 (interface/object deletion + test migration).
- Files deleted: `internal/providers/dbProviders/provider_interface.go`,
  `internal/providers/dbProviders/common/base_provider.go`.
- `internal/providers/dbProviders/mongo_provider/` — reference implementation
  for any new provider methods.
