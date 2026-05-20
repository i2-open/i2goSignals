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

## Subject filtering vocabulary

Terms used by SSF §8.1.3 subject filtering. The implementation guide is
`docs/subject_processing.md`.

### Subject

The principal an event is about, identified per **RFC9493** Subject
Identifiers — the same vocabulary SSF §8.1.3 and SCIM Events (RFC9967)
use. Formats: `account`, `email`, `iss_sub`, `opaque`, `phone_number`,
`did`, `uri`, `aliases`, plus **complex subjects** (user / group /
device / session / tenant / org_unit). A Subject is not necessarily a
person — it may be a device, session, or org unit.
_Avoid_: treating "user" or "account" as synonyms for Subject.

### Subject matching

The SSF §8.1.3.1 predicate that decides whether two Subjects are "the
same" for filtering purposes — distinct from `EventService.MatchesStream`
(which is iss/aud/event-type routing). Rules:

- **Simple Subjects** match iff they are exactly identical.
- **Complex Subjects** match field-wise: for every field (user, group,
  device, …) at least one side may leave it undefined (wildcard); a
  match requires every field that *is* defined on both sides to be
  identical.

Consequence: a receiver can subscribe broadly (few fields specified)
and still receive narrower, more-specific events. Because the two
kinds match differently, the subject filter is stored *split* by
kind — simple Subjects hash-indexed on their canonical key (O(1)
membership), complex Subjects held in a small field-wise-scanned
list. A filter may legitimately reach millions of entries; see
`docs/adr/0003-split-subject-filter-storage.md`.

### defaultSubjects

A per-transmitter-stream setting (goSignals extension, not an SSF
stream-config field) expressing the **default delivery policy** a
receiver sees — not a guarantee:

- **`ALL`** — Subjects are delivered by default; the receiver narrows
  by *removing* Subjects.
- **`NONE`** — no Subject is delivered by default; the receiver opts
  in by *adding* Subjects.

It is only a *default*. Per SSF a transmitter MAY ignore Add/Remove
requests and MAY deliver a Subject out-of-band on its own policy (e.g.
a user opt-in dialog at the transmitter). So a `NONE` upstream can
still send Subjects goSignals never added, and an `ALL` upstream may
withhold some.

The stream's subject filter table holds only the non-default set.
Changing `defaultSubjects` on a live stream is a deliberate reset: the
filter table is cleared, because old entries carry the opposite
meaning under the new baseline.

### Provenance-independent downstream filtering

Because upstream delivery is never guaranteed to track what goSignals
subscribed for, goSignals must tolerate receiving events for Subjects
it never added. The downstream transmitter filter is therefore applied
to **whatever arrives**, judged purely on that downstream stream's own
`defaultSubjects` + filter table — never on how or why the event
arrived. Inbound subscription state and outbound delivery policy are
decoupled.

### Subject filtering mode

A setting on a goSignals **receiver stream** giving the operator
explicit control over how Add/Remove Subject requests arriving at the
fed downstream transmitter streams are handled:

- **`PASSTHRU`** — raw 1:1 relay of Add/Remove to the upstream
  transmitter; no reference counting, no local filtering. Downstream
  streams share one upstream subscription and share fate: one
  downstream's Remove removes the Subject for all. That bluntness is
  the feature.
- **`LOCAL`** — filter locally, independently per downstream
  transmitter stream; never touch the upstream.
- **`HYBRID`** — reference-counted relay *and* local fan-out
  filtering, so each downstream sees only the Subjects it asked for.
  goSignals tracks, per Subject handler + Subject, the **set** of
  interested downstream streams; it relays an `add` upstream when the
  set goes 0→1 and a `remove` only when it goes 1→0. `HYBRID` relays
  **only against a `defaultSubjects=NONE` upstream** — against an
  `ALL` upstream everything already arrives, so it behaves as pure
  local filtering (relaying a `remove` could starve a not-yet-created
  downstream). `HYBRID` is mandatory for a `NONE` upstream fanning
  out to multiple selective downstreams — such a stream cannot be
  filtered `LOCAL`-only because the event never arrives.

`PASSTHRU` and `HYBRID` require (a) the upstream to advertise
`add_subject_endpoint` / `remove_subject_endpoint` in its SSF
discovery metadata, and (b) an unambiguous relay target — see
**Event source** and **Subject handler**.

### Event source

How a transmitter stream selects the events it sends. A new axis,
distinct from `RouteMode` (IM/FW/PB):

- **Direct** — no routed source; events arrive in Mongo by other
  means (e.g. direct POST). Relay is impossible → `LOCAL` only.
- **Audience-routed** — events matched in by `iss`/`aud`/event-type
  (the current behavior). For relay, the feeding receiver stream is
  found by matching the transmitter stream's `iss` to a receiver
  stream's `iss`.
- **Explicit (SID) source** — the transmitter stream names the
  specific source stream SID(s) it forwards/republishes from.

### Subject handler

The single receiver stream designated to receive relayed Add/Remove
Subject requests for a given issuer. When an Audience-routed
transmitter stream's `iss` matches exactly one receiver stream, that
receiver is the subject handler automatically. When several receiver
streams share the issuer (e.g. a cluster of nodes all transmitting to
goSignals on common audiences), the ambiguity MUST be resolved **at
configuration time** by designating one explicitly via Explicit (SID)
source — otherwise stream configuration is rejected.

Publish-mode `iss`/`aud` rewriting is a deferred enhancement and is
out of scope; it will later interact with subject filtering because
rewriting `iss` changes the canonical key of `iss_sub` Subjects.

### Add Subject / Remove Subject

Receiver-initiated requests (SSF §8.1.3.2 / §8.1.3.3) telling a
transmitter stream whether to deliver events for a given Subject. Add
Subject POST returns 200; Remove Subject POST returns 204. Carry
`stream_id`, `subject`, and (Add only) an optional `verified` boolean.
A transmitter MAY silently ignore them. goSignals stores `verified`
for audit and relays it verbatim upstream, but it does not influence
filtering — goSignals is not an identity verifier.

The endpoints are gated by a server-wide `I2SIG_SUBJECT_FILTERING`
setting (`DISABLED` default / `ENABLED`). When `DISABLED` they are
omitted from SSF discovery and return 404.

Add/Remove take effect for **future events only** — they do not
replay a Subject's event history. A receiver that wants history uses
the existing `ResetDate` / `ResetJti` replay mechanism instead.

goSignals applies the subject filter at **delivery time**, not at
routing time. `MatchesStream` and `HandleEvent` are untouched — an
event still enters the stream's pending buffer. The filter is
consulted when the buffer is drained:

- **PUSH** — in `runPushLoop` on the node holding the
  `push-transmitter:<sid>` lease. A filtered-out JTI is **discarded
  (acked), not pushed**, so the pending list still drains and stays
  bounded. The filter is cached in that node's memory; an Add/Remove
  arriving on any node looks up the lease owner and notifies it (the
  same point-to-point pattern as the event wake-up) to reload.
- **POLL** — at poll-response time on whichever node serves the poll;
  the filter is read straight from Mongo (polls are cold and batched).

This is why routing-time filtering was rejected: routing runs on an
arbitrary ingest node, so it would force every node to hold every
stream's filter, with no existing channel to keep them consistent.
Delivery-time filtering pins the hot path (PUSH) to the single lease
owner, which the wake-up scheme already addresses.

Operational events (`Operational=true` — verify, stream-updated)
carry no Subject and always pass the filter, just as they already
bypass `MatchesStream`.

### Removal grace period

A configurable interval (SSF §9.3, "Malicious Subject Removal") during
which a Subject whose delivery was just *stopped* continues to be
delivered, so a malicious or coerced receiver cannot instantly blind a
downstream by quietly removing a victim Subject.

- It gates the **effect**, not the SSF verb: any operation that *stops*
  delivery for a Subject is deferred by the grace period; any operation
  that *starts or resumes* delivery takes effect immediately. A re-Add
  during the window cancels the pending removal.
- It is a per-transmitter-stream setting with a server-wide default;
  `0` means immediate enforcement. It applies only where goSignals is
  itself the filtering transmitter — **`LOCAL`** and **`HYBRID`** local
  fan-out. Under **`PASSTHRU`** the upstream transmitter applies its own
  §9.3, so goSignals adds no grace.
- It covers receiver-issued stop-delivery requests on a *live* stream
  only. A `defaultSubjects` flip is a deliberate operator action, not
  the §9.3 threat, so the flip clears the filter table immediately and
  bypasses grace.

### Example dialogue

> **Dev:** The SCIM demo cluster has several i2scim nodes, each
> transmitting to goSignals on the *same* set of audiences. A
> downstream receiver removes a Subject — where does the Remove go?
> **Domain expert:** i2scim doesn't speak SSF, so there's no upstream
> Add/Remove endpoint to relay to. goSignals filters `LOCAL`.
> **Dev:** And if i2scim later supported SSF?
> **Domain expert:** The cluster would synchronize Subjects internally,
> so you'd relay to just one node. You'd pick one cluster stream as
> the **Subject handler** via Explicit (SID) source — issuer matching
> alone is ambiguous across the cluster, so config would reject it
> otherwise.

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

## Log-level policy

The four slog levels (`DEBUG` / `INFO` / `WARN` / `ERROR`) are the same
labels that flow through to Loki and any dashboards built on top. Pick the
right one so operators can rely on `level=ERROR` as a real attention
signal, not a noise floor:

- **`DEBUG`** — Verbose internal state. Off in production.
- **`INFO`** — Steady-state operational facts: stream registered, lease
  acquired, push delivered.
- **`WARN`** — Recoverable and *expected-as-part-of-normal-operation*
  conditions. Examples:
  - **Authentication and authorization failures** — bad token, expired
    bearer, mismatched audience, missing scope. These are a normal part
    of running an internet-facing server; clients re-auth, servers don't
    need a human.
  - **A stream that fails to connect on a single attempt.** Treat as
    `WARN` until the retry budget is exhausted and it is declared a
    permanent failure (then promote to `ERROR`).
  - **A receiver returning 4xx that the RFC8935 retry policy already
    covers.** The router handles it; the operator does not need to.
- **`ERROR`** — Demands operations attention. Reserve for conditions that
  will not resolve themselves without human intervention. Examples:
  - A stream that has crossed its retry budget and is now declared
    permanently offline.
  - The persistence layer has lost its primary and exhausted reconnect
    attempts.
  - An internal invariant violation (e.g. lease ownership mismatch with
    a fencing token in the past).

The discipline is asymmetric. Promoting an item from `WARN` to `ERROR`
because "it might matter" pollutes the signal that on-call uses to
decide whether to wake up. Demoting an existing `ERROR` to `WARN`
because the condition turned out to be normal-ops is welcome — leave a
note at the call site so the next reader knows it was deliberate.

If you find yourself wanting a fifth level ("this is serious but not
quite ERROR"), the answer is almost always `WARN` plus an `error=` field
on the record. Grafana / LogQL can already filter `{level="WARN"} | json
| error="..."` for the subset that matters; a new level cannot.

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
