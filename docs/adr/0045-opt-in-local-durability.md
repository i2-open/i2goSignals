<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 45. Opt-in local durability: ack after a node-local WAL fsync

Date: 2026-09-28

## Status

Accepted (community #340; spec-111 Stage 3).

The default contract is still ADR 0038 as ADR 0043 implements it. This ADR
adds a documented, weaker exception to it and does not amend it. #341 (WAL
lifecycle and metrics), #342 (ring-fed delivery) and #343 (the per-stream
`durability` attribute and the permanent multi-node rule) build on it.

## Context

After Stages 1 and 2, every acknowledged SET still waits for a majority
journal write in MongoDB. The streaming throughput research (§1.3, §1.4, §4)
proposed a Stage 3 that removes that wait for deployments that accept a
weaker promise. The SET goes to a local append-only log, fsynced on this
node, and the node answers 202. A worker then moves the log to Mongo.

Delivery reads its pending list from Mongo (`GetPendingForStream`, prefetch,
backfill). A SET that is still only in one node's log cannot be seen by a
delivery-lease holder on another node. The research therefore said a local
log is only coherent in one of two cases: the ingest node is also the
delivery node, or delivery reads the local ring first.

## Decision

### 1. The contract

`I2SIG_STORE_WAL` selects the deployment's durability mode:

| Value                 | 202 means                                                                 |
|-----------------------|---------------------------------------------------------------------------|
| unset / `majority`    | The body and every delivery intent are majority-journaled in Mongo (ADR 0038). Unchanged. |
| `local`               | The SET is fsynced to **this node's** WAL. Mongo gets it when the drain worker next runs. |

Any other value refuses to start, with an error that names the variable.
`local` is **never the default**. It is **"single-node durable"**, an
explicit downgrade, and never a silent one. Startup logs a WARN that says
so.

The WAL lives in `I2SIG_STORE_WAL_DIR` (default `data/wal`, relative to the
working directory). It was one bbolt file, `ingest.wal`; ADR 0046 replaced
it with a directory of segment files and migrates the bbolt file on open.

### 2. The ingest path in `local` mode

`handleEvents` parses the SETs, applies the import/forward rules and plans
the fan-out exactly as in `majority` mode. Then, instead of the one-trip
store write, it does the following:

1. It reserves each JTI in an in-memory set of buffered JTIs. A JTI that is
   already buffered, or repeated in the same batch, is acked as a duplicate
   and not appended again. This is the WAL's own JTI check. It exists only
   to avoid buffering the same SET twice. ADR 0017 dedup still happens at
   the Mongo insert.
2. It encodes one WAL entry: the ingress SID, the event records (with the
   raw token), and the planned fan-out targets.
3. It appends the entry and fsyncs it. On success every SET in the call is
   acknowledged.
4. If the append fails, the reservations are released and every SET gets
   `ErrStoreUnavailable`, which is a 503 (ADR 0038). A SET that is not in the
   WAL is never acknowledged.

Ingress metering, the egress counters, and the wake-up of delivery targets
do **not** happen at the ack. They happen when the SET is actually in Mongo.
So the counters and the delivery runners see the same state that they see in
`majority` mode.

### 3. The drain worker

One goroutine per router. It wakes on each append, and it also runs once at
startup to pick up entries left by a previous process. Each pass:

1. Reads up to 256 entries from the head of the log, and stops early once
   the records reach `I2SIG_STORE_GROUP_COMMIT_MAX`.
2. Merges their records and pending maps and makes **one**
   `EventService.AddEventsWithPending` call. This is the #331 one-trip
   ordered `bulkWrite` that the majority path uses, behind the #330
   group-commit batcher.
3. For each entry that is fully stored, it meters ingress, runs
   `commitFanoutLocked` (egress metering, poll-buffer submit, wake-up), and
   truncates the log through the last fully stored entry.
4. A record that comes back `ErrDuplicateJTI` is already in Mongo. It counts
   as drained and is not metered again. This covers three cases: a SET that
   arrived through another path, a retry after a pass that half-failed, and
   a replay after a crash that happened between the store write and the
   truncate.
5. If the store fails, nothing is truncated. The worker retries with
   exponential backoff (50ms, doubling to 5s). Nothing is dropped. An entry
   that cannot be decoded is logged at ERROR and dropped. Only corruption
   that passed the CRC check can cause this.

The drain keeps entry order and record order within an entry. Within one
store call it keeps the batch order that ADR 0040 relies on.

Retention (ADR 0055) and dedup (ADR 0017) apply at the Mongo insert exactly
as they do today. The WAL holds no retention state. A drained SET is an
ordinary Mongo record, and `RetentionEngine.PurgeExpired` purges it the same
way (US 34, `TestLocalWal_DrainedSetIsPurgedByRetention_{Memory,Mongo}`).

### 4. The store: bbolt

> **Amended by ADR 0046.** The store is now an append-only segment log
> with one fsync per group; bbolt remains only as the reader for migrating
> an existing `ingest.wal`. The interface and the group-commit shape below
> are unchanged.

The WAL is a small interface in `internal/wal`:
`Append(batch) (seq, error)`, `ReadFrom(seq, limit)`, `Truncate(seq)`,
`Depth()` and `Close()`. The store behind it can be swapped.

The implementation is **bbolt** (`go.etcd.io/bbolt` v1.5.0, **MIT**, pure Go,
maintained by etcd):

| Store        | Licence | Sync default                       | Notes                                                                    | Verdict      |
|--------------|---------|------------------------------------|--------------------------------------------------------------------------|--------------|
| bbolt        | MIT     | fsync on every commit (2 per tx)   | B+tree, one writer, crash-safe copy-on-write pages, active (etcd)        | **Chosen**   |
| tidwall/wal  | MIT     | configurable                       | Segment log, purpose-built; about 13 months without a release when checked | Not chosen |
| Badger       | Apache-2.0 | `SyncWrites` defaults to **false** | An acknowledged write is not on disk by default                       | **Rejected** |
| Pebble       | BSD-3   | WAL sync on commit                 | LSM, far larger than this needs                                          | Not chosen   |

Records are keyed by bbolt's `NextSequence` (8-byte big-endian). Each value
carries a CRC32C prefix. A short record or a record with a bad CRC is
skipped on read. bbolt's copy-on-write commit already means a torn commit is
never visible, and the CRC is a second check. `TestBolt_KillDuringAppend`
SIGKILLs a child process mid-stream and checks that every acknowledged
sequence survives with its exact payload.

**Group commit.** bbolt's own `DB.Batch` is not used. It closes a batch on a
fixed timer. When the fsync is slow, the batches that queue behind the
writer lock hold one call each, and throughput collapses to one SET per
commit: 125 ev/s on macOS, measured. The WAL instead uses leader-based group
commit. While one transaction is committing, every `Append` and `Truncate`
that arrives queues. The next leader writes the whole queue in one
transaction, then hands leadership to the oldest waiter. Truncation rides
the same commit, so the drain does not cost the ingest path an extra fsync
pair.

### 5. The multi-node question: ring-fed delivery over ingest affinity

The research gave two ways to make a node-local log coherent in a cluster:

- **(a) Ingest affinity.** Route each stream's ingest to its delivery-lease
  holder by redirect or proxy. This adds a network hop, and it makes a
  stream unavailable for ingest while its owner is down (about 30 to 45
  seconds for a lease takeover).
- **(b) Ring-fed delivery** (§4.4, write-through / read-from-cache). The
  buffering node's delivery runners read the local WAL first. Mongo stays
  the truth, and a new lease owner backfills from Mongo as it does today.

**Decision: (b), in #342.** It keeps ingest behind any load balancer. It
needs no new routing layer. It reuses the wake-up plus backfill behaviour
the code already has. The replicated-buffer alternative (write to two nodes
before the 202) is Mongo majority re-implemented, and it is rejected.

#340 shipped a temporary single-node guard. #343 replaces it with the
permanent multi-node rule, below.

#### 5a. Per-stream durability and the multi-node rule (#343)

**Per-stream.** `I2SIG_STORE_WAL=local` is a deployment ceiling, not a
stream setting. Each stream carries an optional `durability` operator knob
on its `StreamStateRecord`, off the SSF wire format, like `event_validation`
and `retention_window_days`:

- `majority` is the default, and an unset value means the same. The stream
  keeps the full ADR 0038 contract, even on a `local` node.
- `local` opts the stream into the WAL path of section 2. It takes effect
  only when the node runs `I2SIG_STORE_WAL=local`. Elsewhere the value is
  stored and reported, the stream runs at majority, and the router logs one
  WARN per stream.
- Any other value is rejected with 400 on create or update.

The effective mode is resolved per SET at the ingest seam, from the ingress
stream record (for SSTP, the pair record). The stream-state read surfaces
report it as the derived, never-persisted `effective_durability`. The
#341 lifecycle and #342 ring-fed behaviour are unchanged for `local`
streams.

**Multi-node.** In a cluster, `local` requires ring-fed delivery
(`I2SIG_STORE_WAL_RING_FED=true`). Without ring-fed, `OpenPersistence` first
registers this node (`nodeid.Resolve()`) with the cluster coordinator and
then asks for the active nodes, so two nodes started together see each other
rather than both passing an empty read. If any active node other than this
one is registered, or membership cannot be read, it logs an ERROR and refuses
to start. The error names the condition and the two fixes: enable ring-fed
delivery, or return to `majority`. The startup check only covers the node
that joins, so the server repeats the membership read after every heartbeat
(`enforceLocalModeCluster`): the first time a running local-mode node finds a
peer it logs the same ERROR and suspends local ingest on itself
(`EventRouter.SuspendLocalIngest`, `StreamService.SetDeploymentDurabilityLocal(false)`).
Streams with `durability=local` are then acked at majority, the WAL keeps
draining, `goSignals_wal_local_ingest_suspended` reads 1, and the node stays
that way until restart; there is no re-arm, so the contract does not flap
with membership. With ring-fed on, both halves are skipped.

### 6. Lifecycle is #341's

This slice ships the store, the mode switch, the ingest path, the drain and
this contract. Three things belong to #341:

- A bounded drain on graceful stop, before the leases are released.
- Replay that finishes before ingest resumes after a crash restart.
- The WAL metrics: depth, drain lag, drained and replayed counts, and drain
  duration.

Today, `Shutdown` stops the drain worker and closes the log. Undrained
entries stay on disk. The next start drains them in the background while
ingest is already accepting.

## Failure matrix (research §1.3, reproduced)

| Path | Effect in `local` mode |
|---|---|
| Graceful stop | Safe when the stop drains before it releases (#341). Until then, the tail stays on disk and drains on the next start **on this node**. |
| `kill -9` / OOM / host loss | The lease expires on its own and another node takes over, but the tail is on the dead node's disk. **Acknowledged SETs that were not yet drained are lost, unless the WAL is on persistent, re-mountable storage and the node restarts with it.** A longer lease TTL only delays takeover. |
| Mongo unreachable | Ingest keeps acknowledging **into the WAL** while the drain retries with backoff and delivery stops. An availability outage becomes a growing local backlog. A WAL high-water mark to shed load is future work (the depth metric is #341). |
| Network partition (node isolated) | Same as Mongo unreachable, from the node's point of view. The isolated node's WAL cannot drain until the partition heals. The risk is **late** delivery, not double delivery: duplicate JTIs are absorbed at insert (ADR 0017). |

**Node loss with an undrained WAL loses acknowledged events in `local` mode.
That is the documented price of the mode.** An operator who cannot accept it
keeps the default.

## Consequences

- `majority` mode is unchanged. `RouterDeps.WAL` is nil, and `handleEvents`
  takes the ADR 0043 path. The full suite runs with the variable unset and
  with `majority`.
- In `local` mode, a SET is visible to delivery and to the counters only
  after it drains. On a busy node, the delivery tail grows by the drain lag.
  #342 adds `I2SIG_STORE_WAL_RING_FED=true`, which removes that lag on the
  buffering node: the runners read undrained SETs from memory and are woken
  at append, and acks taken before the drain are held and written right
  after the SET. Counters still move at drain. See `docs/perf/ring-fed-342.md`.
- A SET whose append failed is answered 503, and its JTI reservation is
  released, so a retry is accepted.
- A SET acknowledged in `local` mode that turns out to be a duplicate of one
  already in Mongo is dropped quietly at drain. This is the same outcome a
  duplicate gets in `majority` mode, only later.
- One new dependency: bbolt, MIT, which passes `make licenses-check`.

## Measurements

`BenchmarkMongoRouterWalIngest` sends 5000 SETs from 16 concurrent clients
through the router into the dev 3-member `mongo:8.0.13` replica set. It runs
once per mode. See `docs/perf/local-wal-340.md` for the method.

| Host for the router                          | `majority` ack ev/s | `local` ack ev/s | `local` stored ev/s |
|----------------------------------------------|---------------------|------------------|---------------------|
| Linux container on the dev Docker VM (same VM as Mongo) | 3533 / 2964 / 3468 | 6035 / 6341 / 6493 | 5941 / 6251 / 6405 |
| macOS host (APFS, `F_FULLFSYNC`)             | 3314 / 3219 / 3304  | 800 / 743 / 819  | about the same as ack |

On Linux, `local` acks about 1.9x faster, and the drain keeps up (stored is
within 2% of ack). On macOS, bbolt's `F_FULLFSYNC` flushes the drive cache,
so a commit costs about 9.4 ms against 0.77 ms in the Linux VM. `local` mode
is then slower than Mongo, whose own fsyncs run in the Linux VM. The mode is
worth enabling only on a host whose fsync is cheap: Linux on NVMe, or a
volume with a power-loss-protected write cache.
