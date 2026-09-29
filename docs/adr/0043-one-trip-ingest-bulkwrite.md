<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 43. Ingest groups commits and writes each SET's body and delivery intents in one trip

Date: 2026-09-28

## Status

Accepted (community #330, #331; spec-111 Stage 1).

This ADR supersedes ADR 0038's BeginAddEvents/RetractPending mechanism while
preserving its contract.

## Context

ADR 0038 fixed the ingest durability contract: a SET is acknowledged only
after both its body (`events`) and every delivery intent it produces
(`pendingEvents`) are majority-journaled. A duplicate `jti` is answered
`ErrDuplicateJTI` and leaves no orphan marker (ADR 0017). ADR 0038 met that
contract by issuing the two writes concurrently. The markers were treated as
speculative until the body write was joined, and then the markers of rejected
candidates were retracted with `EventDAO.RetractPending`.

That mechanism has three costs. It still pays two majority-acked writes per
batch, although the two overlap. The speculative marker is cluster-visible, so
a duplicate re-send could be re-delivered in the window before the
retraction. And the retraction has to undo exactly one `AddPending` per `jti`,
which is subtle enough that ADR 0040 had to redocument its sort order.

spec-111 Stage 1 attacks the per-SET write cost from two sides.

## Decision

### 1. Group commit on EventDAO writes (#330)

`internal/dao/groupcommit` decorates the event DAO. It merges concurrent
`Insert`/`InsertMany` calls into one bulk `InsertMany`, and it merges
`AddPending`/`AddPendingMany` calls for the same stream into one
`AddPendingMany`. It is tuned by `I2SIG_STORE_GROUP_COMMIT_WINDOW` (default
`1ms`) and `I2SIG_STORE_GROUP_COMMIT_MAX` (default `128`). Each caller still
gets its own per-record results. Measurements are in
[docs/perf/group-commit-330.md](../perf/group-commit-330.md).

### 2. One-trip body + intent write (#331)

`EventDAO.InsertWithPending(ctx, records, pending)` replaces
`BeginAddEvents` + `AddEventsToStream` + `RetractPending`. It persists the
records and, for each record that is accepted, its pending markers.
`pending` maps stream ID to the JTIs queued on it. It returns one error per
record: `nil`, `ErrDuplicateJTI`, or a store error. A batch-level error means
nothing is known to be stored.

- **MongoDB >= 8.0:** there is one ordered client-level `bulkWrite` across the
  `events` and `pendingEvents` namespaces. The ops are **grouped by
  namespace**: every record's events insert comes first, then every marker
  insert. An ordered bulkWrite stops at the first failed op, and every marker
  follows every body, so a rejected body is never followed by a written
  marker. That is how ADR 0017's "no orphan marker" rule holds without any
  retraction. Every op before the failure is known to have succeeded. The
  failed op is mapped back to its record, which is answered `ErrDuplicateJTI`
  (a duplicate-key error on the body), a store error (any other body error),
  or "pending marker write failed" (the body landed but a marker did not).
  That record's remaining ops are dropped, and every other op after the
  failure is resubmitted, in the same order, in a fresh bulkWrite. The
  resubmit includes the markers of records whose bodies landed before the
  failure, so no stored body is left without its markers. No record is
  reported successful until its body and all its markers are durable. A batch
  with k per-record failures therefore costs k+1 round trips, and the common
  case costs one.

  The first cut interleaved the ops per record (a body, then its markers,
  then the next body). That alternates namespaces on every op, and mongod
  batches consecutive inserts only while they target the same namespace, so
  each op became its own storage write unit. A server-side profile on Mongo
  8.0.13 counted about 32 lock acquisitions per command for the interleaved
  layout, against 4 when grouped. Grouping recovered 3-11% at the router (see
  Measurements).
- **Memory DAO:** this is the same loop in-process.
- **Group commit:** the #330 decorator coalesces concurrent
  `InsertWithPending` calls into one inner call. It rebuilds the merged
  `pending` map so that each caller's markers stay on that caller's streams,
  and it splits the results back per caller. An empty call, or one at least
  `I2SIG_STORE_GROUP_COMMIT_MAX` long, bypasses the coalescer.

`handleEvents` now plans the fan-out with no database access
(`planFanoutLocked`, `selectMatchingLocked`). It issues the one write
(`EventService.AddEventsWithPending`) and reconciles the per-record results
(`reconcileIngest`). A record whose body or marker failed is answered
`ErrStoreUnavailable` (503 + `Retry-After`, #333) and is never acknowledged.
A duplicate is acknowledged idempotently and is not fanned out. Only accepted
records are metered as egress and wake their streams (`commitFanoutLocked`).
Since no marker is ever speculative, there is nothing to retract.
`BeginAddEvents`, `IngestBatch`, `DiscardPending`, `AddEventsToStream`,
`EventDAO.RetractPending` and the router's `queued` bookkeeping are removed.

### 3. Server-version fallback

`MongoProvider.connect` runs `buildInfo` once and logs the server version at
INFO. The provider exposes it through `ServerVersion()`, and the event DAO is
set to one-trip mode when the major version is at least 8. Below 8.0, or when
the version cannot be read, the provider logs exactly one WARN per process and
the DAO uses the **two-write fallback**. The fallback runs `InsertMany` on the
bodies, then `InsertMany` on the markers of the records that were accepted.
Both modes store identical documents and report identical per-record results;
a test runs the same batch through each mode and compares the stored state.
The fallback is sequential rather than ADR 0038's concurrent form, because
writing markers only after their body is known to be accepted is what removes
retraction. The cost is two round trips on old servers, which is the price of
not maintaining two mechanisms.

## Options considered

- **Option A: fold the marker into the event document** (ADR 0038 option 2,
  deferred there). Rejected. It makes ingest a single-document write on any
  server version, but every stream ack becomes an update of the event document
  instead of a delete from `pendingEvents`. The pending index that every
  delivery leg reads (`{sid:1,jti:1}`, ADR 0040) would move to an array field
  on a hot, growing collection. It also needs a schema migration of stored
  data. The multi-namespace bulkWrite gets the one-trip saving without
  changing the storage shape.
- **Keep ADR 0038's concurrent writes and add group commit only.** Rejected as
  the end state. It keeps the speculative-marker window and `RetractPending`.
- **A multi-document transaction.** Rejected. It also gives atomicity, but at
  the cost of a transaction commit round trip plus conflict retries on the hot
  path, and ordering already gives the only property needed (no marker without
  its body).

## Consequences

- ADR 0038's contract is unchanged: no ack without a majority-journaled body
  and all its markers, and a duplicate leaves no orphan marker. The
  crash-consistency and fan-out tests
  (`internal/eventRouter/ingest_crash_consistency_test.go`,
  `fanout_commit_test.go`) assert it against the new path.
- ADR 0038's duplicate re-delivery window is gone, because a duplicate
  never writes a marker. A receiver re-sending a SET that is still pending
  leaves exactly one intent.
- **Residuals.** The one-trip write is ordered but not atomic. A crash, or a
  marker failure, after a body lands but before all its markers land leaves a
  body with missing markers. That SET was answered 503, not acked. A retry by
  the transmitter is then a duplicate, and the router repairs it (#331): for
  every duplicate it calls `EventDAO.EnsurePending(jti, targets)`, an
  idempotent upsert keyed on `(sid, jti)` that queues the JTI on each target
  stream holding neither a pending nor a delivered record for it, and the
  re-queued targets are metered and woken exactly as an accepted SET's are.
  A duplicate whose markers are all in place changes nothing. If the repair
  itself fails the duplicate is answered 503, not acked, so the transmitter
  keeps retrying. The same repair covers the fallback between its two writes
  and the ADR 0045 WAL drain. What remains is at-least-once by design: a
  retry that arrives after ADR 0055 retention has purged the delivered
  record, or after a stream's configuration changed to match the SET, is
  re-queued on that stream. The inverse residue, a marker with no body, can
  no longer be produced by this build. The delivery legs still skip such a
  marker if an older build left one.
- Mongo < 8.0 deployments keep working, with one WARN at startup and two
  sequential writes per batch.

## Measurements

See [docs/perf/one-trip-ingest-331.md](../perf/one-trip-ingest-331.md).

The router benchmark (`BenchmarkMongoRouter`, Mongo 8.0.13 three-node replica
set, medians of three interleaved runs against `9113c1a`) does **not** show a
gain. Serial `ingest` went from 3.04 to 3.33 ms/op (+9.5%), and the concurrent
`ingest-batch100` went from 929 to 1060 µs/SET at 4 workers (+14%), 518 to 627
at 8 (+21%), and 313 to 417 at 16 (+33%). The likely cause is not yet
verified: ADR 0038 had already overlapped the two writes, so one trip saves
little latency, while the client-level `bulkWrite` command costs more per op
than two collection inserts. The end-to-end `goSignalsBench` run at 5000
events / 16 clients is still to be done. The design is kept for the removal
of speculative markers and `RetractPending`, but its throughput case is open.

Profiling then showed the cost was the interleaved op layout, which defeats
mongod's same-namespace insert batching (about 32 lock acquisitions per command,
against 4 grouped). Grouping the ops by namespace took serial `ingest` from
3.39 to 3.20 ms/op and `ingest-batch100` at 16 workers from 370 to 328 µs/SET.
That is still about 5% behind the pre-#331 base at 16 workers, and the
end-to-end run is still pending.
