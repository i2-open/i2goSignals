<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 38. Ingest writes the event body and its delivery intents concurrently

Date: 2026-09-08

## Status

Accepted (community #286).

## Context

Once push, poll and SSTP delivery had been batched and pooled (ADRs 0035, 0036,
0037), ingest became the ceiling for every leg. `HandleEvents` paid two
majority-acked replica-set round trips per inbound batch, one after the other:

1. `events` — the SET bodies, via `EventService.AddEvents` / `InsertMany`.
2. `pendingEvents` — one delivery intent per matching outbound stream, via
   `AddEventsToStream` / `AddPendingMany`.

Server-side timings on `goSignals1` during a 5000-event push run measured
9.30 ms average for the `events` insert and 8.82 ms for the `pendingEvents`
insert. The client is configured `WriteConcern{W: "majority"}` in
`MongoProvider.connect`, so each write waits for replication across the 3-node
replica set, and the two costs added rather than overlapped.

The second write was sequenced after the first only because the fan-out is
filtered by the first write's outcome: a JTI the unique `events.jti` index
rejects as a duplicate (ADR 0017) must not be fanned out a second time. Nothing
else in the fan-out needs the database — `MatchesStream` is a pure predicate
over records built from the inbound tokens.

Three options were considered (#286): issue the two writes concurrently; fold
the pending marker into the event document; or relax the write concern on
`pendingEvents` alone. All three change the ingest durability contract, so the
decision is recorded here whether or not the storage shape moves.

## Decision

**Issue the two writes concurrently**, and treat a pending marker as
speculative until the body write is joined.

The other two options are not taken. Folding the marker into the event document
would make ingest one write instead of two, but it costs an update per
stream-ack and a schema migration. Relaxing `pendingEvents` to `w:1` would
weaken durability on the leg that decides whether an accepted SET is ever
delivered, for a saving the concurrent form already realises at full write
concern.

`EventService.BeginAddEvents` starts the body write and returns immediately with
the candidate records. `HandleEvents` then:

1. plans the fan-out against those candidates and writes their pending markers
   while the bodies are still in flight (`planFanoutLocked`);
2. joins the body write (`IngestBatch.Wait`), which decides which candidates
   were accepted;
3. commits the fan-out (`commitFanoutLocked`) — retracting the markers of every
   rejected candidate, metering the survivors as egress, and only then waking
   the streams.

Nothing observable happens on a speculative marker: no stream is woken, no SET
is metered as egress and no error is reported until the body write has been
joined.

Retraction undoes exactly one `AddPending` per JTI. `EventDAO.RetractPending`
removes the **newest** pending entry for a JTI and leaves any earlier entry in
place and in its original position, because the two entries are otherwise
identical and removing both would silently drop a real, still-undelivered
delivery intent — the case where a receiver re-sends a SET that is still pending
on the same outbound stream.

The in-memory `EventDAO` previously recorded a pending marker only if the body
was already stored. That guard is removed: it made the marker's fate depend on
write ordering, which concurrency no longer fixes, and the Mongo DAO never had
it. Both providers now record a delivery intent independently of the body.

`SubmitOperationalEvent` keeps its sequential form. Operational events are
point-to-point SSF protocol traffic (verify, stream-updated) at negligible rate,
and the ordering there is worth more than the round trip.

## What this changes about crash semantics

Before: the body was written first, so a crash between the two writes lost only
the **delivery intent**. The SET was stored and queryable but was never queued
to any stream, and only a backfill could find it.

After: the two writes race, so a crash between them can instead leave a
**pending entry with no body**. The affected SET is not stored, so it cannot be
delivered — the same net outcome for the receiver as the old failure mode — but
the residue is now in `pendingEvents` rather than in `events`.

Every delivery leg already tolerates that residue, and each is now pinned by a
test in `internal/eventRouter/ingest_crash_consistency_test.go`:

| Leg | Behaviour on a pending JTI with no body |
|---|---|
| push (`pushBatch`) | skipped; not pushed and **not acked** |
| poll (`assemblePollResponse`) | skipped; left out of the response body, marker left pending |
| SSTP responder (`buildSstpOutboundSets`) | skipped; never rendered onto the wire |
| SSTP initiator (`resolveSstpEventsByJti`) | skipped; dropped from the flush |

None of them acks what it did not send, so nothing confirms delivery of a SET
that does not exist. The orphaned marker is inert rather than harmful: it is
never delivered and never acked, and it is retired when the stream's pending
list is cleared or the stream is deleted.

This is a durability *contract* change, not a durability *loss*: the number of
inbound SETs that survive a crash is unchanged, because both writes still run at
`majority` write concern and both must land for a SET to be deliverable. What
changes is which half of the pair can be left behind.

## Measurements

`BenchmarkMongoRouter` (`internal/eventRouter/handle_event_bench_test.go`)
against the `docker-compose-dev.yml` 3-node replica set on an Apple M3 Max,
`-benchtime 300x`. `ingest` and `verify+ingest` are medians of three runs taken
back to back on the same cluster with the change stashed and unstashed;
`ingest-batch100` and `drain+ack` are single runs.

| Benchmark | Before | After | Change |
|---|---|---|---|
| `ingest` (1 SET) | 2.387 ms/op | 1.744 ms/op | **-27%** |
| `verify+ingest` (1 SET) | 2.588 ms/op | 1.961 ms/op | **-24%** |
| `ingest-batch100` workers=1 | 2352 µs/SET | 1763 µs/SET | -25% |
| `ingest-batch100` workers=4 | 909.4 µs/SET | 856.1 µs/SET | -6% |
| `ingest-batch100` workers=8 | 610.7 µs/SET | 444.5 µs/SET | -27% |
| `ingest-batch100` workers=16 | 444.4 µs/SET | 311.3 µs/SET | -30% |
| `drain+ack` (control, untouched) | 5.292 ms/op | 5.371 ms/op | +1.5% (noise) |

Across three runs each the two distributions do not overlap: `ingest` measured
2.312-2.646 ms before and 1.677-1.792 ms after. `drain+ack` is the control — it
touches neither write and does not move.

End to end, `cmd/goSignalsBench --mix push --events 5000 --concurrency 16`
against the same stack, three runs each side (rows appended to
`docs/perf/e2e-history.md` as `spec102-286-before/after-runN`). The first run
after each container rebuild is cold and is reported separately rather than
folded into the median.

| Run | Ingest ev/s | Ingest p50 | Ingest p99 |
|---|---|---|---|
| before, cold | 529 | 25.9 ms | 101.7 ms |
| before, warm | 769 / 759 | 19.1 / 19.1 ms | 46.5 / 47.3 ms |
| after, cold | 719 | 18.7 ms | 78.5 ms |
| after, warm | 844 / 834 | 16.5 / 16.6 ms | 48.6 / 50.5 ms |

Warm medians: **ingest p50 19.1 -> 16.6 ms (-13%)** and **759 -> 834 ev/s
(+10%)**. The end-to-end gain is smaller than the router benchmark's because
the e2e figure also carries HTTP, JWS verification and the ingress handler, and
because at sixteen concurrent clients the replica set is already the bottleneck:
some of the removed serial latency comes back as throughput rather than as p50.

## Consequences

- Ingest pays roughly one majority-acked round trip instead of two. The floor is
  now the slower of the two writes, not their sum.
- A pending marker is speculative between the plan and commit phases of one
  `HandleEvents` call. It is never acted on in that window.
- A duplicate JTI costs one extra round trip it did not cost before: the
  retraction. Duplicates are the exceptional path, so this is not on the hot
  path, and `RetractPending` is deliberately one round trip per JTI rather than
  a batched delete so the "newest only" rule stays exact.
- `EventDAO` gains `RetractPending`. It is the compensating counterpart to
  `AddPending`, distinct from `RemovePendingMany`, which removes *every* entry
  for a JTI and records the removals as delivered.
- The in-memory provider can now hold a pending marker with no body, which is
  what lets the crash-consistency behaviour be tested without a crash.
