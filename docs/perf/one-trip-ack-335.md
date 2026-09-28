# One-trip ack (#335, spec-111 Stage 2)

This page compares the ack path before and after #335.

Before the change an ack took three round trips:

- a `find` that read which JTIs were pending,
- a `delete` on `pendingEvents`,
- an `insert` on `deliveredEvents`.

After it, `EventDAO.AckDelivered` does the whole ack in one client-level
multi-namespace `bulkWrite` on MongoDB 8.0+. That call holds one `DeleteMany`
per JTI on `pendingEvents` and one `InsertOne` per JTI on `deliveredEvents`.
Its verbose results give each JTI's delete count, so the call knows which JTIs
were pending.

A JTI that was not pending gets no delivered record (ADR 0017). The call
deletes the delivered rows it inserted for those JTIs by `_id`, which costs one
more `delete`. That extra trip happens only when an ack names a JTI that is
not pending.

The call runs at `w:1`, the `deliveredEvents` concern (#332). A client
`bulkWrite` takes a single concern, so the pending delete is `w:1` too. The
reason is in
[configuration_properties.md](../configuration_properties.md#mongo-write-concern).
On Mongo older than 8.0 the old three-trip path is used, selected by the same
server-version check as the one-trip ingest (#331).

`TestAckDelivered_OneTripIsOneBulkWrite` in `internal/dao/mongo` counts the
commands sent:

| Case | Commands |
|---|---|
| One-trip, every JTI pending | `bulkWrite` x1 |
| One-trip, one JTI not pending | `bulkWrite` x1, `delete` x1 |
| Fallback (< 8.0) | `find` x1, `delete` x1, `insert` x1 |

## Procedure

The environment is an M3 Max with the dev stack's Mongo 8.0.13 three-node
replica set (ports 30001-30003). Group commit ran at its defaults. "Before" is
`7c37b69` (the spec branch before #335), run from a detached worktree. "After"
is this change. The two sides were interleaved, three runs each:

```bash
go test -run '^$' -bench 'BenchmarkMongoRouter/drain\+ack' \
    -benchtime 300x -benchmem ./internal/eventRouter/
```

`drain+ack` is `GetEventRecord`, then an RS256 re-sign, then `AckEvent`, per
SET. It exercises the single-JTI ack that the push transmitter sends.

## Results: router benchmark (three interleaved runs)

| Benchmark | Before (runs) | After (runs) | Median change |
|---|---|---|---|
| `drain+ack` (ms/op) | 3.05 / 3.68 / 2.83 | 1.74 / 1.59 / 1.65 | 3.05 -> 1.65 (-46%) |
| `drain+ack` (allocs/op) | 585 / 586 / 585 | 523 / 523 / 523 | -62 |
| `drain+ack` (B/op) | 58437 / 58787 / 58588 | 51722 / 51691 / 51721 | -11% |

The runs do not overlap. Two of the three round trips are gone, and the
benchmark's time dropped by a little under half.

## End to end (5000 events, 16 clients): not run

The `goSignalsBench` end-to-end run at 5000 events and 16 clients was **not**
done for this change. The dev containers compile the mounted source tree when
they start. A "before" run would mean reverting the working tree under the
shared dev stack. To run it:

1. Restart the stack on each tree with
   `docker compose -f docker-compose-dev.yml restart goSignals1 goSignals2 goSsfServer`.
2. Run the command below three times per side, as in
   [write-concern-332.md](write-concern-332.md):

```bash
make dev-bench BENCH_E2E_ARGS="--issuer=https://bench335<side><run>.example.com \
    --mongo-uri='mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?replicaSet=dbrs&authSource=admin' \
    --label=ack335-<side>-c16-r<run>"
```

The router result shows the change per acked SET. End-to-end throughput also
depends on ingest and push, so its gain will be smaller than 46%.

## Metrics

`AckDelivered` is a new `op` label on `goSignals_dao_op_duration_seconds` and
`goSignals_dao_batch_size`, counted in JTIs (see [Metrics.md](../Metrics.md)).
In production the ack path no longer emits `RemovePendingMany` or
`MarkDeliveredMany`, so dashboards that summed those ops for ack cost should
use `AckDelivered` instead.
