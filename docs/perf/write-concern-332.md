# Per-collection write concern (#332, spec-111 Stage 1)

This page compares the ack path before and after #332. Before the change the
Mongo client carried `w:majority`, so every collection wrote at majority.
After it, each collection handle carries its own concern:

- `events`, `pendingEvents` and `cluster_leases` use majority with `j:true`.
- `deliveredEvents` and the admin/config collections use `w:1`.

The full table is in
[configuration_properties.md](../configuration_properties.md#mongo-write-concern).
The one-trip ingest `bulkWrite` sets majority with `j:true` explicitly,
because it takes the client's concern and the client now has none.

## Procedure

The environment is an M3 Max with the dev stack's Mongo 8.0.13 three-node
replica set (ports 30001-30003). Both sides ran in one-trip mode with group
commit at its defaults. "Before" is `97ea6fe` (#331) and "after" is this
change.

**Router benchmark.** "Before" ran from a detached worktree at `97ea6fe`. The
two sides were interleaved, three runs each:

```bash
go test -run '^$' -bench 'BenchmarkMongoRouter/(ingest$|drain\+ack)' \
    -benchtime 300x -benchmem ./internal/eventRouter/
go test -run '^$' -bench 'BenchmarkMongoRouter/ingest-batch100/workers=16$' \
    -benchtime 300x -benchmem ./internal/eventRouter/
```

**End to end, 5000 events and 16 clients.** The dev containers compile the
mounted source tree when they start. Each side was therefore a
`docker compose -f docker-compose-dev.yml restart goSignals1 goSignals2 goSsfServer`
on that tree, followed by three runs:

```bash
make dev-bench BENCH_E2E_ARGS="--issuer=https://bench332<side><run>.example.com \
    --mongo-uri='mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?replicaSet=dbrs&authSource=admin' \
    --label=wc332-<side>-c16-r<run>"
```

The end-to-end runs were **not** interleaved. All three "after" runs came
first, then all three "before" runs. Both sides slowed a little from run to
run.

## Results: router benchmark (medians of three interleaved runs)

| Benchmark | Before (runs) | After (runs) | Median change |
|---|---|---|---|
| `drain+ack` (ms/op) | 3.63 / 3.85 / 3.72 | 3.12 / 3.14 / 3.26 | 3.72 -> 3.14 (-16%) |
| `ingest` (ms/op, serial) | 3.25 / 3.27 / 3.44 | 3.18 / 3.36 / 3.20 | 3.27 -> 3.20 (noise) |
| `ingest-batch100/workers=16` (µs/SET) | 418 / 437 / 434 | 428 / 435 / 464 | 434 -> 435 (noise) |

The `drain+ack` runs do not overlap. Allocations did not change: `drain+ack`
stayed at 583-585 allocs/op on both sides.

## Results: end to end (`goSignalsBench`, 5000 events, 16 clients)

| Metric | Before (runs) | After (runs) | Median |
|---|---|---|---|
| `MarkDeliveredMany` p50 (ms) | 4.35 / 4.39 / 4.76 | 0.80 / 0.85 / 0.97 | 4.39 -> 0.85 (-81%) |
| `MarkDeliveredMany` mean (ms) | 4.84 / 4.90 / 5.30 | 1.19 / 1.29 / 1.48 | 4.90 -> 1.29 |
| `RemovePendingMany` p50 (ms) | 6.26 / 6.78 / 6.93 | 6.50 / 6.89 / 7.32 | unchanged (still majority) |
| `InsertWithPending` p50 (ms) | 8.83 / 9.26 / 9.97 | 9.30 / 9.47 / 10.78 | unchanged (still majority) |
| Ingest (ev/s) | 810 / 783 / 734 | 786 / 754 / 705 | 783 -> 754 (inside the spread) |
| Ingest latency p50 (ms) | 16.9 / 18.4 / 19.6 | 18.5 / 19.1 / 20.5 | inside the spread |
| Push leg e2e (s) | 6.69 / 6.89 / 7.32 | 6.87 / 7.15 / 7.60 | inside the spread |
| Drain after ingest (s) | 0.52 / 0.51 / 0.51 | 0.51 / 0.51 / 0.51 | unchanged |
| Journal syncs / SET | 0.44 / 0.44 / 0.45 | 0.42 / 0.43 / 0.41 | about -5% |

Every run had 0 ingest errors, and every leg delivered 100%.

## Reading

- **The ack path gets cheaper.** The delivered-record insert fell from about
  4.4 ms to about 0.85 ms. It no longer waits for a secondary to replicate the
  write. In the router benchmark this is a 16% cut per drained-and-acked SET.
- **The rest of the ack is unchanged.** Acking a SET also deletes its pending
  marker. That delete stays majority, because `pendingEvents` is part of the
  ADR 0038 contract. It is now the larger part of the ack's database time.
- **Ingest does not move.** `events` and `pendingEvents` were majority before
  and are still majority. The end-to-end ingest differences are inside the
  run-to-run spread, and the run order was not interleaved.
- **Durability.** ADR 0038 is unchanged: no SET is acked before its body and
  markers are majority-journaled. A `deliveredEvents` row written at `w:1` can
  be lost if the primary fails over before it replicates. The row is the
  retention purge anchor (ADR 0055), so losing it only delays that event's
  purge. The pending marker was already removed at majority, so the SET is
  not redelivered.

## Caveats

- The servers ran under Delve with debug logging, as in the earlier Stage 1
  pages.
- Leases moved from client majority to handle majority. Their cost is the
  same, and no lease-path benchmark was run.
