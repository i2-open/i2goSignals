# One-trip ingest write (#331, spec-111 Stage 1)

This page compares ingest before and after ADR 0043's one-trip write. Before
the change, the event bodies and their pending markers were two concurrent
writes with retraction (ADR 0038). After it, they are one ordered
multi-namespace `bulkWrite` (`EventDAO.InsertWithPending`). Both sides run
with the #330 group-commit decorator on at its defaults.

## Procedure

"Before" is a detached worktree at `9113c1a` (#330). "After" is this change.
Both carry the same bench-only fix (`EnsureSigningKey` for the bench issuer,
#308). The environment is an M3 Max against the dev stack's Mongo 8.0.13
three-node replica set (ports 30001-30003). The provider logged
`serverVersion=8.0.13` and selected one-trip mode. The two sides ran
interleaved, three times each:

```bash
go test -run '^$' -bench 'BenchmarkMongoRouter/(ingest$|ingest-batch100)' \
    -benchtime 300x ./internal/eventRouter/
```

The regex also matches `verify+ingest`.

## Results (medians of three interleaved runs)

| Benchmark | Before (runs) | After (runs) | Median change |
|---|---|---|---|
| `ingest` (ms/op, serial) | 3.12 / 3.00 / 3.04 | 3.49 / 3.24 / 3.33 | 3.04 -> 3.33 (+9.5%) |
| `verify+ingest` (ms/op) | 3.48 / 3.19 / 3.28 | 3.52 / 3.40 / 6.86 | 3.28 -> 3.52 (+7%) |
| `ingest-batch100/workers=1` (µs/SET) | 3367 / 3228 / 3075 | 3524 / 3243 / 3305 | 3228 -> 3305 (+2%, noise) |
| `ingest-batch100/workers=4` (µs/SET) | 929 / 1185 / 842 | 1178 / 1060 / 1060 | 929 -> 1060 (+14%) |
| `ingest-batch100/workers=8` (µs/SET) | 518 / 518 / 490 | 803 / 622 / 627 | 518 -> 627 (+21%) |
| `ingest-batch100/workers=16` (µs/SET) | 321 / 313 / 299 | 417 / 380 / 443 | 313 -> 417 (+33%) |

Allocations barely moved: `ingest` went 1012 -> 1016 allocs/op, and the batch
cases rose by about 3% per SET.

## Reading

On this stack the one-trip write is **slower** at the router, and the gap
widens with concurrency. The serial single-SET case is within about 10%, and
the concurrent batches lose 14-33%. The runs do not overlap at 8 and 16
workers.

A likely cause, which has **not** been verified by a server-side profile, is
this. ADR 0038 had already overlapped the two majority-acked writes, so one
trip saves little wall-clock latency. Meanwhile the client-level `bulkWrite`
command (an admin-database command that interleaves two namespaces) costs more
per op than two collection `insert` commands. Also, under group commit each
flush is now one serial bulkWrite instead of two parallel inserts. The next
step would be a profiler-level-2 comparison of `bulkWrite` against
`insert` + `insert` durations on `goSignals1`.

## Gap: end-to-end 5000 events / 16 clients

The acceptance point, `goSignalsBench` at 5000 events and 16 clients, was
**not run** for this change. It needs `make dev-rebuild` on the shared dev
stack, which other agents may be using. To produce it:

```bash
make dev-rebuild
make dev-bench BENCH_E2E_ARGS="--issuer=https://bench331.example.com \
    --mongo-uri='mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?replicaSet=dbrs&authSource=admin' \
    --label=ot331-c16-r1"
```

Compare the result against the "After, 16 clients" column of
[group-commit-330.md](group-commit-330.md) (707 / 721 / 719 ev/s).
