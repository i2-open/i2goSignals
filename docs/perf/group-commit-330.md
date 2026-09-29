# Group commit on EventDAO writes (#330, spec-111 Stage 1)

This page compares the end-to-end harness before and after the
group-commit decorator (`internal/dao/groupcommit`). The decorator merges
concurrent `Insert`/`InsertMany` calls into one bulk `InsertMany`, and
merges `AddPending`/`AddPendingMany` calls for the same stream into one
`AddPendingMany`. It is tuned by `I2SIG_STORE_GROUP_COMMIT_WINDOW` (default
`1ms`) and `I2SIG_STORE_GROUP_COMMIT_MAX` (default `128`); see
[configuration_properties.md](../configuration_properties.md#store_groupcommit).

"Before" is the Mongo default-workers row of the #329 baseline,
[throughput-baseline-alpha20.md](throughput-baseline-alpha20.md). "After"
uses the same stack, harness and load with the decorator on at its
defaults. The environment is the one described there: M3 Max, servers
under Delve, Mongo 8.0.13 three-node replica set, 5000 events,
`--mix alternate`. The same 10% noise band applies.

## Procedure

```bash
make dev-rebuild      # dev image with the decorator; restarts both nodes
make dev-bench BENCH_E2E_ARGS="--issuer=https://bench330.example.com \
    --mongo-uri='mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?replicaSet=dbrs&authSource=admin' \
    --label=gc330-c16-r1"
```

This was run three times at 16 clients (the acceptance point) and once at
64 clients (`BENCH_E2E_CONCURRENCY=64`). Using a new `--issuer` makes the
harness mint a fresh signing key. The stack held an issuer key from an
earlier run that did not match the saved PEM, which made every push fail
signature verification (HTTP 400) until the issuer was changed.

## Results (Mongo, default workers)

| Metric | Before, 16 clients | After, 16 clients (3 runs) | Before, 64 clients | After, 64 clients (1 run) |
|---|---|---|---|---|
| Ingest (ev/s) | 681 | 707 / 721 / 719 | 1140 | 1497 |
| Ingest wall time (s) | about 7.3 | 7.07 / 6.93 / 6.95 | about 4.4 | 3.34 |
| Delivery per leg (ev/s) | 212 | 220-224 | 260-282 | 343 / 383 / 343 |
| Journal syncs / SET | 0.89 | 0.66 / 0.69 / 0.69 | 0.57 | 0.36 |
| Log writes / SET | 3.42 | 1.89 / 1.91 / 1.92 | 3.03 | 1.07 |
| `InsertMany` p50 / p95 (ms) | 4.29 / 15.38 | 6.6-7.0 / 19.9-21.4 | 5.48 / 21.86 | 8.10 / 23.17 |
| `AddPendingMany` p50 / p95 (ms) | 3.77 / 9.43 | 4.5-4.6 / 10.0-10.8 | 4.66 / 13.99 | 5.66 / 15.98 |

There were no ingest errors, and every leg delivered 100% in every run.

## Reading it

- **Fewer round trips reach Mongo.** Log writes per SET fall by 45% at 16
  clients and by 65% at 64 clients. Journal syncs per SET fall by 23% and
  37%. The primary is committing fewer, larger bulk writes.
- **At 16 clients, ingest gains 4-6%, which is inside the noise band.**
  Each client still makes its two ingest writes in sequence (ADR 0038). So
  16 clients put at most 16 records in flight, and a batch rarely holds
  more than a few of them. The saved round trips are offset by the
  collection window and the queueing in front of it.
- **At 64 clients, ingest gains 31% (1140 to 1497 ev/s).** This is outside
  the noise band. There are enough concurrent callers to fill the batches.
- **The DAO histograms measure the caller's view.** `daometrics` wraps
  outside `groupcommit`, so the `InsertMany` / `AddPendingMany` figures
  include the time a caller waits for its batch. That is why p50 rises by
  about 1-2.5 ms even though Mongo does less work. There is still exactly
  one recorded call per SET, and the size of the merged inner write is not
  exported.
- **Durability is unchanged.** Every merged write is still one
  majority-journaled bulk write, and no caller gets an answer before that
  write completes. The two-leg `BeginAddEvents` join is untouched;
  collapsing it is #331.

## Caveats

- There is no control run with the window set to 0 in this pass. "Before"
  is the #329 baseline taken earlier the same day on the same stack. It is
  a different build, and #333/#334 landed in between.
- The 64-client figure is a single run.
- Servers ran under Delve with debug logging, as in the baseline.
