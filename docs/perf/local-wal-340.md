# Local WAL ingest (#340): measurements

This note gives the measurements behind ADR 0045 (`I2SIG_STORE_WAL=local`,
spec-111 Stage 3).

## Method

`BenchmarkMongoRouterWalIngest` (`internal/eventRouter/local_wal_bench_test.go`)
sends 5000 single-SET pushes from 16 concurrent goroutines through the
router's `HandleEvent` into MongoDB. It runs two sub-benchmarks:

- `majority`: the ADR 0043 one-trip path. The benchmark has no local WAL.
- `local`: a bbolt WAL in a temporary directory, with the drain worker
  running.

It reports two rates:

- `ack-ev/s`: SETs acknowledged per second.
- `stored-ev/s`: SETs in Mongo per second. In `local` mode, the clock stops
  when the WAL depth reaches zero.

The Mongo target is the dev 3-member `mongo:8.0.13` replica set
(`MONGO_URL`, or the benchmark default).

To run it on the host:

```bash
go test -run xxx -bench BenchmarkMongoRouterWalIngest -benchtime=1x -count=3 ./internal/eventRouter/
```

To run it from a Linux container on the dev Docker network, which is the
same VM as Mongo:

```bash
docker run --rm --network i2gosignals_backend \
    -v "$PWD":/src:ro -v "$(go env GOMODCACHE)":/go/pkg/mod \
    -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=auto -w /src golang:1.25 \
    sh -c 'mkdir /tmp/w && cd /src && tar --exclude=./.mongo --exclude=./.git -cf - . | tar -xf - -C /tmp/w && cd /tmp/w && go test -run xxx -bench BenchmarkMongoRouterWalIngest -benchtime=1x -count=3 ./internal/eventRouter/'
```

The WAL micro-benchmarks are in `internal/wal/segment_bench_test.go`:
`BenchmarkSegmentAppendSerial`, and `BenchmarkSegmentAppend16` (16 concurrent
1 KB appends per op). The bbolt numbers below predate ADR 0046, which
replaced bbolt with a segment log (macOS: 16-way 18.5 -> 9.7 ms, serial
9.4 -> 4.5 ms).

End to end on the benchmark stack (`docker-compose-benchmark.yml`, 20000
events, 128 clients, `--durability=local`, same session, rows labelled
`algs-*-c128` in `e2e-history.md`): bbolt RS256 3271 / ES256 3920 ingest
ev/s; segment log RS256 3406 / ES256 4140 (p99 ingest latency 80.9 -> 69.8 ms
and 68.1 -> 61.0 ms). The new `goSignals_wal_append_seconds` histogram put
one append at about 7 ms mean, p99 under 25 ms, so inside the Linux VM the
WAL is now roughly a quarter of the 30 ms ingest p50; the rest is signature
verification and handler work, not the disk.

## Results (2026-09-28, Apple M3 Max, 3 runs)

| Router host                                 | `majority` ack-ev/s | `local` ack-ev/s | `local` stored-ev/s |
|---------------------------------------------|---------------------|------------------|---------------------|
| Linux container (dev Docker VM)             | 3533 / 2964 / 3468  | 6035 / 6341 / 6493 | 5941 / 6251 / 6405 |
| macOS host (APFS)                           | 3314 / 3219 / 3304  | 800 / 743 / 819  | about the same as ack |

| WAL commit (bbolt)       | Linux VM | macOS host (`F_FULLFSYNC`) |
|--------------------------|----------|----------------------------|
| One serial append        | 0.77 ms  | 9.4 ms                     |
| 16 concurrent appends    | 1.8 ms   | 19 ms                      |

## Findings

- **Linux:** `local` acknowledges about 1.8 to 1.9 times faster than
  `majority`. The drain keeps up: stored throughput is within 2% of ack.
- **macOS:** bbolt uses `F_FULLFSYNC`, which flushes the drive cache. A
  commit costs about 12 times what it costs in the Linux VM. On this host,
  `local` is *slower* than `majority`, because Mongo's own fsyncs run in the
  Linux VM. `local` mode pays off only on a host with cheap, honest fsync.
- **Group commit matters.** With bbolt's `DB.Batch`, whose batches close on a
  fixed timer, `local` reached only 125 ev/s on macOS. Under a slow fsync,
  batches degrade to about one call each. The leader-based group commit (then in
  `internal/wal/bolt.go`, now `segment.go`) brought this to about 550 ev/s. Routing the drain's
  `Truncate` through the same commit queue brought it to about 800 ev/s.

## End-to-end runs

The end-to-end `goSignalsBench` measurements were taken on
`docker-compose-benchmark.yml` once #343 lifted the single-node guard: the
single-node `algs-*-c128` rows quoted above, and the two-node
`cluster-*-c128` rows in [e2e-history.md](e2e-history.md). The two-node runs
are analysed in [cluster-perf.md](cluster-perf.md); in short, a second node
scales ingest but not delivery, because the cross-node hand-off is a
payload-less wake followed by a bounded backfill, and `local` mode's
wake-before-drain adds to that gap.
