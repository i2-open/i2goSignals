# Throughput baseline (alpha.20 cycle, Stage 0)

The measured starting point for the spec-111 throughput work: a
concurrency sweep of the end-to-end harness on the Mongo and memory
providers, with DAO latency from the #328 histograms, WiredTiger journal
syncs per SET, and CPU and block profiles at 16 and 64 clients. How to
reproduce it is in [e2e-benchmark.md](e2e-benchmark.md#concurrency-sweep).

**Verdict:** ingest is bound by **Mongo round trips**. Each SET pays two
sequential writes (`InsertMany`, then `AddPendingMany`; ADR 0038), and
`InsertMany` is the dominant DAO op. With the database removed (memory
provider), the same stack ingests about 3x faster at one client and 1.8x
faster at 64. CPU is far from saturated and the push worker count does not
move the numbers. Journal syncs fall from about 3.7 to about 0.55 per SET
as concurrency rises, so group commit already amortises the fsync, and the
per-SET cost that remains is round-trip latency and queueing.

## Environment

| Item | Value |
|---|---|
| Host | Apple M3 Max, 14 cores, 96 GiB RAM, macOS (Darwin 25.6) |
| Docker | Docker Desktop, 14 CPUs, about 63 GiB |
| Go | 1.27.0 darwin/arm64 (harness); servers built from source in the dev image |
| Servers | `goSignals1` + `goSignals2` from `docker-compose-dev.yml`, running under Delve (debug build), JSON logging, version 0.12.0-alpha.19 at `b855d5b` |
| Mongo | 8.0.13, three-node replica set `dbrs` in Docker, one primary |
| Memory provider | same stack with `docker-compose-dev-memory.yml` (`MONGO_URL=memorydb:`) |
| Load | 5000 events, `--mix alternate` (one third each to push, poll and SSTP), goSignals1 SSTP initiator |
| Date | 2026-09-28 |

This is a noisy dev environment, not a production one. Delve, debug
logging and Docker Desktop networking all sit in the path. Treat
differences under about 10% as noise.

## The axes

- **Clients**: `--concurrency` 1, 4, 16 and 64. The server has no ingest
  worker pool, so client count is ingest parallelism.
- **Workers**: `I2SIG_PUSH_CONCURRENCY` on goSignals1, the push-delivery
  pool (ADR 0037). `default` is `GOMAXPROCS` clamped to 8..32, which is
  **14** here. It was set to 8 and 32 when the stack was started.

## Ingest throughput (ev/s)

Unprofiled runs; wall time for the whole run (ingest plus drain) is in
brackets.

| Provider | Workers | 1 client | 4 clients | 16 clients | 64 clients |
|---|---|---|---|---|---|
| Mongo | default (14) | 239 (21.5 s) | 504 (10.4 s) | 681 (7.9 s) | 1140 (6.4 s) |
| Mongo | 8 | 242 (21.2 s) | 474 (11.1 s) | 725 (7.4 s) | 1114 (6.5 s) |
| Mongo | 32 | 235 (21.8 s) | 514 (10.2 s) | 674 (7.9 s) | 1129 (6.0 s) |
| Memory | default (14) | 741 (7.3 s) | 1668 (3.5 s) | 1941 (3.1 s) | 2062 (2.9 s) |
| Memory | 32 | 801 (6.8 s) | 1547 (3.7 s) | 1870 (3.2 s) | 1827 (3.3 s) |

There were no ingest errors and every leg delivered 100% in every run. The
worker axis moves ingest by less than the 10% noise band on both providers.
The memory provider was not run at 8 workers (see Caveats).

The first Mongo default pass measured 247 / 354 / 398 ev/s at 1 / 4 / 16
clients, with DAO p95 up to 36 ms. The repeat (the row above) and both
other worker settings agree with each other, so that pass is treated as a
cold-cache outlier.

## Delivery throughput (ev/s per leg: push / poll / SSTP)

Each leg carries a third of the events (about 1667). The rate is that leg's
events divided by its end-to-end time from the first ingest, so aggregate
delivery is about three times the per-leg figure. Every leg drains within
two seconds of ingest finishing (usually well under one), so delivery
keeps pace with ingest and does not set the rate.

| Provider | Workers | 1 client | 4 clients | 16 clients | 64 clients |
|---|---|---|---|---|---|
| Mongo | default | 78 / 78 / 78 | 160 / 160 / 160 | 212 / 212 / 212 | 260 / 282 / 282 |
| Mongo | 8 | 79 / 79 / 81 | 151 / 151 / 151 | 225 / 225 / 225 | 256 / 334 / 303 |
| Mongo | 32 | 77 / 77 / 78 | 163 / 163 / 163 | 210 / 210 / 210 | 306 / 280 / 280 |
| Memory | default | 230 / 230 / 230 | 475 / 475 / 474 | 540 / 540 / 540 | 568 / 568 / 568 |
| Memory | 32 | 247 / 247 / 267 | 446 / 446 / 446 | 522 / 522 / 522 | 513 / 513 / 513 |

## DAO latency on goSignals1 (p50 / p95, ms)

These figures come from the `goSignals_dao_op_duration_seconds` histograms,
as the difference between scrapes taken before and after each run. Each
ingested SET makes exactly one `InsertMany` and one `AddPendingMany` call
(5000 of each per run).

| Provider / workers | Op | 1 client | 4 clients | 16 clients | 64 clients |
|---|---|---|---|---|---|
| Mongo default | `InsertMany` | 1.96 / 4.51 | 3.53 / 7.76 | 4.29 / 15.38 | 5.48 / 21.86 |
| Mongo default | `AddPendingMany` | 1.82 / 3.87 | 3.00 / 4.95 | 3.77 / 9.43 | 4.66 / 13.99 |
| Mongo 8 | `InsertMany` | 1.94 / 4.47 | 3.61 / 8.33 | 4.03 / 12.56 | 6.31 / 22.57 |
| Mongo 32 | `InsertMany` | 1.94 / 4.45 | 3.48 / 7.73 | 4.23 / 16.59 | 4.97 / 20.52 |
| Memory default | `InsertMany` | 0.25 / 0.48 | 0.27 / 0.79 | 0.34 / 4.05 | 0.48 / 18.25 |
| Memory default | `AddPendingMany` | 0.25 / 0.48 | 0.26 / 0.49 | 0.30 / 2.99 | 0.37 / 15.70 |
| Memory 32 | `InsertMany` | 0.25 / 0.48 | 0.27 / 0.86 | 0.33 / 4.55 | 0.41 / 19.22 |

The lowest histogram bucket is 0.5 ms, so a memory p50 of about 0.25 ms
means "under 0.5 ms". The memory p95 still climbs to 15-19 ms at 64
clients. That is lock contention inside the in-memory store and the
router, not I/O.

**Dominant op:** `InsertMany`, by total wall time on goSignals1, in 23 of
24 runs. The exception is Mongo, 32 workers, 1 client, where
`RemovePendingMany` edged ahead: at one client, delivery acks arrive one
at a time, about 5000 calls. `InsertMany` is also the dominant op on
goSignals2 in every run.

## Journal syncs per SET (Mongo)

These are server-wide deltas of the primary's `wiredTiger.log` counters,
covering both nodes and all background writes. The memory provider shows
about zero, as a control.

| Workers | Metric | 1 client | 4 clients | 16 clients | 64 clients |
|---|---|---|---|---|---|
| default | syncs / SET | 3.73 | 1.45 | 0.89 | 0.57 |
| default | log writes / SET | 8.71 | 4.42 | 3.42 | 3.03 |
| default | sync time (s) | 11.4 | 6.7 | 5.1 | 4.2 |
| 8 | syncs / SET | 3.71 | 1.46 | 0.92 | 0.57 |
| 32 | syncs / SET | 3.79 | 1.45 | 0.91 | 0.53 |

At one client every write commits on its own: about 3.7 syncs per SET
across the ingest pair and the delivery bookkeeping. As concurrency rises,
WiredTiger group commit folds concurrent commits into one sync, so syncs
per SET fall about 6.5x by 64 clients. Log writes per SET settle near 3,
which matches the writes each SET needs end to end.

## Profiles (Mongo, default workers, 16 and 64 clients)

These are 10 s CPU and block profiles from runs with
`I2SIG_PPROF_BLOCK_RATE=1`. Those runs measured 663 and 904 ev/s. The drop
at 64 clients against the unprofiled 1140 is the cost of block sampling.

- **CPU is not the bound.** goSignals1 uses about 2.5 of 14 cores. Roughly
  half of its samples are RSA `SignPKCS1v15`, from re-signing outbound SETs
  in publish mode (push `tokenString`, poll `assemblePollResponse`, SSTP
  `buildSstpSets`), with GC the next largest cost.
- **Goroutines wait on Mongo.** At 64 clients, 57% of goSignals1's blocked
  time is in `select`, and the largest single site is the Mongo driver's
  `contextDoneListener.Listen` (about 145 s per 10 s window, or roughly 14
  goroutines parked on a Mongo reply at any moment). At 16 clients, `select`
  is 59%.
- **Router lock convoy (secondary).** `sync.RWMutex.RLock` accounts for 29%
  of blocked time at 64 clients (19.5% at 16). The readers are ingest's
  fan-out commit (`handleEvents`, `event_router.go` about line 1055) and
  `IncrementCounter` (about line 560), both on the router's `r.mu`. The
  writer they queue behind is `acquireSstpSecondPushSlot`
  (`sstp_outbound.go` about lines 575 and 586). A pending writer on an
  RWMutex stalls every new reader, so each SSTP slot claim briefly pauses
  ingest.
- **Logging mutex.** Most `sync.Mutex.Lock` waiting is in `slog`'s handler,
  which serialises writers of the debug-level JSON log.

## What bounds throughput

1. **Mongo round trips, per SET.** At one client, a SET takes 4.2 ms
   (1 / 239 ev/s), and the two sequential ingest writes take about 3.8 ms
   of that (p50 1.96 + 1.82). With more clients, the round trips overlap,
   but their latency grows about 3x (p50 `InsertMany` from 1.96 to 5.48 ms)
   as work queues in the driver and on the primary. Throughput therefore
   rises sub-linearly: 16x the clients gives 2.8x the ingest. The memory
   control, with the same HTTP, TLS, JWT and routing work, runs 1.8-3.1x
   faster.
2. **Journal fsync** is significant only at low concurrency. Group commit
   already brings it down to about 0.55 syncs per SET at 64 clients.
3. **Secondary costs** show up once Mongo is removed: memory-provider
   ingest flattens above 16 clients. They are the router `r.mu` convoy, RSA
   re-signing and the logging mutex.

For the next stage, this points at cutting the number of round trips
(ADR 0038's two writes per SET, per-call batching) rather than adding
workers.

## Caveats

- Servers ran under Delve with debug logging, so absolute numbers
  understate a release build. Comparisons within this table hold.
- Each run is short (5000 events, 3-22 s). Single runs sit within about
  10% of each other; differences smaller than that are noise.
- The memory provider was swept at `default` and `32` workers only.
  Workers made no difference on Mongo or on the memory runs, so the
  8-worker memory row was not run.
- Journal counters are server-wide and include lease and heartbeat writes
  from both nodes.
- Profiles were taken on Mongo only. Block sampling lowers throughput at 64
  clients.

## Spec #112 single-node run (i2-open/i2goSignals#366)

The run that closes the spec's single-node clause: 5000 events, 16
clients, `--mix alternate`, one node, on the spec branch
`spec-112-cluster-delivery` at `2a54c40` plus this slice. The branch already
includes the `deliveries` collection (#359/#360), the per-stream delivery
queue and coalesced ack, and #352's two observations per SET. Measured
2026-10-05 on the same host as above.

**Stack difference.** These runs used the benchmark stack
(`make bench-stack-up`, `docker-compose-benchmark.yml`): a release image,
majority durability, not Delve. The baseline above ran on the dev stack under
Delve, so its absolute numbers are lower and the two rows are not
like-for-like. To get a like-for-like comparison, `release-0.12.0` at
`b38b9c2` (the spec branch's base) was built into the same benchmark image
and run on the same stack between the spec runs.

| Build | Stack | Runs | Ingest ev/s (mean, range) | Ingest p50 ms | Per-leg ev/s push / poll / SSTP | `InsertWithPending` mean ms |
|---|---|---|---|---|---|---|
| alpha.20 baseline (Mongo, default workers) | dev, Delve | 1 | 681 | - | 212 / 212 / 212 | (`InsertMany` + `AddPendingMany`) |
| `release-0.12.0` `b38b9c2` (control) | bench | 3 | 1536 (1477-1576) | 8.6 | 450 / 450 / 450 (2 runs) | 5.92 |
| spec #112 branch | bench | 6 | 1389 (1306-1536) | 9.9 | 406 / 406 / 405 | 6.78 |

Every spec run drained all three legs to 100%. The third control run's SSTP
leg stalled at 4 of 1666 events and timed out; that is an existing
`release-0.12.0` flake, not counted in the control's per-leg mean, and its
ingest figure (1477) is included.

**Reading.** Against the alpha.20 table the spec branch ingests about 2x
faster at 16 clients, but most of that is the stack (release image, no
Delve). Against the like-for-like control the spec branch is about 9-10%
lower (1389 against 1536 ev/s), at the edge of the 10% noise band; the spread
of the six spec runs (1306-1536) overlaps the control's range. The visible
cost is in the ingest write: `InsertWithPending` mean rises from 5.9 to
6.8 ms, consistent with the `deliveries` collection carrying more indexes
than the old pendingEvents collection (unique `(sid, jti)`, `(sid, state,
jti)`, the partial `(sid, createdAt)` for `OldestBeyond`, `jti`, TTL). That
is the spec's design, not something this slice changes.

**Verified properties** (spec runs; the control build has no such counters):

| Counter | Per run |
|---|---|
| Ack writes / ack batches | 1199-1756 / 1199-1756, so 1.000 writes per batch |
| Reads under the router lock | 0 |
| Reads before an ack batch | 0 |
| Peer claims served / budget exhausted | 0 / 0 (single node, no peer) |

**`OldestBeyond` query cost.** The queue window was smaller than the
backlog in every spec run, so `GetPendingForStreamBeyond` fired 25-149 times
a run (65, 144, 67, 27, 25, 149). Its mean was 3.0-4.7 ms, against
2.0-4.6 ms for a plain `GetPendingForStream` page (one outlier run at
14.4 ms). The extra `find ... sort({createdAt: 1}).limit(1)` over
`deliveriesPendingCreatedAt` therefore adds about a millisecond to a read
that is off the ingest path.

## Spec #112 re-run at `0ef80a4` (i2-open/i2goSignals#366, #367)

A second measurement of the spec branch, after the lock-audit gate:
`I2SIG_ROUTER_LOCK_AUDIT` now turns the goroutine-ID router-lock audit on
and off, and it is off by default (production). `docker-compose-benchmark.yml`
sets it to `true` so that the bench's `properties:` line can count reads
under the lock, so both settings were measured. Same host, same benchmark
stack (`make build-docker`, fresh volumes), same load as the run above:
5000 events, 16 clients, `--mix alternate`, one node. Measured 2026-10-05.

| Build | Lock audit | Runs | Ingest ev/s median (range) | Ingest p50 ms | Per-leg ev/s | `InsertWithPending` mean ms |
|---|---|---|---|---|---|---|
| `release-0.12.0` `b38b9c2` (control, above) | n/a | 3 | 1536 mean (1477-1576) | 8.6 | 450 | 5.92 |
| spec #112 at `2a54c40` (above) | on | 6 | 1389 mean (1306-1536) | 9.9 | 406 | 6.78 |
| spec #112 at `0ef80a4` | **off** (production) | 6 | **1489** (1469-1523) | 8.8-9.2 | 426-439 | 5.93-6.19 |
| spec #112 at `0ef80a4` | on (bench default) | 3 | 1455 (1449-1476) | 9.3-9.5 | 420-427 | - |

Against the control's 1536 ev/s, the production setting is **3.1% lower** and
the audit-on setting 5.3% lower. Both are inside the 10% noise band, and the
production setting's range overlaps the control's. The `InsertWithPending`
mean is back at the control's figure (5.9-6.2 ms against 5.92 ms). Every
leg of every run drained to 100%. Ack writes were 1.000 per batch, and reads
under the lock and before an ack were 0 with the audit on.
`GetPendingForStreamBeyond` fired 31-125 times a run, with a mean of
2.9-5.5 ms.

**Profile** (separate run with mutex and block sampling on, so it is not in
the table; goSignals1, 4 s window). RSA signing accounts for about half of
the CPU (`goSet.JWS` 57% cumulative: push delivery, poll response and the SSTP
ack). That cost predates #112. The #112 paths (`deliveryQueue`, `acker`,
`walReadThrough`, group commit) account for about 3% of CPU, and most of
that is Mongo driver I/O. Contention on `sync.Mutex` is 0.12 s over a 4 s
window across all goroutines; the rest of the mutex delay is the runtime
scheduler lock. Blocking is dominated by ingest waiting on the
`InsertWithPending` round trip, which is the design. No #112 hotspot could
give a gain larger than the noise band, so no optimisation was attempted.

### Two-node drains at 128 clients (#367)

Benchmark stack with `BENCH_CLUSTER=1` (goSignals1 + goSignals1b, ingest
alternating between them, WAL local), 5000 events, 128 clients, lock audit
on. The benchmark certificates have no SAN for `goSignals1b`, so a scratch
compose override gave goSignals1b the network alias `goSsfServer` (which is in
the SAN and not run in this stack), and the `--gs1b-internal` runs used
`https://goSsfServer:8888`. The first `--gs1b-internal` poll run, made without
the alias, failed TLS verification and did not drain (goSignals2 logged `tls: failed to verify certificate`).

| Leg | Receiver points at | Ingest ev/s | Drained | Leg ev/s | Delivery p50 / p95 ms | Peer claims served |
|---|---|---|---|---|---|---|
| push | - | 3455 | 5000/5000 | 1682 | 1128 / 1714 | 0 |
| POLL | goSignals1 | 3087 | 5000/5000 | 2343 | 569 / 919 | 0 |
| POLL | goSignals1b | 3334 | 5000/5000 | 2492 | 570 / 892 | 0 |
| POLL (repeat) | goSignals1 | 3167 | 5000/5000 | 2396 | 516 / 733 | 0 |
| POLL (repeat) | goSignals1b | 3334 | 5000/5000 | 2490 | 552 / 860 | 0 |
| SSTP, goSignals1 dials | - | 3891 | 5000/5000 | 1782 | 1120 / 1337 | 0 |
| SSTP, goSignals1 accepts | goSignals1 | 3828 | 5000/5000 | 1763 | 1108 / 1336 | **50** |
| SSTP, goSignals1 accepts | goSignals1b | 3852 | 5000/5000 | 1771 | 1125 / 1338 | 0 |

Every leg drained. The responder leg shows peer claims served (50, all
counted on goSignals1b as `mode="sstp-server"`), so a non-owner served
through the owner. **The POLL leg showed no peer claims in any of its four
runs**, on either node (`goSignals_router_peer_claims_total` has no
`poll-transmitter` series on either node). The polled node appears to hold
the poll-transmitter lease each time, so the non-owner poll path did not run.
#367's acceptance criterion for the POLL leg is therefore not met by these
runs.

### POLL peer claims: both nodes polled, and a pinned owner (#367)

The four POLL runs above showed no peer claims because goSignals2 polls one
node, which takes the stream's poll-transmitter lease on its first poll
(`resolveOwnerSeeded`) and keeps it. Two bench options now put polls on a
non-owner (#366): `--poll-targets both` creates one goSignals2 poll receiver
per node, and `--poll-pin-owner` has the harness poll goSignals1b once (taking
the lease) before goSignals2 starts polling goSignals1. The bench certificate
now names `goSignals1b` (`make generate-certs` reissued the server
certificate under the existing CA), so `--gs1b-internal
https://goSignals1b:8888` works without the network alias.

Same benchmark stack (`BENCH_CLUSTER=1`, fresh volumes, image as above, lock
audit on), 5000 events, 128 clients, `--mix poll`, ingest alternating
between the nodes. The lease owner was read from `cluster_leases` during
each run. Measured 2026-10-05.

| Run | Lease owner | Ingest ev/s | Drained | Leg ev/s | Delivery p50 / p95 ms | Peer claims served | Ack writes / batch | Reads under lock / before ack | Budget exhausted |
|---|---|---|---|---|---|---|---|---|---|
| both nodes, 1 | goSignals1 | 2733 | 5000/5000 | 2130 | 135 / 228 | **36** | 80 / 80 (1.000) | 0 / 0 | 0 |
| both nodes, 2 | goSignals1 | 2580 | 5000/5000 | 2042 | 145 / 235 | **33** | 78 / 78 (1.000) | 0 / 0 | 0 |
| both nodes, 3 | goSignals1 | 2700 | 5000/5000 | 2117 | 150 / 235 | **34** | 71 / 71 (1.000) | 0 / 0 | 0 |
| pinned owner, 1 | goSignals1b | 3276 | 5000/5000 | 2458 | 583 / 910 | **52** | 52 / 52 (1.000) | 0 / 0 | 0 |
| pinned owner, 2 | goSignals1b | 3432 | 5000/5000 | 2012 | 718 / 942 | **51** | 51 / 51 (1.000) | 0 / 0 | 0 |

Every run drained, and every run shows peer claims served, so the
non-owner poll path ran under load. With both nodes polled, a little under
half of the poll batches (33-36 of 71-80 ack batches) were served to
goSignals1b, the non-owner, through a peer claim. With the owner pinned, every
poll batch was a peer claim (claims = ack batches). The peer counter is on the owner and carries the
label `mode="poll"`, not `poll-transmitter`, so the earlier note that "no
poll-transmitter series" exists was looking for the wrong label. The claim
budget was never exhausted. Throughput stays in the range of the
single-target runs above (2343-2492 ev/s), and the pinned worst case is no
slower than polling the owner directly.

Polling both nodes roughly quarters the delivery latency (p50 about 145 ms
against about 550 ms) because two receivers each long-poll. Read that as a
change in receiver concurrency, not as a gain from the peer hop.

These were agent runs on the benchmark stack, not hand runs on the developer
stack, which is what #367 specifies.
