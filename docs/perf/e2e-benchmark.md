# End-to-end benchmark harness (`goSignalsBench`)

`cmd/goSignalsBench` drives a large number of Security Event Tokens through the
`docker-compose-dev.yml` stack so the whole receive → route → deliver path can be
measured and profiled, and so throughput can be tracked over time. It complements
the micro-benchmark set in [go127-baseline.md](go127-baseline.md), which measures
isolated hot paths in-process; this harness measures the servers as deployed,
Mongo and TLS included.

## Topology

Every run builds five streams plus one SSTP pair (one half on each node) and,
unless `--keep`, deletes them afterwards:

```
harness ──RFC 8935 push──▶ goSignals1  ingress   (push-receive, route_mode FW,
                                                  aud = [push-aud, poll-aud, sstp-aud])
                              │
                              ├─ aud=push-aud ──RFC 8935 push──▶ goSignals2  push-receive (IM)
                              │   (push transmitter, PB)
                              │
                              ├─ aud=poll-aud ◀──RFC 8936 poll── goSignals2  poll-receive (IM)
                              │   (poll transmitter, PB)
                              │
                              └─ aud=sstp-aud ──SSTP pair──────▶ goSignals2  SSTP inbound (IM)
                                  (SSTP outbound, PB)             (--sstp-role picks who dials)
```

* The ingress stream on goSignals1 is a push receiver in **FORWARD** mode. The
  CLI default (IMPORT) stores events without routing, so it would measure nothing
  downstream.
* The three outbound legs have **different audiences**. Each generated SET
  carries one audience, rotating push → poll → SSTP (`--mix alternate`, the
  default), or all three (`--mix all`), so the EventRouter's audience match
  decides per event which leg carries it.
* The SSTP pair is a plain business stream: both halves are created with the
  `stream`+`event` client token the harness registers, no admin scope. Its
  reverse direction (goSignals2 → goSignals1, audience `<sstp-aud>/reverse`)
  is provisioned but carries no traffic.
* `--sstp-role` sets goSignals1's SSTP role and therefore which node is the
  HTTP client. `initiator` (default): goSignals1 dials `POST /sstp/{id}` on
  goSignals2 and carries the SETs in its request bodies. `responder`:
  goSignals2 dials goSignals1 and goSignals1 hands the SETs back in the
  long-poll responses. The audiences, modes and counting are the same in
  both, so the two rows are directly comparable and together cover both
  halves of the protocol.
* goSignals2's receivers trust `https://goSignals1:8888/jwks/<issuer>` because
  the transmitters re-sign (PUBLISH mode) with goSignals1's copy of the issuer
  key.
* The harness signs with an RSA key that goSignals1 mints on the first run
  (`POST /key/<issuer>` with the bootstrap secret). The PEM is saved to
  `bin/bench/<issuer host>.pem` (`bench.example.com.pem` by default; the
  issuer and audiences are URLs because the SSF profile uses URIs throughout,
  not because SSTP validation requires them) and reused on later runs. After `make dev-clean` the
  server forgets the key and the harness mints a fresh one.

The SETs use the SCIM profile (RFC 9967) event types rotated across
`prov:create:full`, `prov:patch:full` and `prov:delete`, with a SCIM User payload
shaped like the i2scim cluster demo's. To reuse the SCIM demo's issuer key
instead of minting one, pass
`--issuer cluster.scim.example.com --issuer-key config/scim/cluster-scim-issuer.pem`.

## What is measured

| Metric | Source |
|---|---|
| Ingest throughput, latency p50/p95/p99/max | harness timing of each `POST /events/{id}` (202 Accepted) |
| Ingress count | goSignals1 `goSignals_router_events_in_total{stream_id=ingress}` |
| Push leg delivered / drain time | goSignals2 `goSignals_router_events_in_total{stream_id=push-receiver}` |
| Poll leg delivered / drain time | goSignals2 `goSignals_router_events_in_total{stream_id=poll-receiver}` |
| SSTP leg delivered / drain time | goSignals2 `goSignals_router_events_in_total{stream_id=<SSTP inbound id>, tfr=SSTP}` |
| Delivery latency per leg, p50/p95/p99/max | goSignals2 `goSignals_router_event_age_at_receipt_seconds{tfr}`, diffed over the run |
| Verified properties (`properties:` line, `properties` in the JSON) | goSignals1 (+ `--gs1b`) `goSignals_router_ack_writes_total` / `goSignals_router_ack_batches_total` (ack writes per batch), `goSignals_router_reads_under_lock_total`, `goSignals_router_reads_before_ack_total` (design value 0 for both; counted only with `I2SIG_ROUTER_LOCK_AUDIT=true`, which the dev and benchmark stacks set) and `goSignals_router_peer_claims_total{result="served"}`, diffed over the run and summed over the cluster members |
| `OldestBeyond` query cost (`oldest-beyond` line, `oldest_beyond_gs1` in the JSON) | `goSignals_dao_op_duration_seconds{op="GetPendingForStreamBeyond"}` count and mean against `{op="GetPendingForStream"}`: a pending page shorter than the stream's backlog also reads `PendingPage.OldestBeyond`, so the count is non-zero only when a backlog exceeds the queue window |

### Ingest breakdown (DAO metrics)

The ingest latency above is the whole HTTP request. To see how much of it is the
two Mongo writes the 202 waits on, scrape goSignals1's `/metrics` for
`goSignals_dao_op_duration_seconds{op="InsertMany"}` and
`{op="AddPendingMany"}` (with `goSignals_dao_batch_size` for per-document cost)
and compare their p50 with `goSignals_http_duration_seconds`. The histograms,
labels, buckets and example queries are in
[`docs/Metrics.md` — DAO Metrics](../Metrics.md#dao-metrics). The design
questions these numbers feed are in the research notes
[event-store fast path](event-store-fast-path-research.md) and
[streaming throughput](streaming-throughput-research.md).

First reading (2026-09-28, dev stack, 2000 events, 16 workers, ingest p50
27.6 ms at 503 ev/s): `/events/{id}` HTTP p50 24.7 ms; `InsertMany` p50 6.6 ms
and `AddPendingMany` p50 5.7 ms, each with batch size 1 per request. The two
writes run concurrently, so roughly 7 ms of the ~25 ms request is Mongo; the
rest is per-request overhead outside the DAO.

Delivery is always counted on goSignals2. goSignals1's `events_out_total` is only
incremented on a push acknowledgement, never on a poll, so it cannot be used for
the poll leg. `/metrics` is unauthenticated on the dev stack, so no extra
credentials are needed.

SETs are built before the run starts. Each ingest worker signs its SET (RS256)
immediately before the POST, stamping `toe` at the same moment, and starts the
latency clock only after signing. Signing is therefore excluded from the ingest
latency samples, but it is inside the ingest wall time, so ingest ev/s is
slightly lower than in rows recorded before #325, when every SET was pre-signed.

Timings reported per leg:

* **end-to-end** — from the first push until goSignals2 has counted every
  expected event;
* **drain-after-ingest** — how long goSignals2 kept receiving after the harness
  finished pushing (0 means the leg kept up with ingest).

### Delivery latency

Drain time shows whether a leg kept up; it does not show how long one event
took. Per-event delivery latency fills that gap.

**Method.** The harness stamps each SET's `toe` claim with the current time just
before it POSTs the SET to goSignals1. When goSignals2 counts an inbound SET, it
observes receipt time minus `toe` into
`goSignals_router_event_age_at_receipt_seconds{tfr}` (`PUSH`, `POLL` or
`SSTP`). The harness scrapes that histogram on goSignals2 before and after the
run, takes the difference, and reports interpolated p50/p95/p99 (the same
method as PromQL `histogram_quantile`) for each leg. The result goes in the
`delivery latency` summary line, in `delivery_latency` in the JSON output, and
in the `lat p50/p95/p99/max ms` history columns.

**Why this method.** The alternative was a receipt log keyed by `jti`, joined
against the harness's send times. That needs a new server endpoint or log
format, and a per-event label would make the metric unbounded. The histogram
needs one metric. It is scraped exactly like `events_in_total`, it is labelled
only by `tfr` (three series, no `stream_id`), and it is useful outside the
bench: for ordinary events it shows how old events are when they arrive.

**toe precision.** `toe` is a JWT NumericDate, which goSet used to truncate to
whole seconds. That would have made every sample a multiple of one second.
goSet now keeps the fractional part of `toe` through JSON and BSON, so samples
resolve to the microsecond. A `toe` without a fraction is encoded exactly as
before, so only SETs that carry one, which in practice means bench SETs,
change on the wire.

**What the number covers.** The clock starts at the POST to goSignals1, before
the 202, so the ingest latency is part of each delivery sample. It ends when
goSignals2 counts the SET: for push and SSTP, on receipt; for poll, when the
poll response is processed. Under local-WAL durability, inbound events are
counted when the WAL drains, so WAL time is included too.

**Clock assumption.** `toe` comes from the harness's clock and receipt time from
goSignals2's. On the single-host dev and benchmark stacks they are the same
clock. Across hosts, any clock skew adds directly to every sample, and
negative ages are clamped to 0.

**max.** A histogram cannot report an exact maximum. `max` is the upper bound of
the highest bucket that holds a sample, so the true maximum is at or below it.
If a sample exceeded the last finite bucket (30 s), `max` is 30000 ms and is
then a lower bound.

## Running

```bash
make dev-up                                   # goSignals1 + goSignals2 healthy
make dev-bench                                # 5000 events, 16 workers
make dev-bench BENCH_E2E_EVENTS=20000 BENCH_E2E_CONCURRENCY=32
make dev-bench BENCH_E2E_ARGS="--pprof"       # + CPU profiles of both nodes
make dev-bench BENCH_E2E_ARGS="--history docs/perf/e2e-history.md --label 'after fix X'"
go run ./cmd/goSignalsBench -h                # every flag
```

Useful flags:

| Flag | Purpose |
|---|---|
| `--events`, `--concurrency` | load size and parallel ingest connections |
| `--mix alternate\|all\|push\|poll\|sstp` | which audience(s) each SET carries |
| `--sstp-role initiator\|responder` | goSignals1's SSTP role, i.e. which node opens the HTTP connection |
| `--issuer`, `--push-aud`, `--poll-aud`, `--sstp-aud` | issuer and per-leg audiences (URLs) |
| `--pprof`, `--pprof-seconds` | fetch `debug/pprof/profile` from goSignals1 (`:6060`) and goSignals2 (`:6061`) during the run; files land in `bin/bench/pprof/` |
| `--pprof-block` | with `--pprof`, also fetch a `debug/pprof/block` delta profile over the same window (needs `I2SIG_PPROF_BLOCK_RATE` on the servers) |
| `--mongo-uri` | host-side Mongo URI (default `$BENCH_MONGO_URI`); snapshot the primary's journal counters before and after the run (see [Concurrency sweep](#concurrency-sweep)) |
| `--workers` | free-text record of the server-side worker setting, stored in the result; it does not change the servers |
| `--signing-alg RS256\|ES256\|ML-DSA-65` | `signing_alg` on the push and poll transmitter streams (default: the server default). Anything but RS256 needs an issuer key of that algorithm; the harness mints one through `POST /key/{issuer}?alg=` when it is missing |
| `--durability majority\|local` | `durability` on the ingress stream (default: the server default). `local` needs `I2SIG_STORE_WAL=local` on goSignals1; the harness then scrapes the ingress counters only once `goSignals_wal_depth` has drained to zero |
| `--history <file>` | append a summary row to a Markdown table (see below) |
| `--label` | free text stored with the result (what changed) |
| `--note` | why the run was made (the change under test); written to the history `Note` column |
| `--keep` | leave the streams in place for inspection with the CLI / admin UI |
| `--drain-timeout` | give up waiting for goSignals2 (default 5m) |
| `--gs1`, `--gs2`, `--ca`, `--bootstrap-token` | point at a different stack |
| `--gs1b <url>` | a second member of goSignals1's cluster (e.g. `https://localhost:8887`); ingest workers alternate between `--gs1` and it (see [Two-node cluster ingest](#two-node-cluster-ingest)) |
| `--gs1b-internal <url>` | with `--gs1b`, the base URL goSignals2 uses to reach the `--gs1b` node; the poll receiver polls it and, with `--sstp-role responder`, goSignals2 dials it for SSTP, instead of goSignals1 (#366) |
| `--poll-targets one\|both` | `one` (default): one goSignals2 poll receiver, at goSignals1 or `--gs1b-internal`. `both` (needs `--gs1b-internal`): one receiver per node, so polls reach the poll-transmitter lease owner and the non-owner, which serves through a peer claim; the POLL leg counts both receivers (#366, for #367) |
| `--poll-pin-owner` | with `--gs1b` (not `--gs1b-internal`): before any receiver exists the harness polls `--gs1b` once, so it takes the poll-transmitter lease and keeps it, then goSignals2 polls goSignals1 for the whole leg. Every poll is then a non-owner poll: the worst case for the peer hop (#367) |
| `--gs1b-sync-timeout` | with `--gs1b`, how long to wait after creating the streams for the second node to register the run's outbound streams before ingest starts (default 90s; peers sync every 40 s) |

Every run writes `bin/bench/bench-<timestamp>.json` with the full result
(topology ids, latency percentiles, per-leg counts, profile paths).

### Two-node cluster ingest

With `--gs1b` the harness spreads ingest over two members of goSignals1's
cluster: all streams are still created through `--gs1` (the cluster shares
one Mongo store, so they exist on both nodes), then even-numbered workers post
to `--gs1` and odd-numbered workers to `--gs1b`, each over its own connection
pool. A node only learns about streams created on a peer through its 40 s
background sync, and a SET that reaches `--gs1b` before it has registered the
run's outbound streams matches nothing and is never delivered; so after
creating the streams the harness polls `--gs1b`'s `/metrics` until a
`goSignals_router_events_in_total` series exists for each outbound stream
(push, poll and SSTP transmitters), failing the run after
`--gs1b-sync-timeout`. The wait is reported as `gs1b stream sync: Ns`
(`gs1b_sync_seconds` in the JSON). Before the ingress counter is read, `goSignals_wal_depth` must have
drained to zero on **both** nodes, and `ingress_counted` is the sum of each
node's `goSignals_router_events_in_total{stream_id=ingress}`. The result adds
an `ingest split: gs1=N gs1b=M` line (`ingest_split` in the JSON, from the
workers' 202 counts) and a `dao gs1b:` block; the history row format is
unchanged, so use `--label` to mark cluster runs. `--pprof-gs1b` profiles the
second node when set.

The peer never forgets a stream either: a node keeps delivering to streams a
previous run deleted, which inflates its fan-out work and leaves orphan
pending markers. Until that is fixed, restart the second node before each
two-node run (`docker compose -f docker-compose-benchmark.yml --profile
cluster restart goSignals1b`). The two-node results and the coordination
defects they exposed are in [cluster-perf.md](cluster-perf.md).

Teardown of the poll receiver waits for its in-flight long poll to expire, so
the last log line arrives about ten seconds after the summary.

### Benchmark stack

`docker-compose-dev.yml` is built for debugging, not measuring: every node runs
under Delve from a debug build with a bind-mounted source tree, logs at INFO
(one line per SET), and shares the host with Keycloak, Postgres, two SCIM
servers, goSsfServer and the observability stack. On the same laptop the same
run measured 2.3–2.5× slower there than on the benchmark stack.

`docker-compose-benchmark.yml` is the same two goSignals nodes and three-member
replica set on the production distroless image, LOG_LEVEL=WARN, pprof on, no
other services, and a 1 GiB WiredTiger cache per member. goSignals1 runs the
node-local WAL (`I2SIG_STORE_WAL=local`, ring-fed); goSignals2 stays at
`majority`. It binds the same host ports as the dev stack, so stop that first.

```bash
make dev-down
make bench-stack-up            # make build-docker + compose up --wait
make dev-bench BENCH_E2E_EVENTS=20000 BENCH_E2E_CONCURRENCY=128 \
     BENCH_E2E_ARGS="--durability=local --history docs/perf/e2e-history.md --label bench-stack"
make bench-stack-logs
make bench-stack-down          # add -v by hand to drop the volumes
```

Runtime knobs pass straight through from the environment: `BENCH_LOG_LEVEL`,
`BENCH_SUBJECT_FILTERING`, `GOMAXPROCS`, `GOGC`, `GOMEMLIMIT`,
`I2SIG_PUSH_CONCURRENCY`, `I2SIG_DELIVERY_INFLIGHT_MAX`,
`I2SIG_PPROF_MUTEX_FRACTION`, `I2SIG_PPROF_BLOCK_RATE`, `BENCH_GS1_WAL`,
`BENCH_GS2_WAL` and `BENCH_IMAGE`. Rows taken on this stack are labelled
`bench-stack-*` in the history; do not compare them with dev-stack rows.

### Signing algorithms

Every ingested SET is re-signed once per outbound leg (push, poll and SSTP), so
the transmitter's `signing_alg` is a first-order term in goSignals1's CPU:
RSA-2048 signing costs about 1 ms per SET on an arm64 Docker VM, ECDSA P-256
about 50 µs. `make dev-bench-algs` runs the same load once per algorithm in
`BENCH_ALGS` (default `RS256 ES256`) and appends one history row each, labelled
`algs-<alg>-c<clients>`, then prints those rows:

```bash
make dev-bench-algs BENCH_E2E_EVENTS=20000 BENCH_E2E_CONCURRENCY=128 \
     BENCH_E2E_ARGS="--durability=local"
make dev-bench-algs BENCH_ALGS="RS256 ES256 ML-DSA-65"
```

The JSON result and the summary line carry `signing_alg` and `durability`, so
a row's algorithm is recoverable without the label.

### Aborted runs

Leftover streams are not harmless: they match the same audiences, so every
SET reaches goSignals2 twice and the second arrival is dropped by JTI dedup
and never counted on the stream the new run is watching. The symptom is a run
that stalls short of 100% on every leg. The harness therefore records its
streams in `bin/bench/streams-in-flight.json` while a run is live, tears them
down on Ctrl-C, and on the next start deletes whatever a killed run left
behind before building a fresh topology. `make dev-clean` is the fallback if
the file is gone.

## Profiling with it

```bash
make dev-bench BENCH_E2E_EVENTS=20000 BENCH_E2E_ARGS="--pprof --pprof-seconds 60"
go tool pprof -http=:8081 bin/bench/pprof/cpu-goSignals1-<stamp>.pb.gz
```

`--pprof` needs the nodes to expose a Go `pprof` listener (`I2SIG_PPROF_ADDR`,
host ports 6060 / 6061 in the dev stack once PR #282 lands); without it the
profile fetch is skipped with a warning and the benchmark still runs.

Binaries in the dev stack run under Delve from source, so symbols resolve
without any extra setup. For heap, goroutine or mutex profiles use
`make dev-pprof PPROF_KIND=heap` while a long run is in flight (see
[pprof.md](pprof.md)).

## Concurrency sweep

The sweep answers one question: as ingest parallelism rises, what bounds
throughput — Mongo round trips, the journal, or the server's own CPU and
locks? It runs **5000 events** (`alternate` mix) at **1, 4, 16 and 64
clients** for each worker setting, on the Mongo provider and again on the
memory provider as a no-database control. The latest results are in
[throughput-baseline-alpha20.md](throughput-baseline-alpha20.md).

### The two axes

- **Clients** — `--concurrency`, the number of parallel ingest connections.
  The server has no ingest worker pool: each ingest request runs on its own
  handler goroutine, so client count *is* ingest parallelism.
- **Workers** — `I2SIG_PUSH_CONCURRENCY` on goSignals1, the push-delivery
  pool size ([ADR 0037](../adr/0037-push-concurrency-derived-from-processors.md):
  `GOMAXPROCS` clamped to 8..32 when unset, 14 on a fourteen-processor host).
  It is read once at start-up, so it is set when the stack is started, not per
  run. The sweep uses `default`, `8` and `32`. `--workers` only records the
  setting in each JSON result.

### Running it

```bash
# Mongo provider, one worker setting at a time
I2SIG_PUSH_CONCURRENCY=8 docker compose -f docker-compose-dev.yml \
    up -d --force-recreate goSignals1 goSignals2
make dev-bench-sweep BENCH_SWEEP_WORKERS=8

# back to the derived default
docker compose -f docker-compose-dev.yml up -d --force-recreate goSignals1 goSignals2
make dev-bench-sweep                                  # BENCH_SWEEP_WORKERS=default

# memory provider (control): the overlay swaps MONGO_URL for memorydb:
docker compose -f docker-compose-dev.yml -f docker-compose-dev-memory.yml \
    up -d --force-recreate goSignals1 goSignals2
make dev-bench-sweep BENCH_MONGO_URI= \
    BENCH_E2E_ARGS="--issuer=https://bench-mem.example.com --issuer-key=bin/bench/bench-mem.example.com.pem"
```

`dev-bench-sweep` runs `dev-bench` once per entry in
`BENCH_SWEEP_CLIENTS` (default `1 4 16 64`), labels each result
`sweep-c<clients>-w<workers>` and passes `BENCH_E2E_ARGS` through. Every run
writes its own `bin/bench/bench-<timestamp>.json`.

**Use a separate issuer for memory-provider runs.** A memory store starts
empty on every restart, so goSignals1 no longer holds the issuer's key and the
harness mints a new key pair and writes it to the `--issuer-key` file (default
`bin/bench/<issuer host>.pem`). The Mongo stack still holds the old public
key, so after that every SET the same issuer sends to the Mongo stack fails
with HTTP 400. The harness now keeps the previous PEM as
`<file>.<UTC stamp>.bak` before writing a new one, so the old key can be put
back, but a distinct `--issuer` (and so a distinct key file) for memory runs,
as above, avoids the problem.

### Journal syncs per SET

With `--mongo-uri` (or `BENCH_MONGO_URI`) set, the harness reads
`db.serverStatus().wiredTiger.log` on the replica-set primary before and after
the run and records the difference in the result's `journal` block: `log sync
operations`, `log write operations`, `log flush operations`, bytes written and
sync time, plus syncs and writes per ingested SET.

- The URI is dialled **from the host**. The dev replica set advertises
  `mongo1`..`mongo3` on ports 30001..30003, so `/etc/hosts` must map those
  names to `127.0.0.1`; the Makefile default is
  `mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?replicaSet=dbrs&authSource=admin`.
- The counters are **server-wide**. goSignals1 and goSignals2 share the replica
  set, so a run's delta covers ingest on goSignals1 and delivery bookkeeping on
  goSignals2 together, plus any background writes (leases, heartbeats).
- An empty URI skips the probe; on the memory provider set `BENCH_MONGO_URI=`.

### DAO latency

Each result carries `dao_gs1` / `dao_gs2` (see
[Ingest breakdown](#ingest-breakdown-dao-metrics)) and `dominant_dao_op`, the
op with the most wall time on goSignals1 (`WatchPending` excluded). The lowest
histogram bucket is 0.5 ms and quantiles interpolate from zero inside it, so
on the memory provider a p50 of about **0.25 ms** means "under 0.5 ms", not a
measured 0.25 ms.

### Profiles for the 16- and 64-client runs

Start the stack with block sampling on, then profile only the two runs that
matter:

```bash
I2SIG_PPROF_BLOCK_RATE=1 docker compose -f docker-compose-dev.yml \
    up -d --force-recreate goSignals1 goSignals2
make dev-bench-sweep BENCH_SWEEP_CLIENTS="16 64" \
    BENCH_E2E_ARGS="--pprof --pprof-block --pprof-seconds=10"
go tool pprof -top bin/bench/pprof/block-goSignals1-<stamp>.pb.gz
```

`--pprof-block` fetches `debug/pprof/block?seconds=N` alongside the CPU
profile, so both cover the same window; files are
`bin/bench/pprof/{cpu,block}-goSignals{1,2}-<stamp>.pb.gz`. Block sampling
costs throughput at 64 clients, so take the sweep table from unprofiled runs.
Recreate the two services without `I2SIG_PPROF_BLOCK_RATE` afterwards (see
[pprof.md](pprof.md#mutex-and-block-profiling-opt-in)).

## Recording results over time

[e2e-history.md](e2e-history.md) is the running log. Append to it with
`--history docs/perf/e2e-history.md` and a `--label` naming the change, then
commit the row with the change it measures. Rows are only comparable when
events, concurrency, mix, SSTP role and machine class match, so keep the
default sizes (`5000` / `16` / `alternate`) for the rows you intend to compare and use larger
runs for profiling.

The dev stack is not a quiet environment: Delve, JSON logging at `DEBUG`, a
three-node Mongo replica set and Docker Desktop networking all sit in the path.
Treat differences under about 10% as noise and re-run before drawing a
conclusion, the same discipline the micro-benchmark baseline applies.

## Findings and measured gains

Numbers below come from the history table (5000 events, concurrency 16,
`alternate` mix, Apple M-series laptop, Docker Desktop dev stack). They are
the record for release notes; the corresponding rows carry the same labels.

### Push delivery ran five POSTs in flight when the link wanted fourteen (fixed)

`I2SIG_PUSH_CONCURRENCY` defaulted to a fixed 5 (ADR 0035). A `--mix push`
sweep over 1/5/8/16/24/32/64, run twice — once on the full fourteen-processor
host and once with the transmitter held to `GOMAXPROCS=4` — put the knee
between 5 and 16 and a noise-flat plateau from 16 up, and moved by under 1%
when ten processors were taken away: push is latency-bound, so the optimum
belongs to the link, not to the transmitter's CPU. The default is now
`GOMAXPROCS` clamped to 8..32 (**14** on this host), which takes push from
**414-419 to 536-589 ev/s** and drain-after-ingest from 6.8s to 2.3s, paid for
with about 22% of ingest — delivery and ingest compete for the same processors.
Both sweeps and the trade are in [ADR 0037](../adr/0037-push-concurrency-derived-from-processors.md);
the rows are labelled `spec102-285-*`.

To reproduce a sweep point, the dev stack passes both knobs through:

```bash
I2SIG_PUSH_CONCURRENCY=32 GOMAXPROCS=4 docker compose -f docker-compose-dev.yml up -d goSignals1
make dev-bench BENCH_E2E_ARGS="--mix push"
```

Unset both and bring `goSignals1` back up to return to the derived default.

### Push delivery reused no HTTP connections (fixed)

The baseline run drained the push leg at **38 events/s** while the poll leg,
on the same machine and the same Mongo, drained at 106 events/s. The CPU
profile of goSignals2 (the push receiver) showed **70% of its samples inside
TLS server handshakes**, almost all of it RSA certificate signing, and
goSignals1 spent a further 17% in the matching client handshakes.

The cause was in `goSetPush.PushSET`: when the caller supplied no
`HTTPClient` it built a new `http.Client` and, via `CheckCaInstalled`, a new
`http.Transport` for every call. Each transport owns its own connection pool,
so every pushed event dialled a fresh TCP + TLS connection, and the previous
connection sat idle until the receiver timed it out. The delivery adapter in
`internal/eventRouter/delivery` never passes a client, so every push stream
paid this on every event.

`PushSET` now uses one process-wide client per TLS posture (verified / skip
verify), cloned from `http.DefaultTransport` with a larger per-host idle pool,
so consecutive pushes ride pooled keep-alive connections.

| Metric (same run shape) | Before (`baseline`) | After (`shared-push-transport`) |
|---|---|---|
| Push events/s | 38 | 105 |
| Push drain after ingest | 61.7 s | 19.7 s |
| Total end-to-end | 65.4 s | 23.8 s |
| goSignals2 CPU busy over the 30 s profile | 58% (17.3 s) | 23% (6.8 s) |
| goSignals2 CPU in TLS handshakes | 70% | under 1% |

Ingest and poll were unchanged within noise, as expected.

### SSTP initiator went silent when it had nothing to send (fixed)

The first SSTP runs delivered the opening batch and then stalled for the
responder's full 30 s long-poll timeout before the rest arrived. Two dialer
behaviours combined to cause it:

- **No long poll when idle.** `SstpDialer.runCycle` skipped the POST
  entirely when the outbound buffer was empty and no acks were owed, so an
  idle initiator never parked a long poll on the responder and could not
  learn about new inbound SETs until its next scheduled cycle. Per the
  protocol the initiator always opens the cycle; an empty request with
  `returnEvents=true` *is* the long poll. The guard is gone.
- **Second push sent one batch per wake.** With the primary long poll held,
  a buffer wake spawns one push-while-poll-held POST. Wakes that landed
  while it was in flight were coalesced by the single-slot guard and then
  lost, so everything queued during that POST waited until the primary poll
  returned. `pushWhilePollHeld` now loops, claiming batch after batch, until
  the outbound is empty or a batch is only partially acked.

| Metric (300 events, concurrency 8, `--sstp-role initiator`) | Before | After |
|---|---|---|
| SSTP events/s | 3 | 110 |
| SSTP end-to-end | 30.9 s | 0.91 s |

### SSTP by role (measured)

5000 events, concurrency 16, `alternate` mix (rows `sstp-leg-initiator` and
`sstp-leg-responder`):

| goSignals1 role | SSTP events/s | SSTP drain after ingest | Push / poll events/s |
|---|---|---|---|
| initiator (goSignals1 dials) | 106 | 11.1 s | 94 / 103 |
| responder (goSignals2 dials) | 55 | 26.3 s | 94 / 100 |

As initiator, SSTP keeps pace with the poll leg: the primary cycle and the
push-while-poll-held cycle run concurrently, so acking one batch overlaps
delivering the next. As responder, goSignals1 serves each batch inside a
single long-poll handler: it acks the previous batch (one Mongo round trip
per event) and then fetches and signs the next before answering, and the
initiator only sends the next request once that answer lands. The same
per-event Mongo cost that bounds push and poll therefore counts twice per
batch on the responder path, which is the next thing to batch.

### Hot spots after the handshake fix (since addressed by spec-102)

With the handshake gone, the goSignals1 profile was dominated by work that
was serialized per event inside the push loop and the poll handler. Every item
below was taken up by the spec-102 runtime-performance work (PR #293); the
status line on each gives the slice and ADR, and the measured before/after
numbers are in `e2e-history.md` and the PR.

- **RSA re-signing in Publish mode: 41% of goSignals1 CPU.** Both transmitters
  in the harness use `PB` route mode, so every event is re-signed with the
  stream's issuer key on the way out (`SecurityEventToken.JWS`), once for the
  push leg and once per poll response for the poll leg. RSA-2048 signing costs
  roughly 1 ms per event on this machine. Forward mode (`FW`) skips this
  entirely; where re-signing is required, a smaller key type (ES256) or
  signing events in parallel while the push loop stays sequential would help.
  *Status:* ES256 is a selectable per-stream `signing_alg` (#284, ADR 0041);
  RS256 stays the default, so a stream must opt in.
- **Per-event Mongo round trips.** The push loop and poll handler each fetch
  the event record by JTI, look the stream state up by id, and ack the event
  with separate Mongo calls, each a network round trip. At about 10 ms per
  event per leg these bound both transports to ~100 events/s per stream.
  Batching the poll-side fetch and ack, and caching stream state per lease,
  are the obvious next steps.
  *Status:* acks are removed in one query per exchange with `{sid, jti}`
  indexes (#288), ingest writes run concurrently (#286, ADR 0038) and the
  per-event stream, revocation and lease reads are cached (#287, ADR 0039).
- **Per-request bearer validation: about 5% on goSignals1 and 13% on
  goSignals2.** `ValidateAuthorizationAny` parses and RSA-verifies the bearer
  JWT and then checks revocation in Mongo on every request. A short-lived
  cache keyed by token string would remove both the verify and the lookup for
  hot streams.
  *Status:* partly — the revocation lookup is cached for 2s (#287, ADR 0039);
  the per-request JWT verify is still paid.
- **Push loop is strictly sequential per stream.** Sign, deliver, ack, one
  event at a time. Pipelining a small window of in-flight pushes per stream
  (bounded so ordering guarantees hold where they matter) is the largest
  remaining structural gain for the push transport.
  *Status:* push delivers concurrently (ADR 0035) with a pool sized from
  available processors (#285, ADR 0037).

### Poll and SSTP connection handling (SSTP fixed)

- **Poll receiver: already reuses connections.** `runPollLoop` resolves its
  `http.Client` once per stream loop and keeps it across poll cycles,
  refreshing only after a 401/403. The profile after the push fix shows no
  measurable handshake cost on goSignals1, the poll transmitter. The only
  per-call client construction left is the library fallback in
  `goSetPoll.PollRaw` when a caller passes no `HTTPClient`, which the server
  never does.
- **SSTP dialer: builds a client per cycle.** `SstpDialer.deliver` calls the
  credential-chain resolver on every exchange, and for the static-token,
  per-stream-TLS and default paths that returns a fresh `http.Client` with its
  own `http.Transport`, so every SSTP cycle handshakes. The SPIFFE path is
  worse: it opens a new workload-API `X509Source` per cycle and closes it
  afterwards. Only the OAuth client-credentials path is cached (by token
  config, in the `oauthClient` manager). Because each cycle carries a batch,
  the per-event cost is far smaller than the push case was, but an idle pair
  still pays a full handshake every `BaseDelay`. The fix is to resolve the
  client once per pair loop, the way the poll loop does, or to cache the
  static-token / TLS-only clients per server alias in `oauthClient`. With
  the SSTP leg in place this can now be measured; at 100-event batches the
  handshake is amortised well enough that it does not show in the numbers
  above, so it stays a latency and idle-cost concern rather than a
  throughput one.
  *Status:* fixed. The static-token, per-stream-TLS and default paths are
  fixed by #289 — they share a pooled transport, and `clientHandshake` is
  absent from the after-profiles. The SPIFFE path is fixed by #326:
  `oauthClient.GetSpiffeClient` pools one client and transport per peer
  server (keyed on the server and its `SpiffeConfig`), all sharing one
  process-wide `X509Source` that rotates SVIDs itself. Server update/delete
  evicts the entry and shutdown closes the source. Not yet re-profiled on the
  SPIRE compose stack.
