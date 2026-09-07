# End-to-end benchmark harness (`goSignalsBench`)

`cmd/goSignalsBench` drives a large number of Security Event Tokens through the
`docker-compose-dev.yml` stack so the whole receive → route → deliver path can be
measured and profiled, and so throughput can be tracked over time. It complements
the micro-benchmark set in [go127-baseline.md](go127-baseline.md), which measures
isolated hot paths in-process; this harness measures the servers as deployed,
Mongo and TLS included.

## Topology

Every run builds five streams and (unless `--keep`) deletes them afterwards:

```
harness ──RFC 8935 push──▶ goSignals1  ingress   (push-receive, route_mode FW,
                                                  aud = [push-aud, poll-aud])
                              │
                              ├─ aud=push-aud ──RFC 8935 push──▶ goSignals2  push-receive (IM)
                              │   (push transmitter, PB)
                              │
                              └─ aud=poll-aud ◀──RFC 8936 poll── goSignals2  poll-receive (IM)
                                  (poll transmitter, PB)
```

* The ingress stream on goSignals1 is a push receiver in **FORWARD** mode. The
  CLI default (IMPORT) stores events without routing, so it would measure nothing
  downstream.
* The two transmitter streams have **different audiences**. Each generated SET
  carries one audience (`--mix alternate`, the default) or both (`--mix both`),
  so the EventRouter's audience match decides per event which leg carries it.
* goSignals2's receivers trust `https://goSignals1:8888/jwks/<issuer>` because
  the transmitters re-sign (PUBLISH mode) with goSignals1's copy of the issuer
  key.
* The harness signs with an RSA key that goSignals1 mints on the first run
  (`POST /key/<issuer>` with the bootstrap secret). The PEM is saved to
  `bin/bench/<issuer>.pem` and reused on later runs. After `make dev-clean` the
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

Delivery is always counted on goSignals2. goSignals1's `events_out_total` is only
incremented on a push acknowledgement, never on a poll, so it cannot be used for
the poll leg. `/metrics` is unauthenticated on the dev stack, so no extra
credentials are needed.

Signing happens **before** the clock starts: all SETs are pre-built in parallel so
client-side RSA work is not attributed to the server.

Timings reported per leg:

* **end-to-end** — from the first push until goSignals2 has counted every
  expected event;
* **drain-after-ingest** — how long goSignals2 kept receiving after the harness
  finished pushing (0 means the leg kept up with ingest).

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
| `--mix alternate\|both\|push\|poll` | which audience(s) each SET carries |
| `--pprof`, `--pprof-seconds` | fetch `debug/pprof/profile` from goSignals1 (`:6060`) and goSignals2 (`:6061`) during the run; files land in `bin/bench/pprof/` |
| `--history <file>` | append a summary row to a Markdown table (see below) |
| `--label` | free text stored with the result (what changed) |
| `--keep` | leave the streams in place for inspection with the CLI / admin UI |
| `--drain-timeout` | give up waiting for goSignals2 (default 5m) |
| `--gs1`, `--gs2`, `--ca`, `--bootstrap-token` | point at a different stack |

Every run writes `bin/bench/bench-<timestamp>.json` with the full result
(topology ids, latency percentiles, per-leg counts, profile paths).

Teardown of the poll receiver waits for its in-flight long poll to expire, so
the last log line arrives about ten seconds after the summary.

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

## Recording results over time

[e2e-history.md](e2e-history.md) is the running log. Append to it with
`--history docs/perf/e2e-history.md` and a `--label` naming the change, then
commit the row with the change it measures. Rows are only comparable when
events, concurrency, mix and machine class match, so keep the default sizes
(`5000` / `16` / `alternate`) for the rows you intend to compare and use larger
runs for profiling.

The dev stack is not a quiet environment: Delve, JSON logging at `DEBUG`, a
three-node Mongo replica set and Docker Desktop networking all sit in the path.
Treat differences under about 10% as noise and re-run before drawing a
conclusion, the same discipline the micro-benchmark baseline applies.

## Findings and measured gains

Numbers below come from the history table (5000 events, concurrency 16,
`alternate` mix, Apple M-series laptop, Docker Desktop dev stack). They are
the record for release notes; the corresponding rows carry the same labels.

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

### Remaining hot spots (not yet addressed)

With the handshake gone, the goSignals1 profile is dominated by work that is
serialized per event inside the push loop and the poll handler:

- **RSA re-signing in Publish mode: 41% of goSignals1 CPU.** Both transmitters
  in the harness use `PB` route mode, so every event is re-signed with the
  stream's issuer key on the way out (`SecurityEventToken.JWS`), once for the
  push leg and once per poll response for the poll leg. RSA-2048 signing costs
  roughly 1 ms per event on this machine. Forward mode (`FW`) skips this
  entirely; where re-signing is required, a smaller key type (ES256) or
  signing events in parallel while the push loop stays sequential would help.
- **Per-event Mongo round trips.** The push loop and poll handler each fetch
  the event record by JTI, look the stream state up by id, and ack the event
  with separate Mongo calls, each a network round trip. At about 10 ms per
  event per leg these bound both transports to ~100 events/s per stream.
  Batching the poll-side fetch and ack, and caching stream state per lease,
  are the obvious next steps.
- **Per-request bearer validation: about 5% on goSignals1 and 13% on
  goSignals2.** `ValidateAuthorizationAny` parses and RSA-verifies the bearer
  JWT and then checks revocation in Mongo on every request. A short-lived
  cache keyed by token string would remove both the verify and the lookup for
  hot streams.
- **Push loop is strictly sequential per stream.** Sign, deliver, ack, one
  event at a time. Pipelining a small window of in-flight pushes per stream
  (bounded so ordering guarantees hold where they matter) is the largest
  remaining structural gain for the push transport.

### Poll and SSTP connection handling (reviewed, not changed)

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
  static-token / TLS-only clients per server alias in `oauthClient`. The
  harness has no SSTP leg yet, so this is not measured here.
