# Profiling goSignalsServer with pprof

The server exposes Go's standard [`net/http/pprof`](https://pkg.go.dev/net/http/pprof)
endpoints on a **separate, plain-HTTP, unauthenticated** listener whenever
`I2SIG_PPROF_ADDR` is set (see [`configuration_properties.md`](../configuration_properties.md#dev-only-flags)).
It is deliberately kept off the authenticated API router so profiling never
touches the TLS / OAuth surface, and so it can be bound to a loopback or
docker-internal address. Leave the variable unset in production.

## Dev stack (`docker-compose-dev.yml`)

Every Go node in the dev stack is started with `I2SIG_PPROF_ADDR=:6060` and the
port is published to the host:

| Service       | Host port | pprof index                              |
|---------------|-----------|------------------------------------------|
| `goSignals1`  | 6060      | http://localhost:6060/debug/pprof/       |
| `goSignals2`  | 6061      | http://localhost:6061/debug/pprof/       |
| `goSsfServer` | 6062      | http://localhost:6062/debug/pprof/       |

```bash
make dev-up                                       # bring the stack up
make dev-pprof                                    # 30 s CPU profile of goSignals1 (interactive)
make dev-pprof PPROF_KIND=heap                    # heap (in-use) allocations
make dev-pprof PPROF_KIND=goroutine PPROF_PORT=6061   # goroutine dump of goSignals2
make dev-pprof PPROF_KIND=trace PPROF_SECONDS=5   # runtime trace, opens `go tool trace`
make dev-pprof PPROF_UI=1                         # web UI (flame graph) on http://localhost:8081
```

Each fetch is saved under `bin/pprof/<kind>-<port>-<timestamp>.pb.gz` so it can
be re-opened or diffed later:

```bash
go tool pprof -http=:8081 bin/pprof/heap-6060-20260907T101500.pb.gz
go tool pprof -base bin/pprof/heap-6060-before.pb.gz bin/pprof/heap-6060-after.pb.gz
```

Or call the endpoints directly:

```bash
go tool pprof -http=:8081 http://localhost:6060/debug/pprof/profile?seconds=30
go tool pprof http://localhost:6060/debug/pprof/heap
curl -s http://localhost:6060/debug/pprof/goroutine?debug=2 | less   # symbolised goroutine stacks
```

## Useful profiles

| Kind        | What it shows                                                            | Notes |
|-------------|--------------------------------------------------------------------------|-------|
| `profile`   | CPU samples over `?seconds=N`                                            | Generate load (push events, poll clients) during the window. |
| `heap`      | In-use heap objects at the time of the call                              | `-sample_index=alloc_space` shows cumulative allocation instead. |
| `allocs`    | All allocations since process start                                      | Best for finding allocation-heavy hot paths in the event router. |
| `goroutine` | Every live goroutine                                                     | `?debug=2` gives readable stacks; compare against `pkg/goroutineleak`. |
| `block`     | Where goroutines block on sync primitives / channels                     | Off by default; enable with `I2SIG_PPROF_BLOCK_RATE` (below). |
| `mutex`     | Contended mutex holders                                                  | Off by default; enable with `I2SIG_PPROF_MUTEX_FRACTION` (below). |
| `trace`     | Full runtime scheduler trace over `?seconds=N`                           | Open with `go tool trace`. |

## Mutex and block profiling (opt-in)

The `mutex` and `block` endpoints are always *served*, but the Go runtime
collects nothing for them unless sampling is switched on, so an un-configured
server answers with an empty profile:

```bash
$ curl -s "http://localhost:6060/debug/pprof/mutex?debug=1" | head -3
--- mutex:
cycles/second=999999999
sampling period=0        # 0 = mutex profiling is off
```

Two environment variables turn them on. Both are read **only when
`I2SIG_PPROF_ADDR` is already set**, and both default to off, so a server that
was not started for profiling pays nothing:

| Variable                     | Runtime call                       | Meaning of the value |
|------------------------------|------------------------------------|----------------------|
| `I2SIG_PPROF_MUTEX_FRACTION` | `runtime.SetMutexProfileFraction`  | `1` = record every contention event, `N` = roughly one in `N`. |
| `I2SIG_PPROF_BLOCK_RATE`     | `runtime.SetBlockProfileRate`      | Nanoseconds blocked per sample: `1` = every blocking event, `10000` ≈ one sample per 10 µs blocked. |

A value that is unset, `0`, negative, or not an integer leaves that profile off
(the server logs a warning for the last two cases). When either is enabled the
server logs a WARN line at startup naming the variable and the value.

### Overhead

Both knobs are opt-in because they instrument hot paths:

- **Mutex profiling** records the holder's stack whenever a waiter had to sleep.
  Cost scales with contention — which is exactly the workload under
  investigation.
- **Block profiling** is the broader of the two: it timestamps *every* blocking
  operation (channel send/receive, select, mutex wait, `WaitGroup.Wait`),
  including the ones that were never a problem.

Measured on the dev stack with `cmd/goSignalsBench -events 5000 -concurrency 16`
(2026-09-08, all three Go nodes recreated between runs):

| Run                                        | Ingest   | e2e (all three legs) |
|--------------------------------------------|----------|----------------------|
| knobs unset                                | 626 ev/s | 8.50 s               |
| `I2SIG_PPROF_MUTEX_FRACTION=1 I2SIG_PPROF_BLOCK_RATE=1` | 637 ev/s | 8.36 s |

At this load the difference is inside run-to-run noise — the dev stack is not
contention-bound enough for the sampling to show up. That is *not* a licence to
leave the knobs on: the cost rises with contention and with blocking-event rate,
which is precisely where a profiling run is aimed. Treat them as diagnostic
tools — turn them on, capture the profile, turn them off — and record whether
they were set alongside any number appended to
[`e2e-history.md`](e2e-history.md).

### Dev stack

`docker-compose-dev.yml` passes both variables through from the shell, empty (off)
unless exported:

```bash
I2SIG_PPROF_MUTEX_FRACTION=1 I2SIG_PPROF_BLOCK_RATE=1 make dev-up
# ... generate load ...
curl -s "http://localhost:6060/debug/pprof/mutex?debug=1" | head -3   # sampling period=1
make dev-pprof PPROF_KIND=mutex
make dev-pprof PPROF_KIND=block
make dev-down && make dev-up                                          # back to no sampling
```

### Outside Docker

```bash
I2SIG_PPROF_ADDR=127.0.0.1:6060 \
  I2SIG_PPROF_MUTEX_FRACTION=1 I2SIG_PPROF_BLOCK_RATE=1 \
  bin/goSignalsServer
go tool pprof -http=:8081 http://127.0.0.1:6060/debug/pprof/mutex
```

## Delve and pprof together

The dev image runs the server under Delve (`dlv debug ... --continue`), so the
process being profiled is the same one the debugger is attached to. Profiles are
taken by the Go runtime inside the process and are unaffected by Delve unless a
breakpoint is hit, which will show up as a stall in a CPU profile or trace.

## Running outside Docker

```bash
I2SIG_PPROF_ADDR=127.0.0.1:6060 bin/goSignalsServer
go tool pprof -http=:8081 http://127.0.0.1:6060/debug/pprof/profile?seconds=15
```
