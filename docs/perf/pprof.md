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
| `block`     | Where goroutines block on sync primitives / channels                     | Requires `runtime.SetBlockProfileRate`; off by default. |
| `mutex`     | Contended mutex holders                                                  | Requires `runtime.SetMutexProfileFraction`; off by default. |
| `trace`     | Full runtime scheduler trace over `?seconds=N`                           | Open with `go tool trace`. |

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
