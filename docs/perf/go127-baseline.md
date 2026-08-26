# Go 1.27 performance baseline

Status: established by [#270](https://github.com/i2-open/i2goSignals/issues/270) (spec
[planning#101](https://github.com/independentid/i2gosignals-planning/issues/101), Slice 0).

This file is the project's performance floor. It exists because the first `go test ./...` run
after the Go 1.27.0 bump felt markedly slower than on 1.26.5 with no code change, and nobody
could say whether that was the toolchain, the machine, or an accident of caching. Everything
below is the measurement that settles it, plus the per-change delta table that keeps it settled.

**If you are here to record a change:** run the benchmark set, compare against
[Reference benchmarks](#reference-benchmarks), and append a row to
[Per-change deltas](#per-change-deltas). A **>5% regression on a hot-path benchmark** or
**>10% on suite wall-clock** is a stop-and-explain, not something to absorb silently.

## Reproducing

```bash
make bench                        # gate form: one iteration per benchmark, proves they still run
make bench BENCHTIME=200ms        # ... with a real per-op measurement
go test -run='^$' -bench=. -benchmem -benchtime=200ms -count=5 \
    ./pkg/goSet ./pkg/goSetValidate ./pkg/goSetPoll ./internal/eventRouter/buffer
```

The four packages are the benchmark set: they carry the hot paths a toolchain or dependency
change is most likely to move — SET marshal/parse/sign, event-payload validation, RFC 8936 poll
request/response encoding, and the long-poll buffer's wait/wake cycle. `BENCH_PKGS` in the
Makefile is the same list; keep the two in step.

## Method

Both toolchains ran against **byte-identical source**. Go refuses to build a module whose `go`
directive is newer than the running toolchain, so measuring 1.26.5 on the 1.27.0 tree required
lowering that one line. Two scratch copies of the working tree were made, identical except for
`go.mod`:

```
go 1.26.5    # measured under GOTOOLCHAIN=go1.26.5
go 1.27.0    # measured under GOTOOLCHAIN=go1.27.0
```

`diff -r` between the two trees reports `go.mod` and nothing else. The module compiles clean
under both, so no source-level compatibility shim distorts the comparison.

Each toolchain got its **own empty `GOCACHE`**, so "cold" is a genuine from-scratch compile and
"warm" reuses only that toolchain's own artifacts. Cold and warm are reported separately
because they answer different questions: cold is what the "first run felt slow" report was
actually about, warm is what a tight edit/test loop pays. Test result caching is disabled
throughout (`-count=1`), so every warm run still executes every test.

Per-package times come from `go test -json`'s per-package `Elapsed` field. Benchmark figures are
the **median of 5 runs at `-benchtime=200ms`**; medians rather than means so one scheduling
outlier cannot move a row.

### Environment

| | |
|---|---|
| Machine | Apple M3 Max, 14 cores, 96 GB, macOS 26.6.2 (arm64) |
| Toolchains | `go1.26.5` and `go1.27.0`, selected with `GOTOOLCHAIN` |
| Date | 2026-08-26 |
| Commit | `fe5a799` (`release-0.12.0`) plus this slice's benchmark files |

Absolute numbers are specific to this machine, which was also running the docker dev stack
throughout. **Compare deltas, not absolutes** — and when a delta is small, check it against the
noise band below before believing it.

## Headline finding

**The reported slowdown does not reproduce.** Under controlled conditions — identical source, a
private empty build cache per toolchain, test result caching disabled — Go 1.27.0 runs this
suite within **±1%** of Go 1.26.5, race detector on or off.

The most likely explanation for the original observation is that the first `go test ./...` after
the bump paid for a toolchain download and a cold build cache at once, which is a one-time cost
and not a property of the toolchain.

What did change is JSON throughput, and mostly for the better. Go 1.27's `encoding/json` v2
engine makes the decode paths this project runs on every inbound SET substantially faster:

| Path | Improvement on 1.27.0 |
|---|---|
| Poll response decode (100 SETs) | **-70%** |
| Poll response encode (100 SETs) | **-66%** |
| Poll request decode | **-48%** |
| SET JSON unmarshal | **-33%** |
| SET `Peek` (unverified parse) | **-17%** |

The `nojsonv2` column in the benchmark table confirms the attribution: with
`GOEXPERIMENT=nojsonv2` those same benchmarks return to roughly their 1.26.5 timings. Allocation
counts drop alongside — poll response decode goes from 318 to 214 allocs/op, SET parse from 96 to
76 — which is the more durable win, since allocation pressure is what shows up under concurrency.

### The one real regression

`BenchmarkSetJsonBytes` — `SecurityEventToken.JsonBytes`, which encodes through
`json.NewEncoder(...).Encode` — is **~11% slower** on 1.27.0, confirmed across 11 runs with
non-overlapping ranges. It is not noise.

It is also not currently worth acting on:

- It costs ~160 ns per SET on the **transmit** side, against a signing cost
  (`BenchmarkSetJWS`, ~820 µs) roughly 5,000× larger. It is invisible in any real transmit path.
- It buys a **16% allocation reduction** on the same call (14 → 11 allocs/op, 865 → 729 B/op).

Recorded so that a later slice touching SET encoding does not rediscover it and mistake it for
its own doing. If SET encoding ever becomes hot without signing in front of it, revisit.

### Noise band

Repeated runs of the same benchmark on the same toolchain varied by **4–7%** on the
sub-microsecond benchmarks (measured over 11 runs; see the recheck table). Treat a delta inside
that band as unproven rather than real: re-run with `-count=11` and compare ranges, not medians,
before recording it. The 5% threshold below is a trigger to investigate, not a verdict.

## Measurements

### Suite wall-clock

| Command | 1.26.5 | 1.27.0 | delta | 1.27.0 `nojsonv2` |
|---|---|---|---|---|
| `go build ./...` | 8.36s | 7.91s | **-5.4%** | 7.86s |
| `go test ./... (cold cache)` | 55.54s | 55.46s | **-0.1%** | 55.16s |
| `go test ./... (warm cache)` | 53.65s | 53.52s | **-0.2%** | 53.73s |
| `go test -race ./... (cold cache)` | 66.73s | 67.22s | **+0.7%** | — |
| `go test -race ./... (warm cache)` | 55.80s | 56.04s | **+0.4%** | — |

Every suite measure lands within ±1% of 1.26.5. All 40 packages pass under both toolchains,
with and without the race detector.

### Per-package wall-clock (warm cache, `-count=1`)

Sorted by 1.27.0 non-race time. Package times sum to far more than suite wall-clock because
`go test` runs packages in parallel.

| Package | test 1.26.5 | test 1.27.0 | delta | race 1.26.5 | race 1.27.0 | delta |
|---|---|---|---|---|---|---|
| `cmd/goSignals` | 52.02s | 51.88s | -0.3% | 53.79s | 53.96s | +0.3% |
| `internal/server/test` | 32.95s | 32.46s | -1.5% | 40.98s | 40.42s | -1.4% |
| `internal/providers/dbProviders/mongo_provider/test` | 25.67s | 25.87s | +0.8% | 27.42s | 27.65s | +0.8% |
| `internal/server` | 18.12s | 18.42s | +1.7% | 22.38s | 21.76s | -2.7% |
| `internal/eventRouter/buffer` | 15.86s | 15.16s | -4.5% | 17.00s | 16.97s | -0.2% |
| `pkg/services` | 9.42s | 9.11s | -3.4% | 15.69s | 14.62s | -6.8% |
| `pkg/authSupport` | 9.04s | 9.04s | -0.0% | 10.33s | 10.15s | -1.7% |
| `internal/eventRouter` | 7.76s | 8.05s | +3.8% | 11.93s | 11.51s | -3.6% |
| `internal/providers/dbProviders` | 3.47s | 3.36s | -3.2% | 4.79s | 4.70s | -1.8% |
| `cmd/genTlsKeys` | 3.15s | 3.05s | -3.2% | 4.69s | 5.67s | +20.8% |
| `internal/providers/dbProviders/memory_provider` | 3.59s | 3.05s | -15.0% | 5.45s | 5.30s | -2.8% |
| `internal/providers/dbProviders/mongo_provider` | 3.39s | 3.04s | -10.1% | 5.05s | 4.87s | -3.6% |
| `pkg/goSetPoll` | 2.42s | 2.55s | +5.2% | 2.83s | 2.99s | +5.6% |
| `pkg/dao` | 2.31s | 2.54s | +9.9% | 2.75s | 2.58s | -6.3% |
| `internal/providers/dbProviders/mongo_provider/watchtokens` | 2.66s | 2.52s | -5.4% | 3.51s | 3.45s | -1.7% |
| `pkg/eventRouter` | 2.51s | 2.45s | -2.5% | 2.51s | 2.14s | -14.7% |
| `pkg/goSetSstp` | 2.07s | 2.44s | +17.9% | 3.21s | 3.27s | +1.7% |
| `pkg/goSetPush` | 2.41s | 2.44s | +1.2% | 3.37s | 3.06s | -9.2% |
| `pkg/dao/memory` | 2.20s | 2.29s | +4.2% | 2.36s | 2.16s | -8.5% |
| `pkg/goSsfServer` | 2.13s | 2.23s | +4.9% | 2.64s | 2.74s | +3.7% |
| `internal/eventRouter/delivery` | 2.07s | 2.17s | +4.9% | 3.73s | 3.81s | +1.9% |
| `pkg/goSet/test` | 2.11s | 2.17s | +2.9% | 1.78s | 2.08s | +17.1% |
| `pkg/goSetValidate` | 1.79s | 1.92s | +6.9% | 2.05s | 2.30s | +11.9% |
| `pkg/goSet/events` | 1.66s | 1.90s | +14.3% | 1.44s | 1.87s | +30.1% |
| `pkg/goScim/resource` | 1.82s | 1.84s | +1.2% | 2.10s | 2.01s | -4.4% |
| `pkg/goSet` | 1.59s | 1.80s | +13.2% | 1.81s | 2.12s | +17.1% |
| `pkg/goSignalsServer` | 1.58s | 1.73s | +9.0% | 2.11s | 2.16s | +2.5% |
| `internal/dao/mongo` | 1.84s | 1.54s | -16.4% | 2.91s | 3.27s | +12.5% |
| `pkg/tlsSupport` | 1.55s | 1.52s | -1.9% | 1.69s | 1.99s | +18.0% |
| `pkg/goSsfUtils` | 1.23s | 1.48s | +19.9% | 1.61s | 1.58s | -2.3% |
| `pkg/oauthClient` | 1.62s | 1.22s | -24.4% | 1.74s | 1.95s | +11.9% |
| `pkg/subjectid` | 1.15s | 1.18s | +2.5% | 1.40s | 1.44s | +3.1% |
| `pkg/wellKnownSupport` | 1.32s | 1.09s | -17.0% | 1.52s | 1.97s | +29.2% |
| `cmd/cluster-monitor` | 0.89s | 1.06s | +18.3% | 1.96s | 2.04s | +4.6% |
| `pkg/ssfModels` | 1.16s | 0.98s | -15.7% | 1.46s | 1.78s | +21.7% |
| `internal/envcompat` | 1.05s | 0.97s | -7.1% | 2.12s | 2.25s | +6.4% |
| `pkg/nodeid` | 0.69s | 0.74s | +8.0% | 1.35s | 1.28s | -5.1% |
| `internal/dao` | 0.83s | 0.70s | -15.4% | 1.93s | 2.14s | +10.7% |
| `pkg/logger` | 0.56s | 0.63s | +12.7% | 1.24s | 1.27s | +1.9% |
| `cmd/goSignalsServer` | 0.55s | 0.49s | -10.5% | 1.71s | 1.79s | +5.0% |
| **total** | **230.23s** | **229.09s** | **-0.5%** | **280.34s** | **281.07s** | **+0.3%** |

### Reference benchmarks

Median of 5 runs at `-benchtime=200ms`. **These 1.27.0 numbers are the reference a later
change compares against.**

| Benchmark | 1.26.5 ns/op | 1.27.0 ns/op | delta | allocs 1.26.5 → 1.27.0 | B/op 1.26.5 → 1.27.0 | `nojsonv2` ns/op |
|---|---|---|---|---|---|---|
| `BenchmarkBuiltinRegistry` | 3252 | 3161 | -2.8% | 10 → 10 | 4,480 → 4,480 | 3183 |
| `BenchmarkCreateSet` | 515 | 504 | -2.1% | 3 → 3 | 104 → 104 | 506 |
| `BenchmarkGenerateJti` | 470 | 440 | -6.4% | 1 → 1 | 32 → 32 | 460 |
| `BenchmarkNewValidatorSet` | 376 | 354 | -5.9% | 3 → 3 | 272 → 272 | 357 |
| `BenchmarkParseAndValidate` | 35,065 | 32,081 | -8.5% | 101 → 85 | 8,288 → 7,367 | 32,913 |
| `BenchmarkParsePollRequest` | 22,853 | 11,895 | -47.9% | 140 → 134 | 20,157 → 21,949 | 20,209 |
| `BenchmarkPollBufferAckEvents` | 1982 | 1987 | +0.3% | 0 → 0 | 0 → 0 | 1972 |
| `BenchmarkPollBufferGetEventsAckOnly` | 20.5 | 15.2 | -25.7% | 1 → 1 | 24 → 24 | 15.4 |
| `BenchmarkPollBufferGetEventsReady` | 211 | 178 | -16.0% | 2 → 2 | 1,816 → 1,816 | 180 |
| `BenchmarkPollBufferSubmitDrain` | 102 | 97.5 | -4.2% | 1 → 1 | 198 → 200 | 97.7 |
| `BenchmarkPollBufferWaitWake` ⚑ | 631 | 704 | +11.6% | 4 → 4 | 232 → 233 | 704 |
| `BenchmarkPollBufferWakeupSignal` | 33.4 | 30.1 | -10.0% | 1 → 1 | 112 → 112 | 30.4 |
| `BenchmarkPollRequestMarshal` | 3494 | 3303 | -5.5% | 5 → 5 | 3,603 → 3,603 | 3178 |
| `BenchmarkPollResponseUnmarshal` | 156,199 | 46,815 | -70.0% | 318 → 214 | 46,432 → 44,649 | 135,779 |
| `BenchmarkSetJWS` | 823,999 | 819,086 | -0.6% | 38 → 37 | 7,202 → 6,980 | 820,949 |
| `BenchmarkSetJsonBytes` ⚑ | 1492 | 1619 | +8.5% | 14 → 11 | 865 → 729 | 1430 |
| `BenchmarkSetJsonUnmarshal` | 4575 | 3075 | -32.8% | 56 → 42 | 2,672 → 1,853 | 4198 |
| `BenchmarkSetParse` | 32,187 | 31,474 | -2.2% | 96 → 76 | 7,672 → 6,671 | 33,129 |
| `BenchmarkSetPeek` | 5833 | 4816 | -17.4% | 80 → 60 | 4,360 → 3,346 | 6082 |
| `BenchmarkValidateEngaged` | 361 | 339 | -6.1% | 1 → 1 | 64 → 64 | 333 |
| `BenchmarkValidateMultiEvent` | 871 | 841 | -3.4% | 2 → 2 | 288 → 288 | 830 |
| `BenchmarkValidateUnsupported` | 108 | 95.2 | -11.6% | 1 → 1 | 64 → 64 | 97.7 |
| `BenchmarkWritePollResponse/sets=1` | 2324 | 1232 | -47.0% | 15 → 15 | 2,612 → 2,226 | 2058 |
| `BenchmarkWritePollResponse/sets=10` | 16,360 | 6078 | -62.8% | 33 → 25 | 18,164 → 13,491 | 14,681 |
| `BenchmarkWritePollResponse/sets=100` | 160,493 | 54,903 | -65.8% | 214 → 115 | 168,327 → 126,787 | 138,866 |

⚑ re-measured at `-count=11`; see [Two rows that needed a second look](#two-rows-that-needed-a-second-look).

### Two rows that needed a second look

Both crossed the 5% line at `-count=5`, so both were re-run at `-benchtime=300ms -count=11`
to separate signal from scheduler noise.

| Benchmark | 1.26.5 median | 1.27.0 median | delta | 1.26.5 range | 1.27.0 range | verdict |
|---|---|---|---|---|---|---|
| `BenchmarkSetJsonBytes` | 1447 ns | 1605 ns | **+10.9%** | 1430–1524 | 1580–1674 | **real regression** — ranges do not overlap |
| `BenchmarkPollBufferWaitWake` | 773 ns | 718 ns | **-7.2%** | 760–793 | 701–728 | noise at count=5; actually **faster** |

## The goroutine-leak gate

`make qa` runs a `leak-check` step alongside the benchmarks. It is here rather than in a
document of its own because it answers the question the benchmarks cannot: a leaked goroutine
costs no measurable time at the moment it is created, so no `ns/op` number will ever show one.

Go 1.27 GA'd goroutine leak detection as a `runtime/pprof` profile named `goroutineleak`.
Writing the profile runs a GC cycle with leak detection enabled and reports the goroutines the
runtime has **proved** can never become runnable again — one blocked forever on a channel or
mutex that no live goroutine can ever signal. This is not the count-before-and-after heuristic
the ecosystem used to hand-roll: a goroutine that is merely slow to finish is never reported,
so there is no tolerance to tune and nothing to flake on.

Note the surface. The profile is reached through `pprof.Lookup("goroutineleak")`; there is no
`-test.goroutineleakprofile` flag on `go test` in Go 1.27.0, so the gate is a `TestMain` hook
rather than a command-line switch.

### Running it

```bash
make leak-check                                   # the gate
make qa                                           # ... as part of the full gate
I2SIG_GOROUTINE_LEAK_CHECK=1 go test -count=1 ./internal/eventRouter/...   # one package
```

`pkg/goroutineleak` provides the hook; a package opts in with one line in its `TestMain`:

```go
func TestMain(m *testing.M) { os.Exit(goroutineleak.Run(m)) }
```

The check is **inert unless `I2SIG_GOROUTINE_LEAK_CHECK` is set**, which `make leak-check` does
and a bare `go test ./...` does not. That is deliberate: a leak is a property of the whole
package run, so a failure names the package and not the test that caused it. Keeping it off by
default leaves the tight edit/test loop reporting the failing *test*, and puts the blunter
failure in the gate, where "this package leaks" is the right granularity. `-count=1` is
required — a cached PASS would skip the profile entirely.

`LEAK_PKGS` in the Makefile is the enrolled set: `pkg/goSetPoll`, `pkg/goSetPush`,
`internal/eventRouter/...` and `internal/server`. Those are the packages that own a timer path —
lease heartbeats and push recovery, the long-poll wait, the SSTP dialer's heartbeat and resume
timers — which is where an abandoned goroutine actually comes from.

### Reading a failure

The report prints each leaked goroutine's stack, which names **the code that started the
goroutine, not the test that stranded it**. To find the test, bisect with `-run`:

```bash
I2SIG_GOROUTINE_LEAK_CHECK=1 go test -count=1 -run '^(TestA|TestB|...)$' ./internal/server
```

### What it found on its first run

Enrolling the six packages surfaced two production leaks and two test-hygiene ones, all fixed by
[#279](https://github.com/i2-open/i2goSignals/issues/279):

| Leak | Where | Cause |
|---|---|---|
| Poll buffer pump, on every close with unread events | `internal/eventRouter/buffer/event_buffer.go` | The pump looped while unread JTIs remained even after `in` was closed, re-entering a receive on the channel it had just nil'd. A receive on a nil channel blocks forever. Closing a buffer with events still pending is routine — it is what a stream deletion or a lost lease does. |
| Poll buffer pump, one per poll stream, on router shutdown | `internal/eventRouter/event_router.go` | `Shutdown` closed push and SSTP buffers but skipped poll buffers, under the reasoning that polling is receiver-driven and needs no shutdown. Every `EventPollBuffer` owns a pump goroutine regardless. `RemoveStream` had always closed them on the per-stream path; `Shutdown` now matches. |
| Buffer left open by a test | `internal/eventRouter/buffer/event_buffer_test.go` | `TestEventPollBuffer_Wakeup` never closed its buffer. |
| Routers left running by a suite | `internal/server/server_provisioning_authz_test.go` | `ServerProvisioningAuthzSuite` built a router per test and had no `TearDownTest`. |

The first two are the reason the gate exists: neither was visible in any test result, any
benchmark, or any log line.

## Per-change deltas

One row per change that lands against this baseline. Fill in the worst delta you measured — the
single benchmark that moved most, not an average — so a regression cannot hide behind a set of
improvements. Rows for the sibling slices of spec #101 are pre-seeded; add rows below them for
later work.

| Change | Worst benchmark delta | Suite wall-clock delta | Notes |
|---|---|---|---|
| #270 — baseline + `make qa` | — | — | Established this baseline. |
| #271 — PQ-KEM guard, TLS MinVersion, WithValidMethods | **+3.0%** `BenchmarkPollBufferSubmitDrain` | **+0.4%** (53.72s vs 53.52s) | Inside the documented 4–7% noise band and untouched by this slice — nothing in it goes near the poll buffer. The one benchmark that does exercise changed code, `BenchmarkSetParse` (now runs `jwt.WithValidMethods`), came in at **-1.4%**: the allow-list is a string compare against a two-element slice, ahead of an RSA verify. Every other row improved or held flat. |
| #272 — drop `golang.org/x/exp` (log/slog) | **+4.5%** `BenchmarkSetJsonUnmarshal` | **+0.4%** (53.72s vs 53.52s) | Inside the documented 4–7% noise band and untouched by this slice: the only Go change is an import swap in `cmd/genTlsKeys` (a `main` package no benchmark compiles), so no benchmarked package's dependency graph moved — `golang.org/x/exp` was a leaf of that one command. Every other row is ≤ +4.4% or an improvement. The +1 allocs/op on `BenchmarkSetParse` (76 → 77) and `BenchmarkParseAndValidate` (85 → 86) is [#271](https://github.com/i2-open/i2goSignals/issues/271)'s `jwt.WithValidMethods` allow-list, already on the branch and already explained in its row — not this slice. |
| #273 — JSON wire hygiene, golden-JSON tests, compact poll encoding | **+2.1%** `BenchmarkPollBufferSubmitDrain` | **+0.0%** (53.54s vs 53.52s) | The worst row is the poll buffer, which this slice does not touch, at less than half the documented noise band. Every benchmark over changed code improved, most of them sharply: dropping `json.MarshalIndent` from the poll hot path takes `BenchmarkWritePollResponse` down **-34.2%** (sets=1), **-39.3%** (sets=10) and **-39.5%** (sets=100), with B/op at sets=100 falling 126,787 → 85,704 — the indent pass was re-walking the whole encoded buffer to insert whitespace no receiver reads. `BenchmarkPollRequestMarshal` is **-5.0%** for the same reason on the receiver side. `BenchmarkSetJsonBytes` is **-6.2%** (11 → 10 allocs/op, 729 → 681 B/op): `JsonBytes` no longer builds its result through a `json.Encoder` and its buffer, which also removes the trailing newline from the JWS payload. That row is the ⚑ **real +10.9% regression** flagged in [Two rows that needed a second look](#two-rows-that-needed-a-second-look); this slice gives most of it back. The 20 `omitempty` → `omitzero` retags are compile-time struct tags and cost nothing at run time. |
| #274 — single ID seam `pkg/dao/ids` (uuid v7/v4), drop ksuid | **+3.4%** `BenchmarkSetParse` | **+0.9%** (53.98s vs 53.52s) | The headline is the other direction: swapping `segmentio/ksuid` for the 1.27 stdlib `uuid` takes `BenchmarkGenerateJti` from 440 → 112.5 ns/op (**-74.4%**, allocs flat at 1) and `BenchmarkCreateSet`, which mints one jti per envelope, from 504 → 179 ns/op (**-64.5%**). ksuid was paying for a base62 encode over a 20-byte payload; `uuid.NewV7().String()` is a hex write behind a mutex-guarded timestamp counter. **The `pkg/goSet` workload changed shape** and every row in that package should be read with it: `benchSet()` builds its token through `CreateSet`, so the `jti` claim in the benchmarked SET grew from a 27-character ksuid to a 36-character UUID. That is the whole of the worst row — `BenchmarkSetParse` +3.4% with B/op 6,671 → 6,959 (+288) is 9 extra claim bytes to base64-decode and unmarshal, not a slower parser — and it is why `BenchmarkGenerateJti` B/op reads 32 → 48 and `BenchmarkCreateSet` 104 → 120 with allocation *counts* unchanged: one string, nine bytes longer, in the same single allocation. `BenchmarkParseAndValidate` takes the same 9 bytes for **-1.0%**. Nothing else in the set touches changed code; the poll and buffer rows sit between -5.8% and +1.8%. |
| #275 — timer hygiene, coordinator lifecycle context | **+3.8%** `BenchmarkParseAndValidate` | **+0.0%** (53.54s vs 53.52s) | The worst row is inside the documented 4–7% noise band and sits in `pkg/goSetValidate`, which this slice does not touch (B/op 7,367 → 7,400 and allocs 85 → 86 are [#271](https://github.com/i2-open/i2goSignals/issues/271)'s `jwt.WithValidMethods` plus [#274](https://github.com/i2-open/i2goSignals/issues/274)'s longer UUID `jti`, both already on the branch and already explained in their rows). **The rows that matter here are the six poll-buffer benchmarks**, because `EventPollBuffer.GetEvents` is the one hot path this slice rewrites — its long-poll wait moved from `time.After` to an owned `*time.Timer` stopped on every exit path. They came in flat: `BenchmarkPollBufferWaitWake` **-0.4%** (704 → 701, allocs 4 → 4, B/op 233 → 233), `BenchmarkPollBufferWakeupSignal` **-2.0%**, `BenchmarkPollBufferGetEventsReady` **+0.5%**, `BenchmarkPollBufferGetEventsAckOnly` **+0.9%**, `BenchmarkPollBufferAckEvents` **+0.8%**, `BenchmarkPollBufferSubmitDrain` **+3.0%**. `WaitWake` is the ⚑ row flagged in [Two rows that needed a second look](#two-rows-that-needed-a-second-look) and the only benchmark that actually exercises the changed wait/wake cycle: holding it at -0.4% is the result this slice needed. Owning the timer costs one `time.NewTimer` where `time.After` allocated one anyway, so flat is the expected shape — the win is a stopped timer rather than an armed one, which no ns/op number can show. The large improvements in this run (`BenchmarkGenerateJti` -73.8%, `BenchmarkCreateSet` -64.7%, `BenchmarkWritePollResponse` -17% to -37%) are #273 and #274 already on the branch, not this slice. The coordinator lifecycle-context change touches no benchmarked package. |
| #276 — jsontext reserved-key rejection, aud splice, json/v2 pilot | **+2.4%** `BenchmarkPollBufferSubmitDrain` | **+0.0%** (53.54s vs 53.52s) | The worst row is the poll buffer, which this slice never touches, at well under half the documented 4–7% noise band, and suite wall-clock is unmoved. **This slice adds five benchmarks**, so its own rows are an A/B against this branch's HEAD (`ac74fa3`) with the benchmark files held constant and only the implementation swapped — median of 5 at `-benchtime=200ms`, the same method as the reference. `BenchmarkRejectReservedKeys` (`pkg/goSet`, new): **1933 → 933 ns/op (-51.8%), 73 → 0 allocs/op, 2,040 → 0 B/op**. `BenchmarkWireBSON` (`pkg/goSet`, new — the whole persist-side encode the scan sits in): **13,361 → 12,308 ns/op (-7.9%), 351 → 278 allocs/op, 13,627 → 11,596 B/op**. The zero comes from two changes together: the scan reads member names as raw `jsontext.Value` bytes rather than decoding each one to a Go string, and the decoder is pooled with its reader, because a `jsontext.Decoder` owns a growable buffer and a container stack that a per-call constructor throws away and re-grows — that re-growth was nearly all of the remaining allocation. `v1`'s `json.Decoder.Token()` boxed every token into an `interface{}`; nothing in the new scan allocates at all. `BenchmarkNormalizeAudToArray` and `BenchmarkUnmarshalStreamConfigurationJSON` live in `pkg/ssfModels`, which is deliberately **not** added to `BENCH_PKGS` — the pinned set stays as #270 fixed it so earlier rows keep comparing like with like; run them with `go test -run='^$' -bench=NormalizeAud -benchmem ./pkg/ssfModels`. String aud **6,100 → 308 ns/op (-94.9%), 55 → 1 allocs/op**; array aud **3,629 → 185 ns/op (-94.9%), 32 → 0**; absent aud **3,189 → 1,141 ns/op (-64.2%), 28 → 0**; the surrounding decode **10,708 → 3,592 ns/op (-66.5%), 80 → 21 allocs/op**. The old normaliser decoded the whole document into a `map[string]json.RawMessage` and re-encoded it to change one member — which also sorted the transmitter's members into lexical order, compacted their whitespace, and turned `{"aud":null}` into `{"aud":[""]}`; the splice touches two bytes and returns the caller's own slice untouched whenever there is nothing to rewrite. **The json/v2 pilot verdict: adopted.** `BenchmarkNormalizePayload` (`pkg/goSetValidate`, new) runs both encoders over the same shapes: struct payload **2,067 → 1,399 ns/op (-32.3%), 32 → 22 allocs/op**; map-holding-a-struct **2,610 → 1,719 ns/op (-34.1%), 41 → 31 allocs/op**; already-wire-shaped payload **87.4 → 87.5 ns/op, 0 allocs** (both variants short-circuit, so that row measures `isWireShape` and is expected to be flat). Both axes improve on both round-trip shapes, which is the issue's adoption bar, so `normalizePayload` now runs on `encoding/json/v2`; the superseded v1 form stays in `pkg/goSetValidate/normalize_pilot_test.go` so the A/B is re-runnable against a later toolchain. The pilot is scoped to that one function — `decodeSubjectIdentifier` in `caep.go` keeps its v1 round-trip, since it runs only for CAEP events carrying a payload-level subject, not per event. **One behaviour moves with the encoder:** v2 rejects invalid UTF-8 in a string where v1 substituted U+FFFD, so such a payload now reports `Malformed` instead of validating bytes that had already been rewritten. It can only arrive from an in-process Go string, never off the wire. Every reference row over unchanged code held or improved: `BenchmarkParseAndValidate` **-1.6%**, `BenchmarkValidateEngaged` **-2.2%**, `BenchmarkValidateMultiEvent` **-3.9%**, `BenchmarkSetParse` **-3.0%**, `BenchmarkSetPeek` **-4.2%**. The two ⚑ rows from [Two rows that needed a second look](#two-rows-that-needed-a-second-look) came in flat: `BenchmarkSetJsonBytes` 1619 → 1612 (**-0.4%**, 11 → 10 allocs/op) and `BenchmarkPollBufferWaitWake` 704 → 698 (**-0.8%**). The large wins in this run (`BenchmarkGenerateJti` -74.3%, `BenchmarkCreateSet` -61.1%, `BenchmarkWritePollResponse` -33% to -40%) are [#273](https://github.com/i2-open/i2goSignals/issues/273) and [#274](https://github.com/i2-open/i2goSignals/issues/274) already on the branch, not this slice. Goldens are byte-identical: this slice changes no marshalling API and no struct tag. |
| #277 — `crypto.Signer` at the 9 signing sites | **+2.8%** `BenchmarkPollBufferSubmitDrain` | **+0.3%** (53.70s vs 53.52s) | The worst row is the poll buffer, which this slice never touches, at well under half the documented 4–7% noise band. **The row that matters is `BenchmarkSetJWS`** — the only benchmark that runs the changed code, since it is the SET signing path this slice re-typed. Against the reference it is **+0.4%** (819,086 → 822,465 ns/op) with **allocations flat at 37/op**. An A/B against this branch's own HEAD (`21a7d64`, immediately before the slice) is tighter still: **814,060 → 822,465 ns/op median (+1.0%), 37 → 37 allocs/op, 7,236 → 7,235 B/op**, with the two five-run ranges overlapping (before 808,948–822,076; after 802,358–839,185) — unproven under this file's own range rule, i.e. no measurable cost. That is the expected shape rather than a lucky result: `golang-jwt`'s `SignedString` has always taken its key as `interface{}` and type-asserted it, so passing a `crypto.Signer` boxes the same pointer that was previously boxed one call later. No allocation is added and no new indirection is introduced on the signing path — the whole benchmark is dominated by one RSA-2048 private-key operation ~800 µs long, against which an interface method call is unmeasurable. The `crypto.Signer` → `*rsa.PrivateKey` narrowings this slice adds sit in the key **store** (PKCS#1 marshal) and JWKS build, both of which run at key load and rotation, not per SET. Everything else in the set improved or held flat (`BenchmarkSetParse` -4.3%, `BenchmarkSetPeek` -7.2%, `BenchmarkParsePollRequest` -6.8%); the large wins (`BenchmarkGenerateJti` -74.3%, `BenchmarkCreateSet` -64.7%, `BenchmarkWritePollResponse` -33% to -38%) are [#273](https://github.com/i2-open/i2goSignals/issues/273) and [#274](https://github.com/i2-open/i2goSignals/issues/274) already on the branch, not this slice. |
| #278 — ML-DSA-65 SET signing (RFC 9964) | | | |
| #279 — `testing/synctest` suites + goroutine-leak gate | **+6.4%** `BenchmarkPollBufferGetEventsAckOnly` (A/B); ⚑ see note on `GetEventsReady` | **-0.5%** (53.24s vs 53.52s) | **This slice's numbers are an A/B against the branch's own HEAD (`358a42d`)**, not against the reference table, because the reference row for one poll-buffer benchmark no longer reproduces on this machine at all — see the ⚑ paragraph below. The A/B is per-benchmark isolated (`-bench='^BenchmarkPollBufferX$'`, median of 5 at `-benchtime=200ms`) because this slice makes an existing WARN reachable, and its output interleaves with `go test`'s on stdout. **The rows over changed code both improve**: `BenchmarkPollBufferSubmitDrain` **-9.2%** (95.88 → 87.10) and `BenchmarkPollBufferGetEventsReady` **-7.2%** (291.50 → 270.50), which is the expected shape — the pump loop lost a `mutex.Lock`/`Unlock` pair per iteration along with the nil-channel leak. The rest are flat: `BenchmarkPollBufferAckEvents` **+0.0%**, `BenchmarkPollBufferWaitWake` **-2.7%**, `BenchmarkPollBufferWakeupSignal` **+2.1%**. The worst row, `BenchmarkPollBufferGetEventsAckOnly` **+6.4%**, is 11.31 → 12.03 ns/op — seven tenths of a nanosecond on a benchmark that does one map lookup, with allocations and B/op unchanged and the two ranges nearly touching (base 11.3–11.5, after 11.7–12.5). Nothing in this slice is on that path. ⚑ **`BenchmarkPollBufferGetEventsReady` reads +52% against the reference table, and that drift is environmental, not this slice's.** The pre-slice branch HEAD measures **291.5 ns/op** against a recorded reference of 178, i.e. worse than this slice's 270.5 — so the slice narrows the gap rather than opening it. Re-measuring [#270](https://github.com/i2-open/i2goSignals/issues/270)'s own commit (`cc680e4`), the tree that *produced* the 178, gives **287.1 ns/op** today; walking the branch forward gives `c83a29a` 291.3, `0b338ae` 296.9, `4a0b2fb` 318.8. Byte-identical source, three-to-four tenths slower than recorded, so the 178 is a property of the conditions of the original run and not of any code since. The reference file already warns that its absolute numbers are machine- and load-specific ("Compare deltas, not absolutes"); this is that warning coming true, and a reason to prefer A/B-against-HEAD for any row where the reference and the current branch disagree. **The non-benchmark result of this slice is the leak gate**, documented above: it found two production goroutine leaks on its first run, neither of which any benchmark could have shown. |

### Thresholds

| Signal | Threshold | Action |
|---|---|---|
| Hot-path benchmark ns/op | >5% slower | Stop and explain in the PR before merge |
| Suite wall-clock | >10% slower | Stop and explain in the PR before merge |
| Benchmark allocs/op | any increase on a hot path | Explain; often the cheapest thing to fix |

A regression that is understood and accepted is fine — the rule is that it must be *stated*, with
its number, not discovered later.

### Appending a row

1. `make bench BENCHTIME=200ms` (or the `-count=5` command above for a publishable number).
2. Compare each benchmark against [Reference benchmarks](#reference-benchmarks).
3. Add your row with the worst delta and a one-line cause.
4. If a benchmark's *meaning* changed — different workload, different shape — say so in Notes.
   A delta against a workload that no longer exists is worse than no delta at all.

Do not silently re-baseline. If the reference numbers genuinely need to move (new machine, new
Go release), replace this whole file in its own change and say why in the commit.
