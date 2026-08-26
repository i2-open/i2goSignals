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

## Per-change deltas

One row per change that lands against this baseline. Fill in the worst delta you measured — the
single benchmark that moved most, not an average — so a regression cannot hide behind a set of
improvements. Rows for the sibling slices of spec #101 are pre-seeded; add rows below them for
later work.

| Change | Worst benchmark delta | Suite wall-clock delta | Notes |
|---|---|---|---|
| #270 — baseline + `make qa` | — | — | Established this baseline. |
| #271 — PQ-KEM guard, TLS MinVersion, WithValidMethods | | | |
| #272 — drop `golang.org/x/exp` (log/slog) | | | |
| #273 — JSON wire hygiene, golden-JSON tests, compact poll encoding | | | |
| #274 — single ID seam `pkg/dao/ids` (uuid v7/v4), drop ksuid | | | |
| #275 — timer hygiene, coordinator lifecycle context | | | |
| #276 — jsontext reserved-key rejection, json/v2 pilot | | | |
| #277 — `crypto.Signer` at the 9 signing sites | | | |
| #278 — ML-DSA-65 SET signing (RFC 9964) | | | |
| #279 — `testing/synctest` suites + goroutine-leak gate | | | |

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
