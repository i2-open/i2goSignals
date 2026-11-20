<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 37. Push delivery concurrency is derived from available processors, clamped to a measured plateau

Date: 2026-09-08

## Status

Accepted (community #285).

## Context

ADR 0035 gave push delivery a per-stream worker pool and pinned its width at a
fixed `I2SIG_PUSH_CONCURRENCY = 5`. Five was a starting value, not a measured
one, and push is the only worker pool in the server still on a constant:
`I2SIG_SIGN_CONCURRENCY`, the poll receiver's pool (`pkg/goSetPoll/receiver.go`)
and the SSTP batch verifier (`pkg/goSetSstp/verify_batch.go`) all size
themselves from `runtime.GOMAXPROCS(0)`.

The knob also sets the durability window. `pushBatchMax()` returns
`4 * pushConcurrency`, and that is the ack-deferral window: the number of SETs
a receiver has already accepted whose delivered mark has not yet been written,
and which are therefore resent after a crash mid-batch (ADR 0035). Any change
to the default changes that window by 4x as much.

## Measurements

`cmd/goSignalsBench --mix push`, 5000 events, 16 concurrent ingest clients,
against the `docker-compose-dev.yml` stack on an Apple M-series laptop
(14 processors). Only `I2SIG_PUSH_CONCURRENCY` changed between runs on the
first sweep; the second sweep repeats it with the transmitter constrained to
four processors via `GOMAXPROCS=4`, so the answer is expressed relative to
available processors rather than to one host shape. Transmitter CPU is
`docker stats` on `gosignals1`, sampled once a second across the run; the mean
is diluted by idle time in the long low-concurrency runs, so the peak is the
comparable column.

**14 processors** (1400% CPU available):

| `I2SIG_PUSH_CONCURRENCY` | Push ev/s | Drain after ingest | Ingest ev/s | Total run | Tx CPU mean / peak |
|---|---|---|---|---|---|
| 1 | 163 | 26.24s | 1133 | 30.66s | 65% / 287% |
| 5 (old default) | 417 | 7.09s | 1021 | 11.99s | 111% / 283% |
| 8 | 484 | 4.55s | 863 | 10.34s | 109% / 319% |
| 16 | 542 | 2.04s | 696 | 9.24s | 310% / 335% |
| 24 | 583 | 0.51s | 619 | 8.59s | 314% / 342% |
| 32 | 521 | 0.52s | 550 | 9.61s | 321% / 344% |
| 64 | 545 | 0.51s | 577 | 9.19s | 335% / 341% |

**4 processors** (`GOMAXPROCS=4`, 400% CPU available):

| `I2SIG_PUSH_CONCURRENCY` | Push ev/s | Drain after ingest | Ingest ev/s | Total run | Tx CPU mean / peak |
|---|---|---|---|---|---|
| 1 | 169 | 25.24s | 1142 | 29.63s | 78% / 222% |
| 5 (old default) | 425 | 6.57s | 961 | 11.78s | 109% / 252% |
| 8 | 490 | 4.05s | 812 | 10.22s | 89% / 258% |
| 16 | 546 | 1.53s | 655 | 9.17s | 275% / 279% |
| 24 | 553 | 0.52s | 586 | 9.05s | 268% / 281% |
| 32 | 532 | 0.52s | 563 | 9.40s | 271% / 276% |
| 64 | 577 | 0.52s | 614 | 8.67s | 193% / 284% |

Three things fall out, and the second is the surprise.

1. **The knee is between 5 and 16, and the plateau starts at 16.** From 16 up,
   every push figure on both shapes sits inside the benchmark's ~10% noise band
   (542, 583, 521, 545 at fourteen processors; 546, 553, 532, 577 at four).
   Drain-after-ingest reaches the metrics-scrape floor of 0.5s at 24, meaning
   the push leg has stopped being the bottleneck: it keeps up with ingest.

2. **The curve barely moves when processors are taken away.** Constraining the
   transmitter from fourteen processors to four changed push throughput at the
   knee by less than 1% (542 → 546 at concurrency 16). The optimum is not a
   property of the transmitter's CPU: push is latency-bound, and the useful
   worker count is roughly the bandwidth-delay product of the link to one
   receiver. Peak transmitter CPU never exceeded 344% of a possible 1400%.

3. **Delivery is bought with ingest.** Ingest falls monotonically as push
   concurrency rises — 1133 → 550 ev/s across the fourteen-processor sweep —
   because the delivery pool and the ingest handlers compete for the same
   processors. Going from 16 to 64 buys 0.5% delivery and costs 17% ingest.

**Before and after at the new default**, same harness and same tree, two runs
each (recorded in `docs/perf/e2e-history.md` under `spec102-285-before-fixed5-*`
and `spec102-285-after-derived-*`; the derived value on this fourteen-processor
host is 14):

| Default in force | Push ev/s | Drain after ingest | Ingest ev/s | Total run |
|---|---|---|---|---|
| fixed 5 (ADR 0035) | 414, 419 | 7.08s, 6.57s | 1001, 935 | 12.08s, 11.93s |
| derived 14 (this ADR) | 536, 589 | 2.55s, 2.03s | 737, 775 | 9.34s, 8.49s |

Push delivery gains about 34%, drain-after-ingest falls from ~6.8s to ~2.3s,
and ingest pays about 22% for it. The run as a whole finishes 26% sooner.

## Decision

1. **The default is derived, clamped, and no longer a constant.**

   ```go
   defaultPushConcurrency() = clamp(runtime.GOMAXPROCS(0), 8, 32)
   ```

   On the dev host (14 processors) that is 14, up from 5.

2. **Floor 8.** Below eight POSTs in flight the push leg is the bottleneck on
   every shape measured (163-169 ev/s at 1, 417-425 at 5, against ~545 on the
   plateau). Because the work is latency-bound rather than CPU-bound, a
   two-processor container gains from concurrency it does not have processors
   for; without a floor it would inherit a near-serial default.

3. **Ceiling 32, and the ceiling is a durability decision.** Past 24 the
   delivery curve is flat within noise while ingest keeps falling, so the extra
   workers buy nothing measurable. What they do buy is resend: at 32 the
   ack-deferral window is `4 * 32 = 128` SETs, the most a crash mid-batch can
   resend to a receiver. Without the ceiling a 64-processor host would derive a
   256-SET window for no measured delivery gain, and a 256-processor host a
   1024-SET one. Receivers dedupe on `jti`, so a resend is correctness-safe and
   the cost is receiver work, but it is a cost the operator did not ask for.

4. **Why derive from processors at all, given finding 2?** Because the clamp
   range comes from the receiver and the trade inside it comes from the
   machine. The plateau's location is a property of the link, so the floor and
   the ceiling do most of the work here and `GOMAXPROCS` only picks a point
   between them. That point still matters: delivery is paid for out of ingest
   on the same processors, so a machine with fewer processors should not keep
   as many POSTs open as one with more. `GOMAXPROCS` is the only measure of
   that budget the process has at boot, and it is the idiom the other three
   pools already use.

5. **An explicit `I2SIG_PUSH_CONCURRENCY` is unchanged and still wins.** It is
   read exactly as before, is not clamped, and `=1` still restores serial POSTs
   with batched reads and acks. The resolved value, its source and the
   resulting ack-deferral window are logged once at router start.

## Does push concurrency self-tune?

Not yet, and this ADR records why not.

The case for a controller is that the optimum is not a property of the
transmitter at all. Push is latency-bound, so the useful worker count is
roughly the bandwidth-delay product: enough concurrent POSTs to keep the pipe
to one receiver full. That depends on the receiver's round-trip latency and
its own capacity, neither of which the transmitter knows at boot and both of
which differ per stream. One number derived from `GOMAXPROCS` cannot be right
for both a 2 ms in-cluster receiver and a 200 ms internet one. The shape would
be a per-stream controller that grows the worker count while drain rate keeps
improving and backs off on 429 or 503 with `Retry-After`, or when ingest
throughput degrades; Little's law gives the target directly from measurements
the delivery loop already takes.

The case against going there first is that it puts a control loop on the
delivery path, control loops oscillate, and the failure mode is overloading a
receiver in a way the current fixed cap cannot produce. ADR 0035 already notes
that a receiver sees up to `concurrency` concurrent POSTs per transmitter
stream; a controller makes that bound dynamic and unowned by the operator.
The measurements above also show the payoff is small: past the knee the curve
is flat, so a controller that lands anywhere in the plateau does no better
than the derived default, while a controller that overshoots costs ingest.

So: land the measured, processor-derived default now, and adopt a controller
only on evidence — a deployment where the derived default is measurably wrong
and the override is not an acceptable answer. If self-tuning is adopted later,
the derived default becomes the controller's **starting point** and its
**ceiling**, and an explicit `I2SIG_PUSH_CONCURRENCY` becomes the override
that pins the controller off.

## Consequences

- **Push delivery is faster out of the box and ingest is slower out of the
  box.** That trade is the point of the sweep and it is now stated on
  `I2SIG_PUSH_CONCURRENCY` in `docs/configuration_properties.md`: a deployment
  that values ingest admission over delivery latency should pin the knob low,
  and one fronting a slow receiver should pin it high.
- **The ack-deferral window grew with the default.** It was 20 SETs at the
  fixed 5; it is now `4 x` the derived value — 32 at the floor, 56 on a
  fourteen-processor host, 128 at the ceiling. A crash mid-batch resends up to
  that many already-accepted SETs, which receivers drop on `jti` dedup
  (ADR 0017).
- **Receiver load per stream rose.** A receiver now sees up to the derived
  concurrency of simultaneous POSTs per transmitter stream instead of five.
  429 and 503 with `Retry-After` are honoured exactly as ADR 0035 describes,
  and a receiver that cannot take the fan-out is the case
  `I2SIG_PUSH_CONCURRENCY` exists for.
- **The benchmark's push and ingest rows are no longer comparable across this
  change without saying which default was in force**, because the default is
  now part of what the row measures. `docs/perf/e2e-history.md` carries the
  before and after rows under the `spec102-285-` labels.
- **`GOMAXPROCS` is now load-bearing for delivery behaviour, not just for CPU
  work.** A container that pins `GOMAXPROCS` low — or a Go runtime that derives
  it from a CPU quota — reduces push concurrency with it, down to the floor.
