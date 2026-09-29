# K in-flight push and SSTP batches (#339, spec-111 Stage 2)

This page describes what #339 changes in the push runner and the SSTP
initiator, and how it was measured. The model and its limits are recorded in
[ADR 0044](../adr/0044-delivery-pipelining.md).

## What changed

Before #339, a push stream had one batch on the wire at a time. #336 let the
next batch be sent while the previous batch's ack was being written, but the
send itself was still serial: the runner waited for every POST of a batch to
finish before draining the next one. The SSTP initiator had a single
second-push slot per pair (Q7.2).

After #339:

- **Push.** The runner keeps up to K batches in flight per stream:

      K = max(1, min(push concurrency, in-flight bound / push batch size))

  The push batch size is 4 x `I2SIG_PUSH_CONCURRENCY` (ADR 0035) and the
  in-flight bound is `I2SIG_DELIVERY_INFLIGHT_MAX` floored at one batch
  (#336). With the default bound of 256, concurrency 8 gives K=8, 14 gives
  K=4, 16 gives K=4, and 32 gives K=2. `I2SIG_PUSH_CONCURRENCY=1` gives K=1,
  which keeps the ADR 0040 ordering knob serial. Each batch takes its own
  slice of the in-flight set before it is sent, so K batches together never
  hold more than the bound.
- **Push failure.** When one batch fails, the runner stops dispatching, lets
  the other in-flight batches finish and applies their acks, and then enters
  the existing T1 recovery path for the first failure. The failed and
  never-sent JTIs were handed back to the store, so backfill redelivers them
  after recovery resumes the stream.
- **SSTP.** The single second-push slot is now a counter bounded by
  `I2SIG_SSTP_PUSH_INFLIGHT` (K; default = in-flight bound / backfill batch,
  clamped to 1..4, which is 2 with the defaults). Each second push draws a
  disjoint claim from `ClaimOutbound`, so no SET rides two of them, and its
  acks coalesce on the pair's acker (#336). Each second push still carries
  `returnEvents=false` and no `Ack`, so the wire exchange is unchanged.
  `I2SIG_SSTP_PUSH_INFLIGHT=1` is the Q7.2 single slot.

No new metric is added. `goSignals_router_delivery_inflight` now shows up to
K batches' worth of JTIs per stream, and `goSignals_router_delivery_ack_batch_size`
shows how many of those batches each ack write coalesced.

## Tests

- `internal/eventRouter/push_pipeline_test.go`
    - `TestPushInFlightBatches_Formula`: the K formula table.
    - `TestPushPipeline_KBatchesInFlight`: at concurrency 2 (K=2), more than
      one pool's worth of POSTs is on the wire, never more than K pools, and
      every SET is delivered exactly once.
    - `TestPushPipeline_ConcurrencyOneKeepsArrivalOrder`: at concurrency 1,
      one POST at a time and the receiver's arrival order equals the store's
      buffer order (ADR 0040).
    - `TestPushPipeline_OneFailedBatchRecoversAndTheRestRedeliver`: a 5xx in
      one of two in-flight batches enters recovery,
      `push_recovery_duration_seconds` is observed, the stream returns to
      `enabled`, and every SET, including the failed one, is delivered.
- `internal/eventRouter/sstp_push_inflight_test.go`: the
  `I2SIG_SSTP_PUSH_INFLIGHT` default, override and invalid value, and the
  per-pair slot counter bounded by K.
- `internal/server/sstp_second_push_feedback_test.go`
    - `TestPushWhilePollHeld_KSecondPushesInFlight`: at K=2, two second pushes
      are on the wire at once, a third is turned away, the claims are
      disjoint, and every SET is acked. Each request is checked for
      `returnEvents=false` and no `Ack`.
    - `TestPushWhilePollHeld_KOneIsTheSingleSlot`: K=1 is the single slot.
- `internal/server/sstp_pair_e2e_test.go`
  `TestSstpWireShape_UnchangedByKInFlight`: with nothing queued, a
  `returnImmediately=true` cycle and a `returnEvents=false` second push each
  return an empty 200 promptly, without holding the long-poll.

## Live measurement: 5000 events, 16 clients

Setup:

- The dev stack (`docker-compose-dev.yml`, Mongo 8.0.13 replica set) on a single
  laptop host, 14 processors visible to the containers, so push
  concurrency is 14, the push batch is 56 and default K is 4.
- Both arms ran the #339 build. The "K=1" arm pins the pre-#339 behaviour
  with `I2SIG_DELIVERY_INFLIGHT_MAX=1` (floored to one batch, so K=1) and
  `I2SIG_SSTP_PUSH_INFLIGHT=1`, set through a compose override on
  goSignals1, goSignals2 and goSsfServer. The "default" arm is the stack with
  no override (push K=4, SSTP K=2).
- `make dev-bench BENCH_E2E_ARGS="--mix push --issuer=https://bench339.example.com"`
  and the same with `--mix sstp`. There were two runs per arm and mix. A fresh
  issuer was used because the stack's stored `bench.example.com` key no
  longer matched `bin/bench/bench.example.com.pem` (see
  [e2e-benchmark.md](e2e-benchmark.md)).

Results:

| Mix | Arm | Ingest ev/s | Ingest p50 | Drain after ingest | Delivered ev/s (e2e) |
|------|---------|-------------|-----------|--------------------|----------------------|
| push | K=1 | 1025, 978 | 14.3, 15.1 ms | 2.54, 2.54 s | 674, 654 |
| push | default (K=4) | 714, 724 | 20.8, 20.4 ms | 0.51, 0.51 s | 665, 674 |
| sstp | K=1 | 1048, 1012 | 12.4, 13.6 ms | 1.02, 1.02 s | 864, 840 |
| sstp | default (K=2) | 902, 887 | 16.3, 16.6 ms | 0.51, 0.52 s | 825, 812 |

What this shows:

- **Delivery keeps up with ingest.** At K=1, push was still delivering 2.5 s
  after ingest finished. At the default K it finished about 0.5 s after
  ingest, which is the bench's polling interval, so the delivery tail is
  about 5 times shorter. SSTP's tail halved.
- **End-to-end throughput did not improve on this stack.** Delivered SETs/s
  are flat for push and about 4% lower for SSTP, because ingest slowed by
  about 30% (push) and 13% (SSTP) at the same time. Both nodes, the
  receivers and the Mongo replica set share one laptop's processors, so the
  faster delivery took CPU from ingest. This is the trade ADR 0037 measured
  for push concurrency, and on this single-host stack it cancels the gain.
  The benefit is expected where delivery is bound by the round trip to a
  remote receiver and not by shared CPU. That has not been measured here.
- To favour ingest on a CPU-bound host, pin `I2SIG_DELIVERY_INFLIGHT_MAX`
  down to one or two push batches, or set `I2SIG_SSTP_PUSH_INFLIGHT=1`.

The raw results are `bin/bench/bench-20260928T2329*.json`,
`bench-20260928T2330*.json` and `bench-20260928T2331*.json` (not committed).

## Reproducing

```bash
# K=1 arm: pin both transports to one batch in flight
cat > /tmp/k1.yml <<'YML'
services:
    goSignals1:
        environment:
            - I2SIG_DELIVERY_INFLIGHT_MAX=1
            - I2SIG_SSTP_PUSH_INFLIGHT=1
    goSignals2:
        environment:
            - I2SIG_DELIVERY_INFLIGHT_MAX=1
            - I2SIG_SSTP_PUSH_INFLIGHT=1
    goSsfServer:
        environment:
            - I2SIG_DELIVERY_INFLIGHT_MAX=1
            - I2SIG_SSTP_PUSH_INFLIGHT=1
YML
docker compose -f docker-compose-dev.yml -f /tmp/k1.yml \
    up -d --no-deps --force-recreate goSignals1 goSignals2 goSsfServer
make dev-bench BENCH_E2E_ARGS="--mix push --issuer=https://bench339.example.com"
make dev-bench BENCH_E2E_ARGS="--mix sstp --issuer=https://bench339.example.com"

# default arm
docker compose -f docker-compose-dev.yml \
    up -d --no-deps --force-recreate goSignals1 goSignals2 goSsfServer
make dev-bench BENCH_E2E_ARGS="--mix push --issuer=https://bench339.example.com"
make dev-bench BENCH_E2E_ARGS="--mix sstp --issuer=https://bench339.example.com"
```

The resolved K is logged at startup:
`Delivery pipelining resolved (#339, ADR 0044) pushInFlightBatches=... I2SIG_SSTP_PUSH_INFLIGHT=...`.
