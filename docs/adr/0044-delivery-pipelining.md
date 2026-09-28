<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 44. Delivery keeps K batches in flight per stream

Date: 2026-09-28

## Status

Accepted (community #336, #337, #338, #339; spec-111 Stage 2).

This ADR amends ADR 0036 (parallel polls) and restates ADR 0040's ordering
knob under pipelining.

## Context

Before spec-111 Stage 2, each delivery leg had one exchange with its peer at
a time:

- **Push** (RFC 8935). A stream drained one batch of up to 4 x
  `I2SIG_PUSH_CONCURRENCY` JTIs, sent it through a worker pool, waited for
  every POST to finish, wrote the ack and only then drained the next batch
  (ADR 0035, ADR 0037).
- **Poll** (RFC 8936). ADR 0036 assembled a response from one read, but
  concurrent polls of one stream each read the same pending head, so two
  pollers re-received the same batch. A poll receiver sent one poll at a
  time.
- **SSTP.** The initiator held one long-poll and had one push-while-poll-held
  slot per pair (Q7.2).

Every stage of a delivery waited on the round trip of the stage before it.
Stage 2 (#336-#339) takes the waits out one at a time:

- #336 decouples the send from the ack.
- #337 lets concurrent polls take disjoint claims.
- #338 pipelines a poll receiver's polls.
- #339 keeps K batches on the wire per stream.

This ADR records the resulting model and the knobs that bound it.

## Decision

### The model

A delivery runner (a push stream, an SSTP pair, a poll stream on the serving
side or a poll receiver) has a bounded **in-flight set**. It holds the JTIs
taken for sending and not yet acked or handed back. Sends run ahead of acks
up to that bound. A **coalescing acker** (#336) collects completed batches
for up to `I2SIG_ACK_COALESCE_WINDOW` and writes their acks as one fenced
store write (one trip, #335).

**Push: K batches.** The push runner dispatches a batch whenever fewer than K
are outstanding. Each batch runs its own worker pool and reports on a result
channel.

    K = max(1, min(pc, floor(inFlightMax / pushBatch)))

    pc          = I2SIG_PUSH_CONCURRENCY (derived: GOMAXPROCS clamped 8..32, ADR 0037)
    pushBatch   = 4 x pc (ADR 0035)
    inFlightMax = max(I2SIG_DELIVERY_INFLIGHT_MAX, pushBatch)

With the default bound of 256, pc 8 gives K=8, 14 and 16 give K=4, and 32
gives K=2. Capping K at pc keeps a small pool from opening more batches than
it has workers for. The derivation keeps K x pushBatch at or below the bound,
so the in-flight set, not K, is what limits exposure. The resolved K is
logged at startup ("Delivery pipelining resolved").

When a batch fails, the runner stops dispatching. It lets the other K-1
batches finish and applies their acks through the acker ("quiesce"), then
enters the existing T1/T2 recovery path for the first failure.
`push_recovery_duration_seconds` is observed as before. The failed JTIs and
any JTIs never sent go back to the store, and backfill redelivers them when
recovery resumes the stream. So one failed batch does not lose the others'
acks, and recovery never races a batch still on the wire.

**SSTP: K second pushes.** The pair's single push-while-poll-held slot
becomes a counter bounded by `I2SIG_SSTP_PUSH_INFLIGHT`. Each second push
draws a disjoint claim from `ClaimOutbound`, so no SET rides two of them. Its
acks coalesce on the pair's acker. The wire exchange is unchanged: a second
push carries `returnEvents=false` and no `Ack`, and the held long-poll still
carries acks and `returnImmediately` as before. The default K is the number
of full claims (`I2SIG_PUSH_BACKFILL_BATCH`) that fit in the in-flight set,
clamped to 1..4. That is 256 / 100 = 2 with the defaults. The cap of 4 exists
because the batches share one transport, so past a few the link, not the
round trip, is the limit.

**Poll (serving side): disjoint claims (#337).** A poll response claims the
SETs it returns for `I2SIG_POLL_CLAIM_TTL`, and concurrent polls of one
stream skip claimed SETs. An ack releases a claim. An expired claim makes its
SETs eligible again, so a poller that never acks still gets redelivery. The
request's `returnImmediately` is honoured as before.

**Poll receiver: pipelined polls (#338).** A poll receiver keeps up to
`I2SIG_POLL_PIPELINE_DEPTH` polls outstanding. The acks for one response
ride the next poll.

### Knobs, defaults and exposure

| Knob | Default | Range | Exposure it bounds |
|------|---------|-------|--------------------|
| `I2SIG_DELIVERY_INFLIGHT_MAX` | `256` | floored at one push batch | JTIs sent but not yet acked, per push stream or SSTP pair. A crash or lost lease redelivers up to this many SETs per stream that the receiver may already hold, which it drops on `jti` dedup. A clean stop flushes queued acks and redelivers nothing already accepted. |
| `I2SIG_ACK_COALESCE_WINDOW` | `5ms` | `0` = ack each batch inline | How long a completed batch's ack may wait. It is written early at half the in-flight bound. A stale fencing token refuses the write and the SETs stay pending for the new owner. |
| Push K | derived, see above | 1..pc | K x pushBatch outstanding POSTs' worth of JTIs, never more than the in-flight bound. |
| `I2SIG_SSTP_PUSH_INFLIGHT` (SSTP K) | in-flight / backfill batch, clamped 1..4 (2) | positive integer; an invalid value warns and uses the default | Concurrent second pushes per pair, each at most one claim. `1` is the Q7.2 single slot. |
| `I2SIG_POLL_CLAIM_TTL` | `30s` | `0` disables claims (ADR 0036 behaviour) | How long an unacked poll response hides its SETs from other pollers. It also sets the redelivery delay after a poller dies. |
| `I2SIG_POLL_PIPELINE_DEPTH` | `2` | 1..4 | Outstanding polls per poll receiver. `1` is the serial receiver from before #338. |

Setting every Stage 2 knob to its "off" value (`I2SIG_ACK_COALESCE_WINDOW=0`,
`I2SIG_DELIVERY_INFLIGHT_MAX` at or below one push batch,
`I2SIG_SSTP_PUSH_INFLIGHT=1`, `I2SIG_POLL_PIPELINE_DEPTH=1`,
`I2SIG_POLL_CLAIM_TTL=0`) restores the pre-Stage-2 exchange on every leg.

### Amendment to ADR 0036

ADR 0036 states that parallel polls of one stream re-receive the same batch,
and that receivers must dedup on `jti`. That statement is **superseded**:
with #337's disjoint claims, concurrent polls served by the same node get
disjoint batches while the claims are live. Claims are held in the serving
node's memory only, so polls of one stream served by different nodes can still
overlap. Redelivery otherwise happens only after a claim expires or a node
restarts, and `jti` dedup is still required for those cases (ADR 0038). With
`I2SIG_POLL_CLAIM_TTL=0` the ADR 0036 behaviour returns.

### ADR 0040 under pipelining

ADR 0040's ordering knob still holds. `I2SIG_PUSH_CONCURRENCY=1` gives
pc = 1, so push K = min(1, ...) = 1. A stream then has one batch and one POST
on the wire at a time, in buffer order. The ADR 0040 caveat is unchanged:
this serialises dispatch but does not impose a total order across ingest
batches, so receivers still sort on `jti`. Above 1, K > 1 adds batch-level
interleaving to the in-batch interleaving ADR 0040 already describes, which
does not change push's standing as the weakest leg for order. Poll and SSTP
batches stay atomic, and order is recovered by sorting `jti`. Disjoint claims
and K second pushes mean the batches can arrive in either order, which a
`jti` sort already handles.

## Consequences

- The delivery tail after ingest shrinks. At 5000 events / 16 clients on the
  single-host dev stack (14 processors, push K=4, SSTP K=2), push finished
  about 0.5 s after ingest instead of 2.5 s, and SSTP about 0.5 s instead of
  1.0 s (`docs/perf/k-inflight-339.md`).
- On that single host, end-to-end throughput did not improve. Ingest slowed
  by about 30% (push) and 13% (SSTP), because delivery and ingest share the
  same processors. This is the trade ADR 0037 records for push concurrency.
  The gain is expected where delivery is bound by the round trip to a remote
  receiver, and that has not been measured yet. On a CPU-bound host,
  operators can favour ingest by lowering `I2SIG_DELIVERY_INFLIGHT_MAX` or
  setting `I2SIG_SSTP_PUSH_INFLIGHT=1`.
- No new metric is added. `goSignals_router_delivery_inflight` shows up to K
  batches per stream, and `goSignals_router_delivery_ack_batch_size` shows
  the coalescing.
- The redelivery exposure on a crash or lost lease is bounded by
  `I2SIG_DELIVERY_INFLIGHT_MAX` per stream, not by K.
