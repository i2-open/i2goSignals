# Send/ack decoupling (#336, spec-111 Stage 2)

This page describes what #336 changes on the delivery path and how to measure
it. The end-to-end figures are **not yet recorded**; see
[End to end](#end-to-end-5000-events-16-clients-not-run).

## What changed

Before #336 a push runner sent one batch (up to 4x `I2SIG_PUSH_CONCURRENCY`
SETs), then wrote that batch's ack with `AckEvents`, and only then drained the
next batch. The ack write (one `bulkWrite` since #335) sat on the send path:
every batch paid one store round trip before the next POST could start. The
SSTP transmitter did the same after each peer ack.

After #336 each delivery runner (push stream or SSTP pair) owns an acker:

- **A bounded in-flight set.** A JTI joins when it is taken for sending and
  leaves once its ack is written or it is handed back unacked. The bound is
  `I2SIG_DELIVERY_INFLIGHT_MAX` (default 256, never below one push batch). When
  the set is full the runner waits for an ack write; that is the back-pressure.
- **A coalescing ack queue.** A completed batch queues its acked JTIs and the
  runner goes straight on to the next batch. One goroutine writes the queue as
  a single `AckEvents` every `I2SIG_ACK_COALESCE_WINDOW` (default 5ms), or
  sooner once the queue holds half the bound.
- **Backfill dedup.** A SET sent and awaiting its ack is still pending in the
  store; backfill skips JTIs in the in-flight set so it is not resent.

`I2SIG_ACK_COALESCE_WINDOW=0` writes each ack inline, which is the pre-#336
behaviour and the "before" side of the measurement below.

The at-least-once contract is unchanged (ADR 0038). Only a receiver-accepted
SET is acked. A SET sent but not yet acked is still pending, so a crash or a
lost lease redelivers it; the most a crash can redeliver per stream grows from
one push batch to `I2SIG_DELIVERY_INFLIGHT_MAX`. A clean stop or a stream
restart flushes the queue first. A stale fencing token (#334) refuses the
coalesced write: the SETs stay pending for the new lease owner and the push
runner stops.

Raising the number of batches on the wire (K > 1) is #339 and is not part of
this change: the runner still has one batch of POSTs in flight at a time. The
gain here is that the ack write overlaps the next batch instead of preceding
it, and that N batches cost one ack write instead of N.

## Tests

In `internal/eventRouter/acker_test.go`:

| Test | Shows |
|---|---|
| `TestAcker_ZeroWindowAcksInline` | window 0 writes each completion at once |
| `TestAcker_CoalescesWithinWindow` | several completions become one write |
| `TestAcker_SizeCapDrainsEarly` | a full queue is written before the window ends |
| `TestAcker_BoundBlocksAndDedups` | the bound blocks, duplicates are dropped, ctx cancels the wait |
| `TestAcker_StaleFenceFences` | a stale fence stops the acker and later reservations |
| `TestPushAckCoalescing_RestartFlushesQueuedAcksNoResend` | queued acks are written on restart; nothing is resent |
| `TestPushAckCoalescing_StaleFenceLeavesSentSetsPending` | after a takeover the sent SETs stay pending |
| `TestSstpAckCoalescing_ClaimHeldUntilAckWritten` | an SSTP SET keeps its claim until its ack is written |

## Metrics

- `goSignals_router_delivery_inflight{stream_id,transport}`: the in-flight set
  size. A stream sitting at the bound is waiting on ack writes.
- `goSignals_router_delivery_ack_batch_size{transport}`: JTIs per coalesced
  write. Its mean over the push batch size is the number of store writes saved
  per write.

On the store side, the `AckDelivered` count in
`goSignals_dao_op_duration_seconds` should fall for the same delivered volume,
while its `goSignals_dao_batch_size` rises.

## End to end (5000 events, 16 clients): not run

The `goSignalsBench` end-to-end run at 5000 events and 16 clients was **not**
done for this change. As for #335, the dev containers compile the mounted
source tree when they start, and the dev stack is shared, so a run would mean
restarting it under other work. Because the "before" side is a setting, not a
revert, only one restart is needed:

1. Restart the stack on this tree with `I2SIG_ACK_COALESCE_WINDOW=0` set on
   `goSignals1`, `goSignals2` and `goSsfServer` in `docker-compose-dev.yml`:
   `docker compose -f docker-compose-dev.yml up -d goSignals1 goSignals2 goSsfServer`.
2. Run the command below three times ("before").
3. Remove the setting (the 5ms default), restart the same way, and run it
   three more times ("after"). Interleave further pairs if the runs overlap.

```bash
make dev-bench BENCH_E2E_ARGS="--issuer=https://bench336<side><run>.example.com \
    --mongo-uri='mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?replicaSet=dbrs&authSource=admin' \
    --label=ack336-<side>-c16-r<run>"
```

Record push delivery ev/s and the `delivery_ack_batch_size` mean for each run
in this page and in [e2e-history.md](e2e-history.md). The push gain is bounded
by the ack write's share of a batch cycle; with the single-batch window (#339
not yet done) the receiver's POST latency still dominates a slow receiver.
