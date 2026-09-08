<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 35. Push delivery runs a per-stream worker pool over batched reads and acks

Date: 2026-09-08

## Status

Accepted (GH PR #283).

## Context

RFC 8935 push delivery was the slowest leg in the end-to-end benchmark
(`docs/perf/e2e-benchmark.md`): about 100 ev/s per stream once the pooled
transport landed, against 250 to 300 ev/s for poll and SSTP after their ack
chains were batched. The push loop popped one JTI at a time and ran it end to
end on the lease holder's single goroutine: one Mongo read for the record, the
subject filter, sign and POST, wait for the 202, then a three-round-trip ack.
Four serial Mongo round trips plus one HTTP round trip per event is the whole
budget behind that number.

RFC 8935 is one SET per POST and the 202 response is that SET's
acknowledgement. The RFC says nothing about how many POSTs a transmitter may
have open to a receiver at once.

## Decision

1. **A worker pool per push stream.** The lease holder keeps
   `I2SIG_PUSH_CONCURRENCY` (default 5) POSTs in flight at once through the
   `PushDelivery` seam. Each worker runs a complete request/response exchange
   and returns its connection to the shared pool before taking the next SET;
   nothing is held open across a batch. The pooled transport already allows 64
   idle connections per host, so the pool does not re-handshake.
2. **Batched reads and acks around the pool.** One loop iteration drains up to
   4x the concurrency of buffered JTIs, fetches their records with one
   `GetEventRecords`, applies the subject filter, runs the pool, then acks every
   202 and every filtered-out discard with one `AckEvents`. A quiet stream
   yields a batch of one and behaves exactly as the serial loop did.
3. **Failure handling is unchanged in kind.** On the first non-Accepted
   classification the pool stops taking new work; pushes already in flight run
   to completion and their 202s are acked. The first failure in batch order is
   handed to the existing T1 `dispatchPushFailure` (rate-limit sleep, disable,
   or recovery mode). Failed and never-dispatched JTIs are not acked, stay in
   the pending list, and come back through backfill once the buffer drains,
   which is the contract a serial failure already had.
4. **Key rotation.** If the seam's `jws_signature_failed` rotate-and-retry
   fires inside a batch, the rotated key from that outcome becomes the next
   batch's key. Workers that raced with the rotation on the old key either
   succeed or rotate again through the same reload path.

## Consequences

- **Ordering.** Delivery order inside a batch is not buffer order. Neither
  RFC 8935 nor SSF promises ordering, and receivers must dedupe on `jti`, so
  this is within the contract; it is documented on the environment variable.
- **Duplicate window.** The delivered mark moves from "after this SET's 202"
  to "after the batch". A crash mid-batch resends up to the batch size of SETs
  the receiver already accepted. Receivers dedupe on `jti`; the window is
  bounded by 4x the concurrency, not by the backfill batch.
- **Receiver load.** A receiver now sees up to five concurrent POSTs per
  transmitter stream. A receiver that answers 429 or 503 with `Retry-After`
  is honoured exactly as before; the remaining in-flight and undispatched SETs
  wait for backfill. `I2SIG_PUSH_CONCURRENCY=1` restores serial POSTs while
  keeping the batched reads and acks.
- **Tests.** `prepareAndSendEvent` remains as a one-element wrapper over the
  batch path, so the existing single-push tests exercise the same code.
