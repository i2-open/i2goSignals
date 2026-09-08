<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 36. Outbound SET batches are assembled from one read and signed by a worker pool

Date: 2026-09-08

## Status

Accepted (GH PR #283).

## Context

After ADR 0035 lifted push to about 400 ev/s per stream, poll and SSTP were
the slowest legs of the end-to-end benchmark (`docs/perf/e2e-benchmark.md`)
at roughly 300 ev/s. A CPU profile of the transmitter during a poll-only run
put 45% of its time in `rsa.SignPKCS1v15` under `PollStreamHandler`.

The handler served a poll by walking the batch's JTIs in series on the HTTP
handler goroutine: one `FindByJTI` round trip and one RS256 signature per
SET. A signature is about a millisecond of CPU, so a response was bounded by
one core's signing rate no matter how many cores the node had, and a larger
`maxEvents` only made each response take proportionally longer. SSTP's
outbound legs (`buildSstpOutboundSets` on the responder, the dialer's
resolve-and-sign loop on the initiator) are separate copies of the same
serial shape, which is why all three legs sat at the same number. The poll
handler was converted first; the two SSTP legs were converted in the next
commit once the poll-only benchmark confirmed the lift, and this record
covers all three.

Two things were considered and rejected:

- **Parallel polls on one stream.** The poll buffer keeps a SET until its
  `jti` is acked, and only a poll carrying acks removes anything. A second
  concurrent poll without acks receives the same un-acked batch again, which
  is correct under RFC 8936 §2.4 but pure duplicate work for both sides. Poll
  is an ack-then-fetch cycle per stream; the parallelism has to live inside
  one response.
- **Re-using `I2SIG_PUSH_CONCURRENCY`.** That knob sizes HTTP requests in
  flight to a receiver. Signing is CPU-bound, so its natural size is the
  core count, not a transport limit.

## Decision

1. **One read per message.** The batch's records are fetched with one
   `GetEventRecords` (`FindByJTIs`) instead of one `FindByJTI` per SET, on
   all three legs: `assemblePollResponse` for poll, `buildSstpOutboundSets`
   for the SSTP responder, and `resolveSstpEventsByJti` for the SSTP
   initiator. Poll's subject-filter discards are acked together in one
   `AckEvents` rather than one at a time.
2. **One signing worker pool.** `eventRouter.SignSets` re-signs a batch
   across `I2SIG_SIGN_CONCURRENCY` workers, default `GOMAXPROCS`, and returns
   the results in input order. Each record is a distinct copy from the DAO
   read and the signer is read-only after precompute, so the workers share
   nothing. All three legs call it; the dialer reaches it through
   `SstpOutbound.SignConcurrency()` so the knob is resolved once, in the
   router. Forward-mode streams return the stored SET and never enter the
   pool. The knob is separate from `I2SIG_PUSH_CONCURRENCY` because that one
   sizes HTTP requests in flight, not CPU work.
3. **Per-leg contracts are unchanged.** Poll and the SSTP responder serve the
   same JTIs for the same request, skip a JTI whose record has been deleted,
   and leave un-acked SETs in the buffer; a SET that fails to sign is omitted
   from that message (instead of being returned as an empty string) and stays
   pending. The SSTP initiator keeps AC 5 of PRD #49: a signing failure
   halts the dial cycle, reporting the first failed JTI in batch order.
4. **The memory DAO's `FindByJTIs` reloads `Original` from disk** the way
   `FindByJTI` already did. With disk persistence the in-memory record drops
   `Original` after insert, so the batched read had been returning empty
   forward-mode SETs on the memory provider.

## Consequences

- **Throughput scales with cores.** A node with N cores can sign roughly N
  times as many SETs per second per stream. In the end-to-end benchmark the
  poll leg went from 327 to 692 ev/s and became ingest-bound; the SSTP
  figures are in PR #283.
- **`maxEvents` and the SSTP batch become useful.** A larger batch now
  amortises one read and one round trip over more SETs instead of
  lengthening a serial loop.
- **CPU spikes are burstier.** One large message can occupy every core for
  the duration of its signing. `I2SIG_SIGN_CONCURRENCY=1` restores serial
  signing while keeping the batched read and ack.
- **Tests.** `SignSets` is a pure helper over an injected sign function, so
  its fan-out and ordering are tested without a signer. End-to-end tests
  cover a whole batch served by one poll and by one SSTP responder response
  (including the deleted-JTI skip), the initiator's claim-order resolve and
  first-failure halt, the batched poll discard through the existing
  subject-filter cases, and the memory DAO's disk reload.
