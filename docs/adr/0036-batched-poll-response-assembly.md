<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 36. Poll responses are assembled from one read and signed by a worker pool

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
serial shape, which is why all three legs sat at the same number.

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

1. **One read per response.** The batch's records are fetched with one
   `GetEventRecords` (`FindByJTIs`) instead of one `FindByJTI` per SET.
   Subject-filter discards are acked together in one `AckEvents` rather than
   one at a time.
2. **A signing worker pool.** The surviving records are re-signed across
   `I2SIG_POLL_SIGN_CONCURRENCY` workers, default `GOMAXPROCS`. Each record is
   a distinct copy from the DAO read and the signer is read-only after
   precompute, so the workers share nothing; results are collected in input
   order. Forward-mode streams return the stored JWS and never enter the pool.
3. **The response contract is unchanged.** The same JTIs are served for the
   same request, a JTI whose record has been deleted is still skipped, and
   un-acked SETs stay in the buffer for the next poll. A SET that fails to
   sign is now omitted from the response instead of being returned as an
   empty string; it stays pending exactly as before.

## Consequences

- **Throughput scales with cores.** A node with N cores can sign roughly N
  times as many SETs per second per stream. In the end-to-end benchmark the
  poll leg went from 327 to 692 ev/s and became ingest-bound.
- **SSTP is untouched.** Both SSTP outbound legs keep their own serial
  read-and-sign loops and stayed at about 300 ev/s. Routing them through
  `signPollSets` and a batched read is the natural follow-up.
- **`maxEvents` becomes useful.** A larger poll batch now amortises one read
  and one round trip over more SETs instead of lengthening a serial loop.
- **CPU spikes are burstier.** One large poll can occupy every core for the
  duration of its signing. `I2SIG_POLL_SIGN_CONCURRENCY=1` restores serial
  signing while keeping the batched read and ack.
- **Tests.** `signPollSets` is a pure helper over an injected sign function,
  so its fan-out and ordering are tested without a signer. The end-to-end
  poll tests cover the batched read, the deleted-JTI skip, and the batched
  discard through the existing subject-filter cases.
