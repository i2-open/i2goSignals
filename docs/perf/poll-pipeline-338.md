# Pipelined poll receiver (#338, spec-111 Stage 2)

This page describes what #338 changes in the RFC 8936 poll receiver and how it
was measured. The in-process pair test has been run; the live docker-stack run
has **not** been done (see [Live measurement](#live-measurement-not-run)).

## What changed

Before #338, `runPollLoop` had one poll outstanding at a time. It sent a poll,
waited for the whole response, verified and ingested every SET, and only then
sent the next poll carrying the acks. Every batch paid one full round trip to
the transmitter plus the local ingest time.

After #338 the loop is a dispatcher that keeps up to
`I2SIG_POLL_PIPELINE_DEPTH` polls outstanding (default 2, range 1 to 4):

- **Issue.** A new poll is sent when fewer than `depth` polls are
  outstanding and either the latest poll has begun to receive a 200 response
  or acks are waiting to be sent. An idle stream therefore holds one long-poll
  open, plus at most `depth - 1` more that carry acks. Each poll runs
  `executePoll` on its own goroutine.
- **Acks.** The dispatcher owns the ack and `setErrs` lists. When a poll's
  SETs have been ingested, its acks are queued and ride the next poll, which
  is sent at once rather than after an idle long-poll returns. A SET whose
  ingest failed is not acked, so the transmitter sends it again (ADR 0038).
- **Non-200 responses** (401, 403, 503 and so on) never release a further
  poll. The dispatcher waits for the outstanding polls, then applies the
  existing retry policy once, so the auth retry limits count attempts as they
  did before.
- **Failure.** A failed poll hands back the acks and `setErrs` it carried, so
  they ride a later poll. The dispatcher lets the other polls finish, then
  applies the existing retry and backoff policy to the first error.
- **Stop and lease loss.** Cancelling the loop context cancels every
  outstanding poll. A response already received is still stored, because
  ingest runs on `context.WithoutCancel`; only its acks are lost, and the
  transmitter redelivers those SETs, where JTI dedup absorbs them (ADR 0017).
- **Depth 1** is the pre-#338 loop: one poll at a time, with acks on the next
  poll.
- Values above 4 are clamped to 4 with a WARN. Values below 1, or values that
  are not numbers, fall back to the default with a WARN.

Overlapping polls rely on #337's disjoint claims (ADR 0036, ADR 0040): without
them, two outstanding polls would receive the same batch.

The new gauge `goSignals_router_poll_receiver_outstanding{stream_id}` shows how
many polls each receiver stream has outstanding.

## Pair test: 5000 SETs, two servers

`internal/server/poll_pipeline_pair_test.go` (`TestPollPipelinePair_ExactlyOnce`,
skipped under `-short`) starts two goSignals servers in one process on loopback
HTTP, each on the memory provider:

- **Server A** has a forwarding ingress stream and an RFC 8936 poll transmit
  stream. The test loads 5000 SETs onto it, signed with A's issuer key.
- **Server B** has a poll receiver stream pointed at A through a proxy that
  holds each request for 10 ms. This makes each poll round-trip bound, as a
  real receiver-to-transmitter link is. B verifies the SETs against A's JWKS.
  The receiver uses `maxEvents=100` and `returnImmediately=true`.

At each depth the test asserts exactly-once delivery:

- B's `eventsIn` counter, which counts only first-time stores, equals 5000.
- A's `eventsOut` counter, which counts acks, equals 5000.
- All 5000 JTIs are in B's event store.

Throughput is reported, not asserted.

Results (Apple silicon laptop, no `-race`, three runs, SETs/s):

| Depth | Run 1 | Run 2 | Run 3 | Stored once | Acked once |
|-------|-------|-------|-------|-------------|------------|
| 1 (before) | 2335 | 2688 | 2658 | 5000 | 5000 |
| 2 (default) | 3786 | 2450 | 4382 | 5000 | 5000 |
| 4 | 2551 | 5315 | 4383 | 5000 | 5000 |

Depth 1 is steady at about 2300 to 2700 SETs/s: every batch waits one full
round trip plus its ingest. Depths 2 and 4 were faster in most runs, up to
about 1.6 to 2 times depth 1, because a second poll hides the round trip
behind the first poll's verify and ingest. They also vary much more from run
to run. Both servers share one process and one memory store, so extra polls
contend for the same CPU and locks as well as hiding latency.

In an earlier run without the 10 ms proxy (pure loopback), the three depths
were within noise of each other: 4030, 3123 and 4625 SETs/s for depths 1, 2
and 4. With no round trip
to hide, pipelining has nothing to gain, and run-to-run variance dominates.

These are single runs on a laptop, not a controlled benchmark. They show the
direction, not a figure to plan capacity from.

## Live measurement (not run)

The shared docker dev stack was running other work, so the receiver node was
not restarted with different depths. To measure on the stack with
`cmd/goSignalsBench`'s poll leg:

1. Bring up the stack (`make run`, or `make dev-up`).
2. **Before:** set `I2SIG_POLL_PIPELINE_DEPTH=1` on goSignals2 (the receiver
   node) and restart it.
3. Run the poll leg only:

    ```bash
    go run ./cmd/goSignalsBench --events 5000 --mix poll \
        --label "poll depth=1 (#338 before)" --workers "I2SIG_POLL_PIPELINE_DEPTH=1" \
        --history docs/perf/e2e-history.md
    ```

4. **After:** set `I2SIG_POLL_PIPELINE_DEPTH=2` (or unset it), restart
   goSignals2, and rerun with the label and workers changed to match. Repeat at
   `4`.
5. For each run, record:
    - wall time and SETs per second;
    - `goSignals_router_poll_receiver_outstanding` over the run (it should sit
      at the depth while a backlog remains);
    - goSignals1's `goSignals_router_poll_claimed_inflight`.

Expect the gain to grow with the real round trip between the nodes. On one
docker host the round trip is small, so the gain is likely to be small too.

## Tests

- `internal/server/poll_pipeline_test.go` drives `runPollLoop` against a fake
  RFC 8936 transmitter. It covers:
    - depth 1 keeps one poll at a time;
    - depths 2 and 4 reach exactly `depth` outstanding polls;
    - a failed ingest is not acked, and the SET is acked after its
      redelivery succeeds (depths 1 and 2);
    - stop cancels the outstanding polls and removes the gauge series.
- `internal/server/poll_envcompat_test.go`
  (`TestLoadPollConfig_PipelineDepth`) covers the default, the 1 to 4 range,
  and clamping or fallback with a WARN.
- `internal/server/poll_pipeline_pair_test.go` is the two-server test above.
