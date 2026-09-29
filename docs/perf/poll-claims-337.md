# Disjoint poll claims (#337, spec-111 Stage 2)

This page describes what #337 changes on the RFC 8936 poll path and how to
measure it. The end-to-end figures are **not yet recorded**; see
[End to end](#end-to-end-5000-events-2-outstanding-polls-not-run).

## What changed

Before #337, `EventPollBuffer.GetEvents` returned the first `maxEvents` pending
JTIs to every caller. Two polls outstanding on one stream therefore received
the same unacked batch (ADR 0036), so a pipelined poll client gained nothing
from its second poll: it re-received, re-verified and re-acked the same SETs.

After #337 a poll response claims the JTIs it returns:

- **Claim token and expiry.** `ClaimEvents` records each returned JTI with the
  poll's random claim token and an expiry `I2SIG_POLL_CLAIM_TTL` ahead
  (default 30s). An overlapping poll skips claimed JTIs and returns the next
  disjoint slice, still in jti order (ADR 0040).
- **Release.** An ack carried by a later poll removes the JTI and its claim.
  A poll that fails to sign its response releases its claim at once, so the
  SETs are not held back for a whole TTL.
- **Expiry.** A claim not acked within the TTL lapses and the JTI is served
  again (at-least-once, ADR 0038). A long poll that finds only claimed JTIs
  waits for a new event or the next claim expiry, whichever comes first.
- **`returnImmediately=true`** returns at once, with an empty batch if every
  pending JTI is claimed.

Claims are held only in the node's in-memory poll buffer: there is no schema
change, and a node restart forgets them, so the restarted node serves the whole
pending set again. The new gauge `goSignals_router_poll_claimed_inflight`
shows how many SETs each stream has claimed.

`I2SIG_POLL_CLAIM_TTL=0` takes no claims. That restores the pre-#337
behaviour and is the "before" side of the measurement below.

## End to end: 5000 events, 2 outstanding polls (not run)

The acceptance measurement uses a pipelined poll client that keeps two polls
outstanding on one stream (`returnImmediately=false`, `maxEvents=100`, and the
previous response's JTIs carried as `ack`). Nothing in the repo implements
such a client yet: `cmd/goSignals` and the poll receiver issue one poll at a
time. The run below has therefore not been done. Recording it needs that
client, or a small harness, first.

Procedure, once a two-poll client exists:

1. Bring up the demo cluster (`make run`) with a poll-publisher stream.
2. **Before:** set `I2SIG_POLL_CLAIM_TTL=0` on the transmitter and restart it.
3. Publish 5000 SETs to the stream, then start the client with two
   outstanding polls. Time from the first poll to the last acked SET, and count
   the SETs received in total (duplicates included).
4. **After:** unset `I2SIG_POLL_CLAIM_TTL` (30s default), restart, and repeat.
5. Record for each side: wall time, SETs per second, SETs received and
   duplicate SETs, and `goSignals_router_poll_claimed_inflight` over the run.

What to expect: before, each pair of polls returns the same batch, so the
client receives about twice as many SETs as it acks, and the second poll adds
no throughput. After, the two polls return disjoint batches, there are no
duplicates, and throughput depends on the client's verify and ack rate rather
than on a single poll's round trip.

| Run | `I2SIG_POLL_CLAIM_TTL` | Wall time | SETs/s | SETs received | Duplicates |
|-----|------------------------|-----------|--------|---------------|------------|
| Before | `0` | not run | not run | not run | not run |
| After | `30s` | not run | not run | not run | not run |

## Tests

- `internal/eventRouter/buffer/poll_claim_test.go` (synctest, fake clock)
  covers: disjoint overlapping claims in jti order, expiry redelivery, release
  on ack and by claim token (the sign-failure path), `ttl=0`, long-poll wake on claim expiry, and
  `returnImmediately`.
- `internal/eventRouter/poll_claim_router_test.go` covers, through
  `PollStreamHandler`: two concurrent long polls with `maxEvents=5` over 10
  pending SETs get disjoint sets; a poll after the TTL gets the unacked set
  again; acked SETs are never served again; and a restarted router over the
  same store serves the claimed SETs.
