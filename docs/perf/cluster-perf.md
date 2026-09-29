# Two-node cluster: throughput and coordination findings

Measured 2026-09-29 on the benchmark stack (`docker-compose-benchmark.yml`
with `--profile cluster`, so `goSignals1` and `goSignals1b` share cluster
`bench` and the three-member Mongo replica set). Same host and images as the
single-node `algs-*-c128` rows in [e2e-history.md](e2e-history.md). The
bench alternates its pushers between the two nodes (`--gs1b`), so both nodes
ingest for every stream while only one node (the lease holder) delivers.

## Throughput

20000 events, 128 clients, three receivers (PUSH, POLL, SSTP initiator).
Ingest ev/s is the acknowledged rate across both nodes. Delivery columns are
the drain time after the last acknowledgement.

| Run | Nodes | Durability | Alg | Ingest ev/s | p50 / p99 ms | Split gs1 / gs1b | PUSH drain s | POLL drain s | SSTP |
|---|---|---|---|---|---|---|---|---|---|
| `algs-RS256-c128` | 1 | local | RS256 | 3406 | 37.0 / 69.8 | - | 0.5 | 0.5 | 0.5 s |
| `algs-ES256-c128` | 1 | local | ES256 | 4140 | 30.5 / 61.0 | - | 0.5 | 0.5 | 0.5 s |
| `algs-RS256-majority-c128` | 1 | majority | RS256 | 2714 | 45.4 / 101.3 | - | 0.5 | 0.5 | 0.5 s |
| `bench-stack-c128-20k-majority-es256` | 1 | majority | ES256 | 3480 | 34.7 / 110.7 | - | 0.5 | 0.5 | 0.5 s |
| `cluster-local-RS256-c128` | 2 | local | RS256 | 2510 | 32.9 / 253.3 | 5217 / 14783 | 38.4 | 6.1 | 3706/6666 at 300 s |
| `cluster-local-RS256-c128-run2` | 2 | local | RS256 | 5027 | 21.5 / 76.5 | 7197 / 12803 | 38.5 | 5.6 | 4782/6666 at 90 s |
| `cluster-local-ES256-c128` | 2 | local | ES256 | 5244 | 21.2 / 67.0 | 7675 / 12325 | 40.9 | 4.6 | 4469/6666 at 300 s |
| `cluster-majority-RS256-c128` | 2 | majority | RS256 | 3782 | 29.0 / 91.6 | 7088 / 12912 | 32.4 | 5.1 | 4923/6666 at 300 s |
| `cluster-majority-ES256-c128` | 2 | majority | ES256 | 4635 | 24.9 / 66.3 | 8063 / 11937 | 33.5 | 4.6 | 5011/6666 at 300 s |

The first `cluster-local-RS256-c128` row has a p99 seven times its
neighbours and the most skewed split; it was the first run after the second
node's restart and is kept as an outlier, not a result.

Reading the table:

- **Ingest scales.** A second node adds ingest capacity: every SET is
  verified, stored and fanned out on the node that received it, and ingest
  never consults the lease. Two nodes acknowledge 1.3 to 1.5 times one
  node's rate for the same 128 clients (RS256 local 3406 to 5027, ES256 local 4140 to 5244, majority
  RS256 2714 to 3782, majority ES256 3480 to 4635). The remaining limit is
  the client-side signing and the shared Mongo replica set. The split is
  uneven because the bench alternates workers, not requests, and the
  faster node completes more.
- **Delivery does not scale, and cross-node delivery is slow.** There is
  one delivery loop per stream, on the lease holder. On one node every leg
  drains within 0.5 s of the last acknowledgement. On two nodes the PUSH
  leg needs 32 to 41 s, POLL 4.6 to 6.1 s, and the SSTP leg did not finish
  within the bench's 5 min drain timeout in any of the four runs, in
  `majority` mode as much as in `local`. The cause is defect D: the
  cross-node hand-off delivers about 100 SETs per second for PUSH and about
  100 per long-poll timeout for SSTP.

Rows marked `(defect, see cluster-perf.md)` in `e2e-history.md` are the runs
that exposed defects A and C; their delivery numbers are not cluster
throughput, they are the defect.

## What happens when many clients push to one stream

The question behind these runs: a transmitter opens many parallel
connections to one inbound stream, possibly spread over both nodes. What the
router guarantees, and where it does not.

- **No per-stream ingest lock.** `HandleEvent` verifies the SET, inserts it
  (Mongo with `majority`, or the local WAL), and matches it against every
  outbound stream in the node's in-memory table. Nothing serialises pushers
  on one stream, on one node or across nodes. 128 clients on one stream
  ingest at the same rate as 128 clients on many.
- **Duplicates.** The sparse unique index on `jti` rejects a repeated SET
  at insert (`ErrDuplicateJTI`); the handler returns the RFC 8935 duplicate
  result and the sender's retry is absorbed. In `local` mode the pre-ack
  check is against the node's own unacknowledged buffer only, so a retry
  that lands on the *other* node, or on the same node after the first copy
  drained, is acknowledged a second time and rejected later at drain. That
  is correct for the store (no second copy) but the sender sees two
  successes. A SET that was already delivered and is pushed again to a
  `local`-mode node is redelivered once to ring-fed targets before the
  drain rejects it.
- **Ordering.** Per stream, delivery is by ascending `jti`, which the
  router mints from the wall clock on the ingesting node. With two ingesting
  nodes the order across them is only as good as their clocks (ADR 0040).
  Within one node, the K in-flight push batches can complete out of order at
  the receiver. Neither is a defect against RFC 8935, which promises no
  order, but a receiver that assumes arrival order will see it broken more
  under a cluster than under one node.
- **Wake-ups.** A SET ingested on the non-owning node is announced to the
  owner with one HTTP call on the internal listener, coalesced over 250 ms,
  carrying the stream id but not the JTIs. Success is logged at DEBUG,
  failure at ERROR (`Wake-up call failed`). Whether the call succeeds or
  not, PUSH targets are fed by the 1 s backfill, 100 SETs at a time, and
  SSTP targets stall after a dropped wake (defect D).
- **Leases.** TTL 30 s, heartbeat 10 s. One failed renewal drops the lease
  and the loop stops; the next acquisition attempt is 15 s later, so a
  transient Mongo hiccup costs a stream up to 15 s of delivery with no SET
  lost. The `goSignals_cluster_lease_acquisition_total` counter also counts
  renewals, so a steady rate of about one per stream per 10 s is normal, not
  thrash.
- **Backfill gating.** `backfillPushBuffer` returns early when the owner's
  buffer is non-empty. Under sustained load on the owner, SETs ingested on
  the peer are picked up only when the owner's own buffer drains, and then
  100 per second. The peer's SETs queue behind the owner's for as long as
  the owner stays busy, then trickle. This is part of defect D.

## Defects found

The two-node runs found four problems. None of them is visible on one node.
The bench and the bench compose were changed so the measurements above are
valid; the server-side fixes are proposals, not done.

### A. Peers learn of new streams only every 40 s (#349)

A node loads the stream table at start and refreshes it from the
`backgroundSync` ticker: every 10 s it refreshes state, every fourth tick it
calls `InitializeReceivers` and picks up new streams. A SET that arrives on
the peer before then matches no outbound stream: it is stored, acknowledged
with 202, and never delivered, because no pending marker was written for it.

Measured: the `cluster-local-RS256-c128-unsynced` row delivered exactly
`goSignals1`'s share of the SETs; `goSignals1b`'s share (about half) was
stored and lost to delivery. The bench now waits after creating its streams
until `goSignals1b`'s `/metrics` names them (`-gs1b-sync-timeout`, 90 s
default; observed 9.6 to 36.9 s).

Fix proposal: refresh the table on demand when a SET matches nothing
(plan against the store when the cache is stale), or have the creating node
broadcast stream-created on the internal listener. The ticker stays as the
fallback.

### B. A node advertises its peer's address (#348)

`registerNode` builds the wake-up address from the host of `BASE_URL`, the
port from `I2SIG_CLUSTER_INTERNAL_PORT` (else the main port), always
`http://`. The shipped `docker-compose-cluster.yml` and
`docker-compose-cluster-dev.yml` give both nodes `BASE_URL=https://gosignals1:8888/`
and set no internal port, so both nodes advertise
`http://gosignals1:8888`: the second node names the first, and the scheme
is plain HTTP against a TLS listener. Every wake-up call fails with
`Wake-up call failed`, and cross-node delivery falls back to the 1 s
backfill (PUSH, POLL) or stalls (SSTP, defect D).

Fixed in `docker-compose-benchmark.yml` only: a shared
`I2SIG_CLUSTER_INTERNAL_TOKEN`, `I2SIG_CLUSTER_INTERNAL_PORT=8898`, and a
per-node `BASE_URL` on `goSignals1b`. Verified in `cluster_nodes`
(`http://goSignals1:8898`, `http://goSignals1b:8898`). The shipped cluster
composes still have the defect.

Fix proposal: a per-node advertise address (`I2SIG_CLUSTER_ADVERTISE_URL`,
default derived as today) and a start-up warning when two live nodes
advertise the same address; fix the two shipped cluster composes.

### C. Stream deletion never reaches peers (#350)

`backgroundSync` adds and updates streams; it never removes one. After the
bench deleted its streams, `goSignals1b` kept them, took over the push lease
of a deleted stream 8 s after `goSignals1` deleted it, and in every later
run fanned out the new SETs to the stale streams: thousands of orphan
`pendingEvents` markers per stale stream (4470 to 4877 observed), pushes to
the removed receiver (`RFC8935Error not_found`), `Error updating remote
address ... not found`, and finally a state transition on a stream that no
longer exists. The `cluster-local-RS256-c128-stale-peer-streams` row was
measured in that state: the peer did about twice the fan-out work per SET.
(Its 40 s push drain is defect D, not C; the clean runs show the same.)

Also never cleaned: `cluster_nodes` rows for nodes that are gone, and
`cluster_leases` rows for streams that are gone.

The bench works around it by restarting `goSignals1b` before each two-node
run. That clears its memory; the orphan markers stay in Mongo and are inert.

Fix proposal: `backgroundSync` reconciles against the store (drop what the
store no longer has, release its lease, stop its loop); the deleting node
also broadcasts stream-deleted on the internal listener. A lease or node row
older than a few TTLs is garbage-collected by whoever notices it.

### D. The cross-node hand-off is a signal without a payload (#347)

When the non-owning node ingests a SET for a stream the other node
delivers, it sends the owner a wake-up call carrying only the stream id and
mode, coalesced to one call per stream per 250 ms. On the owner the wake is
a one-slot, non-blocking channel signal (`Wakeup()` drops the signal if the
loop is busy). What the loop then does decides the throughput:

- **PUSH:** a wake, like the 1 s `backfillTicker`, calls
  `backfillPushBuffer`, which returns at once if the owner's buffer holds
  anything and otherwise reads at most `I2SIG_PUSH_BACKFILL_BATCH` (100)
  pending JTIs from Mongo. So the peer's SETs reach the owner at about
  100 per tick plus the few wakes that land while the buffer is empty. The
  bench log shows exactly 500 delivered per 5 s in every two-node run:
  38 to 41 s for 6667 SETs, against 0.5 s on one node. Local ingest is not
  affected because the ingesting node submits its own JTIs straight into
  the buffer.
- **SSTP client:** a wake while the primary long-poll is parked fires one
  bounded second push that claims at most `BackfillBatch` (100) SETs; a
  wake that arrives while the K second-push slots are held is dropped
  (`AcquireSecondPushSlot` fails, `continue`). When the burst ends, the
  last wake has usually been dropped, and nothing else looks: the dialer
  has no periodic backfill while parked. It moves again only when the
  long-poll returns (responder default 30 s, client safety net 60 s) and
  claims one batch in the primary cycle. Measured: about 100 SETs per
  30 to 60 s, so 3706 to 5011 of 6666 delivered when the 5 min drain
  timeout struck, in all four two-node runs. The 2000-event two-node run
  finished in `majority` mode (1.15 s) only because the burst was short
  enough that no wake was lost.
- **POLL:** the receiver's own poll reads pending JTIs from Mongo directly,
  so it is bounded only by its batch size and round trips (4.6 to 6.1 s).
- **`local` mode adds a second way to lose the wake.** Ring-fed delivery
  (ADR 0045 §5a) wakes the target at WAL append, before the peer's drain
  has committed the SET to Mongo, and never again at drain. A wake that
  does get through finds nothing to claim yet.

Fix proposal, in order of leverage:

1. Make the wake **level-triggered**: on a wake, PUSH backfills regardless
   of buffer depth and repeats until a read returns fewer than a batch; the
   SSTP dialer loops `ClaimOutbound` until a claim comes back empty after
   the wake that started it, and re-checks once more when a second push
   completes.
2. Give the SSTP dialer the same 1 s backfill ticker the push loop has
   while it holds undelivered work, as the safety net.
3. In `local` mode, re-wake the target from `commitWalEntry` when the
   drained SET's stream is owned elsewhere, or defer the ring-fed wake for
   remote owners until commit.
4. Optionally carry the JTIs in the wake body (the coalescing window can
   batch them), so the owner submits them without a Mongo read at all.

## Recommended order

1. **D** (#347, hand-off) and **B** (#348, advertise address). D caps cross-node PUSH
   at about 100 SETs per second and stalls cross-node SSTP in both
   durability modes; B breaks every wake-up in the shipped cluster composes
   today, which turns D into the only delivery path.
2. **A** (#349) and **C** (#350) together, as one "stream table reconciliation" change:
   the peer's table should follow the store, in both directions, faster
   than 40 s.
3. Backfill gating and the one-strike lease renewal are tuning, not
   defects; revisit after 1 and 2 with a two-node soak.

Two-node numbers are therefore a measurement of ingest scaling only until D
is fixed. For delivery, the single-node rows remain the reference.
