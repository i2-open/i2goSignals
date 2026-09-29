# Streaming throughput research: leases, Mongo writes, batched delivery, 10x-100x plan

Date: 2026-09-26
Status: research note, no code changes. Builds on `docs/perf/event-store-fast-path-research.md` (2026-09-26) and
`docs/perf/e2e-benchmark.md`. Branch `release-0.12.0` @ cf069cb. Code paths are cited as `file:line`; each claim
is marked **verified** (read in code / primary source) or **inferred** (reasoned from verified facts, not measured).

## TL;DR

- **Q1.** Ingest is not lease-scoped: every node accepts push, poll-transmitter and SSTP writes for every stream
  with no coordinator call on the path (verified). Leases exist only for the three *delivery* runners
  (`push-transmitter:<sid>`, `poll-receiver:<sid>`, `sstp-client:<pair>`). "Drain-before-release" therefore
  guards the wrong resource: a node that dies holds nothing, and a live node that releases gracefully is already
  free to drain first. A local WAL is a durability-domain decision (single-node), not a lease-protocol change.
- **Q2.** The two majority-acked writes per SET are the wall. A DAO group-commit decorator (window ~1-2 ms, max
  ~100-256) recovers the ~7x/SET the ADR 0038 bench already showed (9 ms -> 311 us/SET at batch 100). Collapsing
  `pending` into the event doc (or Mongo 8.0 `bulkWrite`) removes the second journal sync and the orphan-marker
  stall. Transactions add round trips and do not help. The pool default (100) is not the ceiling today; the
  16-concurrency harness is. Estimated ingest ceiling after Stage 1: ~5-10k ev/s per node (inferred).
- **Q3.** All three delivery legs are **serial per stream and ack-gated**: push sends one batch (4x concurrency)
  and blocks on its ack; poll is ack-then-fetch in one round trip, one poll in flight per receiver; SSTP is one
  primary exchange per pair plus at most one concurrent second push. RFC 8936 and the SSTP draft permit
  pipelining (redelivery is explicitly tolerated; nothing forbids concurrent polls or requires order). Each ack
  batch costs three Mongo round trips (Find, DeleteMany, InsertMany).
- **Q4.** Stage 0 measure (#328) -> Stage 1 group commit + single-write ingest + WC review (target ~10x ingest)
  -> Stage 2 pipelined delivery + ack batching (target ~10x per-stream delivery) -> Stage 3 opt-in local WAL for
  single-node deployments (target 100x). Beyond ~10k ev/s the next walls are RSA re-sign CPU, JWT verify,
  per-`stream_id` counters, and the three-collection pending/delivered model.

## 1. Q1: leases, ingest scope, and drain-before-release

### 1.1 Lease lifecycle (verified)

| Step | Where | Behaviour |
|---|---|---|
| Acquire / renew | `internal/providers/dbProviders/mongo_provider/cluster_coordinator.go:94-123` | One `FindOneAndUpdate` (upsert) on `cluster_leases`: filter `_id=resource AND (leaseUntil<=now OR ownerNodeId=me)`; `$set` owner + `leaseUntil`, `$inc fencingToken`. Duplicate-key -> not acquired. Op ctx 5 s (`:62`). |
| TTL / heartbeat | `internal/eventRouter/lease_heartbeat.go:16-19`; `event_router.go:1760`; `api_receiver.go:1431,1492`; `sstp_dialer.go:53-54` | 30 s lease, 10 s renew, hardcoded for push and poll-receiver; SSTP dialer config-driven (same defaults). No env override for push/poll. |
| Renew failure | `lease_heartbeat.go:81-91` (push), `api_receiver.go:1497-1504` (poll) | Any error or non-ownership == lost; runner stops and re-acquires every 15 s (`event_router.go:484`). SSTP dialer retries once after 1 s (`sstp_dialer.go:1209-1236`). |
| Release | `cluster_coordinator.go:126-149` | `ReleaseLeaseIfOwned` sets `leaseUntil=now` (owner field kept). Called **only** by the SSTP dialer (`sstp_dialer.go:730,735,751`). Push and poll-receiver leases are never released; takeover waits for the 30 s TTL. |
| Takeover | `event_router.go:1745-1797`, `push_runner.go:162-169` | New owner preloads *all* pending JTIs (`MaxEvents: 0`) then runs the 1 s backfill ticker. No jitter for push/poll; SSTP has 100-500 ms jitter (`sstp_dialer.go:58-59`). |
| Fencing | `pkg/services/event_service.go:321-322,343-344` | `fencingToken` is minted but **never checked**: `RemovePendingMany`/`MarkDeliveredMany` take no token (`pkg/dao/dao_interfaces.go:109`). Poll acks pass 0. Push keeps the token from its first acquire (`lease_heartbeat.go:81` discards the renewed value). |
| Owner lookup | `cluster_coordinator.go:151-170`, `lease_owner_cache.go:20` | `GetLeaseOwner` ignores `leaseUntil`, so a dead owner is returned until someone else takes the lease; wake-ups go to the dead node for up to 30 s + 15 s. |

Shutdown order (`internal/server/application.go:454-511`): stop sync -> shutdown receivers -> HTTP servers ->
poll clients -> drain sleep (1 s, `I2SIG_SHUTDOWN_DRAIN`) -> `EventRouter.Shutdown()` (cancels `r.ctx`, does
**not** wait for push runners, `event_router.go:2676-2713`) -> drain sleep -> `Storage.Close()`. In-flight
push and ack calls run on `r.ctx` (`event_router.go:2472,2532`) and are cut off by router shutdown.

### 1.2 Is ingest lease-scoped? No (verified)

- Push receiver `receivePushForStream` (`internal/server/api_receiver.go:1975-2058`): auth -> stream lookup ->
  parse -> `HandleEventCtx`. No coordinator call.
- Router `handleEvents` (`internal/eventRouter/event_router.go:999-1059`): `BeginAddEvents` -> `planFanoutLocked`
  -> `reconcileIngest` -> `commitFanoutLocked`. Its only lease read is wake routing (`wakeTargetLocked`
  `:1222-1300`), which chooses *whom to wake*, never whether to accept.
- SSTP `POST /sstp/{id}` (`api_sstp.go:40`, `runner_sstp_server.go:19-21,46`): "takes no lease, every node can
  serve". Poll transmitter likewise (`event_router.go:1256`).
- Poll receiver (this node polling a remote) is the one *ingest* path that is leased, because it is also a
  delivery-side runner (`api_receiver.go:1407`).

Consequence: the lease governs *who delivers* a stream's pending list, not *who owns the bytes of a SET*.
Today every node's ingest is durable the moment the 202 is written (ADR 0038 majority ack), so no node holds
un-replicated state and the lease never has to care about it.

### 1.3 The proposal: "no release until the local WAL has drained"

Evaluated per release path:

| Path | Can the node gate it? | Effect of drain-before-release |
|---|---|---|
| Graceful stop | Yes, but the gate belongs in `application.go` shutdown, not in the lease. Nothing stops today's shutdown from draining a local buffer *before* releasing (SSTP) or before `Storage.Close()`. | Real safety for this path only. |
| `kill -9` / OOM / host loss | No. The lease expires 30 s later on its own; the buffer is on a dead node. A longer TTL only delays takeover; it does not bring the buffer back. | Narrows nothing; **the buffered SETs are lost unless the WAL is on persistent, re-mountable storage and the node restarts**. |
| Mongo unreachable | Renew fails within 5 s, runner marks lease lost; ingest keeps accepting until inserts fail (400, see below). With a WAL, ingest would keep accepting *into the WAL* while delivery halts. | Turns an availability outage into a growing local backlog; needs a WAL high-water mark to shed load. |
| Network partition (node isolated) | Same as Mongo unreachable from the node's view; another node takes the lease after TTL. The isolated node's WAL cannot drain until the partition heals. | Duplicate delivery is already tolerated by RFC 8936/SSTP; the risk is *late* delivery, not double. |

Three facts matter more than the lease wording (all verified):

1. Delivery *reads* the pending list from Mongo (`GetPendingForStream`, prefetch, backfill). Anything still in
   a node-local WAL is invisible to the lease holder. So a WAL is only consistent when **ingest node == delivery
   node** or when delivery is fed from the local ring first (the write-through/read-from-cache model, section 4.4).
2. The failure to fence acks (1.1) means two nodes *already* can double-ack a stream after a partition; a WAL
   changes nothing here. Fixing the fencing filter (`{sid, jti, fencingToken<=token}` on `pending`) is a
   prerequisite for any multi-node WAL story, and is cheap.
3. Ingest returns **400** for storage failures (`api_receiver.go:2052-2054` -> `goSetPush.WriteDeliveryError`
   -> `http.StatusBadRequest`, `pkg/goSetPush/receiver.go:167-180`). RFC 8935 §2.3 uses 400 for invalid
   requests; a transmitter receiving 400 has no contract to retry. This is a correctness bug independent of
   throughput and should be 503 with `Retry-After`.

Verdict: drain-before-release is a **narrowed window, not a guarantee**. It protects the graceful path (which
needs no lease change to do so) and does nothing for crash loss. The honest contract for a local WAL is
"**single-node durable**": the 202 promises the SET is on *this node's* disk, and the deployment accepts that a
host loss loses the un-drained tail. That is the ADR 0038 contract downgraded explicitly, per stream or per
deployment, never silently.

### 1.4 Alternatives

- **Ingest affinity (route a stream's ingest to its delivery-lease holder).** Receivers post wherever the
  load balancer sends them; adding a redirect/proxy hop to the owner costs a network RTT (~0.2-1 ms in-cluster)
  but makes "WAL on the owner" coherent. Simplest cluster-safe WAL shape, but pushes the availability problem
  to the owner (a stream is down while its owner is down, ~30-45 s). Inferred.
- **Replicated buffer (write to 2 nodes before 202).** This *is* what Mongo majority does, with a persistent
  oplog and election. Re-implementing it in-process (Raft ring, or 2-of-3 gossip ack) is a new distributed
  system; rejected unless the goal is to remove Mongo from the ingest path entirely.
- **Per-stream "acked on one node" contract.** Mark streams (or the deployment) `durability=local`. The 202
  means local WAL fsync; Mongo gets the batch within the group-commit window. Pair it with ingest affinity or
  with the "ingest node delivers from its ring" model. This is Stage 3 below.

## 2. Q2: Mongo write performance

### 2.1 What one SET costs today (verified)

`connect()` sets `WriteConcern{W:"majority"}` client-wide (`mongo_provider/provider.go:711`), `Journal` unset
-> j:true under `writeConcernMajorityJournalDefault` [MDB-WC]. Per SET: two concurrent unordered `InsertMany`
(`events` body `mongo/event_dao.go:122`; `pending` marker via `planFanoutLocked`) joined by `reconcileIngest`
(`event_router.go:1050,1065-1086`) before 202 (ADR 0038). Measured: p50 13-15 ms end to end at concurrency 16
[e2e-history]; ADR 0038 bench: single ingest 1.744 ms/op in-process; batch-100 at 16 workers 311 us/SET.
Majority on the dev 3-member set requires 2 journal syncs per write (primary + one secondary) plus the
replication hop; the ~9 ms single-op figure quoted in the prior note is the replicated-cluster case.

### 2.2 DAO group-commit batcher

Design (decorator behind `interfaces.EventDAO`, wired at `memory_provider/provider.go:138` and
`mongo_provider/provider.go:189`, same seam #328 uses for its latency decorator):

- `InsertMany` callers enqueue `{docs, resultCh}`; a flusher goroutine flushes when **either** the window
  elapses (`I2SIG_STORE_GROUP_COMMIT_WINDOW`, start at 1 ms; 2 ms if p50 permits) **or** the queue reaches
  `I2SIG_STORE_GROUP_COMMIT_MAX` (start at 128; Mongo caps a batch at 100k ops / 16 MB [MDB-BULKWRITE]).
- One `c.InsertMany(ctx, all, SetOrdered(false))`. Errors: driver returns `mongo.BulkWriteException` with
  `WriteErrors []BulkWriteError` carrying `Index` into the *combined* slice [GODRV-BULK]; the flusher maps each
  index back to the owning caller's offset and reproduces today's per-doc `ErrDuplicateJTI` contract
  (`event_dao.go:127-135`). A `WriteConcernError` fails the whole flush; every caller receives it.
- Context: the flush uses a fresh ctx with the DAO op timeout, not any caller's (a cancelled caller must not
  abort the batch). Callers that cancelled still get their result or a cancellation error after the flush.
- The same decorator batches `RemovePendingMany` + `MarkDeliveredMany` (section 3.4) and `pending` inserts.
- Memory provider: pass-through.

Estimated gain (inferred from ADR 0038 numbers): at 1000 ev/s a 1 ms window collects ~1-16 docs; at 10k ev/s
~10-128. Per-SET cost moves from ~1.7-9 ms toward 311 us/SET (batch 100) -> the two-write ingest path can
sustain **~3-6k ev/s per node on the same hardware**, latency p50 roughly window + one majority RTT
(~3-5 ms). Below ~500 ev/s the window rarely fills and latency rises by the window; make the window adaptive
(flush immediately when the queue was empty at enqueue time and no flush is in flight).

### 2.3 Collapse two writes into one

Option A, **embed the marker** (`pending: [sid...]` array or per-target subdocument in the `events` doc):

- One majority-acked insert per batch; no orphan-marker head-of-window stall (ADR 0038 §"orphan marker").
- Readers change: `GetPendingForStream` becomes `find({pending: sid}).sort({jti:1})` with a multikey index
  `{pending:1, jti:1}`; ack becomes `updateMany({jti:{$in}}, {$pull:{pending: sid}, $push:{delivered: ...}})`,
  i.e. one round trip instead of three. Retention sweep moves from "delete pending/delivered docs" to
  "delete events where pending==[] and expiry passed".
- Change-stream wake-up (`WatchPending`, `mongo/event_dao.go:607-661`) is opt-in and **deprecated**
  (`I2SIG_STORE_MONGO_WATCH_ENABLED=false` default, `event_router.go:451-470`;
  `configuration_properties.md:208`); default wake-up is the HMAC RPC + 1 s backfill, unaffected. If watch is
  kept it must match `insert` on `events` with a `pending` filter instead of on the `pending` collection.
- Cost: a schema migration for existing deployments (dual-read during upgrade); `delivered` audit rows move
  into the event doc or stay as a separate low-priority insert (can be w:1, see 2.4).

Option B, **Mongo 8.0 multi-namespace `bulkWrite`** (`Client.BulkWrite`, driver `client.go:976-984`;
server command new in 8.0 [MDB-BULKWRITE]; dev stack runs `mongo:8.0.13`, `docker-compose-cluster-dev.yml:34`):

- Keeps the three-collection model and both indexes; one round trip and **one** journal sync for both
  inserts; `ordered:false` continues on error; results carry per-op `idx`. Not atomic across namespaces, but
  ADR 0038 already tolerates the events-without-marker case.
- Cheaper to adopt than A; less upside (readers still do three trips per ack). Requires a server-version check
  at connect (driver does not gate; server rejects the command pre-8.0).

Recommendation: B first (small, contained), A only if the per-ack cost in 3.4 becomes the wall.

### 2.4 Per-collection write concern

`Collection` options accept a write concern override per handle [GODRV-CLIENTOPTS]. Candidates: `delivered`
(audit, replayable from `events` minus `pending`) at `w:1,j:false`; `pending` stays majority (prior note §6b:
w:1 pending was rejected by ADR 0038 because a rollback would orphan an acked event; re-measure only if 2.3 A
lands, which makes the question moot). `events` stays majority; that is the durability contract.

### 2.5 Why not transactions

A multi-document transaction adds `startTransaction`/`commitTransaction` round trips, holds WiredTiger
snapshots, and forces `w:majority` on commit anyway [MDB-TXN]; it would *raise* per-SET latency and cap
concurrency on snapshot history. The property we need (both writes or neither) is already delivered by
`bulkWrite` semantics plus the reconcile step; atomicity is not the bottleneck.

### 2.6 Pool sizing

Driver v2.9.1 defaults: `MaxPoolSize` 100, `MaxConnecting` 2 (`clientoptions.go:899,914-916`); provider sets
neither (only line 711 touches options). With 16 harness workers the pool is nowhere near saturated; at
100+ concurrent ingesters the pool becomes a queue. Group commit sidesteps this (one connection per flush).
Raise `MaxConnecting` to 4-8 only if connection-storm latency shows up in #328's histogram.

### 2.7 Mongo-side levers

- `storage.journal.commitIntervalMs` (default 100; j:true forces an immediate sync regardless) [MDB-JOURNAL].
  Lowering it does not help majority writes; group commit is the software equivalent.
- Majority size: 3 members -> 2 acks; 5 members (4 data + arbiter) -> 3 [MDB-WC]. A 5-member set is slower,
  not faster, for writes; prefer 3 data-bearing members in one AZ with a low-latency secondary.
- Member locality: majority latency ~= slowest of the two fastest journal syncs + one network RTT. A cross-AZ
  secondary in the majority path adds the AZ RTT to every SET.
- Published insert-throughput guidance: **none found** in MongoDB docs; only the batch caps above.

## 3. Q3: batches on poll, SSTP and push

### 3.1 RFC 8936 poll transmitter (verified)

- Handler `internal/server/api_transmitter.go:38-171` -> `PollStreamHandler` `event_router.go:1529-1687`.
- **Acks first** (`:1540-1552`) via `pollBuffer.AckEvents` + `eventService.AckEvents` (error ignored), then
  prefetch when buffer empty (`:1574-1584`, `MaxEvents=backfillBatch` 100), then `pollBuffer.GetEvents`
  (`:1602`) and `assemblePollResponse` (`:1630-1687`, one `GetEventRecords`, signing on the pool).
- `maxEvents` caps and sets `moreAvailable` (`buffer/event_buffer.go:267-270`); `returnImmediately` short-
  circuits the notifier wait (`:238-275`); timeout 30 s default / 300 s max (`event_router.go:478-479`).
- No per-stream poll lock: two concurrent polls copy the **same** un-acked JTIs (ADR 0036:33-38 accepts this).
  Buffer is per node; poll transmitter takes no lease.
- Extra costs: counter-only `GetEvents` read per poll (`api_transmitter.go:122-136`); prefetch =
  `CountDocuments` + sorted `Find`.

### 3.2 Poll receiver (verified)

`runPollLoop` (`api_receiver.go:1559-1888`): one synchronous `goSetPoll.Poll` (`:1622`, defaults
`MaxEvents 1000, TimeoutSecs 10`, `stream_service.go:839-845`) -> `HandleEvents` for the whole response as **one
batch** (`:1834`; one unordered `InsertMany` + concurrent pending inserts) -> acks for the successful JTIs ride
the **next** poll (`:1838-1845`). Batch N+1 is not sent until batch N's Mongo writes complete. One poll in
flight per stream, under the `poll-receiver:<sid>` lease.

### 3.3 SSTP (verified)

- Wire (`pkg/goSetSstp/message.go:16-33`): `returnEvents`, `returnImmediately`, `sets`, `ack`, `setErrs`; no
  `maxEvents`; batch size is sender-side (`backfillBatch` 100 both ends: `runner_sstp_server.go:201-235`,
  `sstp_dialer.go:286-287,953`).
- Responder (`api_sstp.go:40-162`, `runner_sstp_server.go:46-235`): applies peer acks, ingests inbound via
  `HandleEventsCtx` **before** responding, then drains its outbound buffer (long-poll if empty). Body cap
  disabled (`MaxBodyBytes: 0`). No lease; concurrent requests on one pair get overlapping sets. The `more` flag
  is discarded and `returnImmediately` never set in responses (spec line 299 signal unused).
- Initiator (`sstp_dialer.go:763-1075`): one primary exchange per pair under `sstp-client:<pair>`;
  `ClaimOutbound` (`sstp_outbound.go:196-224`, same-node in-flight claims) -> deliver -> `runInboundHalf`
  (batch `HandleEvents`) -> `AckOutbound` -> next exchange. Plus at most **one** concurrent "second push"
  (`AcquireSecondPushSlot`, `:915-924`, `returnEvents=false`, no acks). Dialer never sets `returnImmediately`,
  so every primary exchange is a long poll; if the responder's outbound is empty, the initiator's acks for the
  Sets it just pushed are held for the whole timeout (that is what the second push works around).
- Spec (`docs/specs/draft-hunt-secevent-sstp-00.txt`): no text on ordering, concurrent exchanges or batch
  size. `:256-260`: "unacknowledged SETs MAY be re-transmitted. The receiver SHOULD accept repeat SETs and
  acknowledge the SETs regardless"; `:248-253`: ack only after retention; `:606-610`: poll-with-ack in one
  request. Pipelining is spec-legal.

### 3.4 Ack cost (verified)

`AckEvents` (`pkg/services/event_service.go:343-361`) = `RemovePendingMany` (`Find` + `cursor.All` +
`DeleteMany`, `mongo/event_dao.go:369-407`) + `MarkDeliveredMany` (`InsertMany`, `:484-502`): **three majority
round trips per ack batch**, none transactional, none fenced. ADR 0038 measured drain+ack at 5.3 ms/op.

### 3.5 Push, RFC 8935 (verified)

Loop `event_router.go:1920-2057`: `drainPushBatch` up to `4 * pushConcurrency` (`:2380-2385`) -> `pushBatch`
(`:2416-2538`) fans out over `pushConcurrency` workers (`I2SIG_PUSH_CONCURRENCY`, default GOMAXPROCS clamped
8..32), stops taking items on first failure, `wg.Wait`, **one** `AckEvents` per batch (`:2531-2535`). The
next batch starts only after the ack returns: per stream, N = concurrency in flight over HTTP, then a
serialised 3-trip ack. HTTP client: one shared client per TLS posture, `MaxIdleConnsPerHost 64`,
`MaxConnsPerHost` 0, `ForceAttemptHTTP2` inherited true from `DefaultTransport.Clone()`
(`pkg/goSetPush/transmitter.go:126-152`) so h2 via ALPN when the receiver offers it [GO-NETHTTP].
RFC 8935 requires one SET per request (§2.1) and says nothing about ordering, serialisation or concurrency;
the ordering contract is the project's own (ADR 0040, UUIDv7 `jti`), and it is already relaxed within a
batch by the concurrent workers.

### 3.6 Pipelining, what is safe

| Leg | Today | Safe change |
|---|---|---|
| Push | batch -> ack -> batch | Decouple ack from send: workers push continuously from the buffer; a separate acker coalesces acked JTIs every ~5-10 ms into one `AckEvents`. In-flight bound = concurrency; ordering within the in-flight window is already relaxed. |
| Poll transmitter | ack-then-fetch, no lock | Add a per-stream "in-flight claim" like SSTP's `sstpInFlight` so K concurrent polls from one recipient get **disjoint** slices; K polls in flight are RFC-legal (duplicates tolerated, §2.4). |
| Poll receiver | 1 poll, wait for Mongo | Overlap poll N+1's request with poll N's ingest (send N+1 with `acks=[]`, then ack N's JTIs on N+2). Bounded pipeline depth 2-4; duplicates are swallowed by the JTI unique index. |
| SSTP | 1 primary + 1 second push | Allow K second pushes (claim-disjoint) and let the responder set `returnImmediately` when `more` is true so the initiator does not wait the long-poll timeout for its acks. |

## 4. Q4: staged plan

Assumptions: dev 3-member `mongo:8.0.13` on one host; 16-concurrency harness; RSA-2048 re-sign on egress;
figures are per node unless stated. Every ceiling below is **inferred** until Stage 0 measures it.

**Stage 0, measure (#328).** `goSignals_dao_op_duration_seconds{op,outcome}` + `goSignals_dao_batch_size{op}`
as the EventDAO decorator. Also record: harness concurrency sweep 16 -> 64 -> 256 (ADR 0037 shows ingest fell
1021 -> 619 ev/s when push concurrency rose 5 -> 24, so ingest and delivery already contend for Mongo and CPU),
Mongo `serverStatus.wiredTiger.log` sync counts, and an in-process pprof under load to refresh the 41 % RSA
figure [e2e-benchmark:263-300]. Exit: know the per-op Mongo p50 and how many journal syncs a SET costs.

**Stage 1, ingest ~10x (target 5-10k ev/s/node, p50 <= 5 ms).** Group-commit decorator (2.2) + `bulkWrite`
single round trip (2.3 B) + `delivered` at w:1 (2.4) + fix 400 -> 503 on storage failure + fencing filter on
acks. Ceiling drivers after this: one majority sync per ~100 SETs (~10 ms) gives ~10k ev/s per flusher; RSA
re-sign at ~1 ms/SET caps egress at ~1k ev/s per core unless ES256 (ADR 0041, ~8x cheaper) or no-re-sign
pass-through is enabled. No Mongo published insert ceiling exists to compare against.

**Stage 2, delivery ~10x per stream.** Ack/send decoupling and ack coalescing on push (3.6); disjoint-claim
concurrent polls; SSTP K second pushes + `returnImmediately`; ack path collapsed to one round trip (Option A in
2.3 or a `{sid,jti}` `deleteMany` + batched `delivered` insert). Target: per-stream delivery limited by
receiver RTT x concurrency rather than by the 3-trip ack (today ~5 ms ack per 32-128 SETs).

**Stage 3, opt-in local WAL, 100x (single-node durable).** `I2SIG_STORE_WAL=local` (or per-stream
`durability=local`): ingest appends to a segment log (tidwall/wal or bbolt per prior note §5), fsync per
group (~50-100 us on NVMe), 202 returned; a drainer moves segments to Mongo in large unordered `InsertMany`
(1k-10k docs). Requires ingest affinity or ring-fed delivery (4.4) for cluster use; otherwise document it as
single-node only. Ceiling: fsync-per-group + JSON parse, ~50-100k ev/s per node inferred; Mongo becomes an
asynchronous sink whose lag is the new SLO.

### 4.4 Write-through, read-from-cache

Mongo stays the durable log; the ingest node keeps a per-stream in-memory ring of parsed SETs and delivers
from it, removing `GetPendingForStream` + `FindByJTIs` from the hot path. Against today's lease model: works
only when the ingest node is the delivery owner (1.2), so it needs ingest affinity, or a rule "the ring is a
cache of pending; on lease takeover the new owner backfills from Mongo as it does today (`push_runner.go:162`)".
The second rule is already the code's behaviour for wake-up + backfill, so the model is compatible: the ring is
an optimisation, Mongo is the truth, and the fencing fix keeps two owners from double-acking. Memory bound:
ring size x streams; shed to Mongo-read when the ring overflows.

### 4.5 What else breaks at 100k ev/s

- **Change stream wake per pending doc**: only if `WatchPending` is enabled; the default RPC+backfill path
  coalesces wakes within 250 ms (`event_router.go:1464-1490`). Keep watch off.
- **Prometheus counters per `stream_id`** (`Metrics.md:14-15,43-46`): cardinality = streams x types x issuers;
  per-event `Inc()` is cheap (~20 ns) but label lookup with 4 labels allocates; pre-resolve `CounterVec.With`
  per stream at buffer creation.
- **JWT verify per request** (~5-13 % CPU [e2e-benchmark]): cache verified bearer -> stream for the token TTL.
- **JSON**: `BenchmarkSetParse` ~31 us, `BenchmarkSetJWS` ~820 us [go127-baseline:309]; signing dominates.
- **Logging**: INFO per-event log lines at 100k/s are a wall of their own; keep per-event logs at DEBUG.
- **Three-collection model**: `pending` grows with backlog x targets; ack = 3 trips; retention sweeps scan
  `delivered`. Option A (2.3) or a TTL index on `delivered` is the structural fix.
- **Oplog**: two docs per SET per target today; single-write halves it; WAL drain batches amortise headers.

## 5. Unverified claims

- All throughput ceilings in section 4 are inferred from ADR 0038 microbenchmarks, not measured.
- `Client.BulkWrite` server-version gate: driver source shows no explicit check; MongoDB docs date the command
  to 8.0; a WebFetch summary claiming "5.0" is treated as wrong.
- Mongo published per-node insert throughput guidance: none found.
- NVMe fsync floor (~50-100 us) is a general figure, not measured on the dev host.
- Whether the harness's 16 concurrency, not Mongo, is the current ceiling: consistent with ADR 0037 data but
  not isolated.
- `ForceAttemptHTTP2` inheritance from `DefaultTransport.Clone()` is read from Go source, not observed on the
  wire against a real receiver.

## 6. Sources

Repository (all under `/Users/pjdhunt/git/i2goSignals`):

- [event-store-fast-path] `docs/perf/event-store-fast-path-research.md`
- [ADR-0035] [ADR-0036] [ADR-0037] [ADR-0038] [ADR-0040] [ADR-0041] `docs/adr/0035-*`, `0036-batched-poll-response-assembly.md`, `0037-*`, `0038-ingest-durability-contract.md`, `0040-set-delivery-ordering-contract.md`, `0041-*`
- [Cluster.md] `docs/Cluster.md:26-106`; [SSTP.md] `docs/SSTP.md`; [SSTP-draft] `docs/specs/draft-hunt-secevent-sstp-00.txt:248-319,606-610,816-819`
- [e2e-benchmark] `docs/perf/e2e-benchmark.md:255-330`; [e2e-history] `docs/perf/e2e-history.md` (tail); [go127-baseline] `docs/perf/go127-baseline.md:309`; [Metrics.md] `docs/Metrics.md:14-15,43-46,59-78`; [config] `docs/configuration_properties.md:208,232-234,267-268`
- Code: `internal/providers/dbProviders/mongo_provider/{provider.go,cluster_coordinator.go}`, `internal/providers/cluster/coordinator.go`, `internal/eventRouter/{event_router.go,lease_heartbeat.go,lease_owner_cache.go,push_runner.go,runner_sstp_server.go,sstp_outbound.go,buffer/event_buffer.go}`, `internal/server/{api_receiver.go,api_transmitter.go,api_sstp.go,sstp_dialer.go,application.go,routers.go}`, `internal/dao/mongo/event_dao.go`, `pkg/services/event_service.go`, `pkg/dao/dao_interfaces.go`, `pkg/goSetPush/{receiver.go,transmitter.go}`, `pkg/goSetPoll/{poll.go,receiver.go}`, `pkg/goSetSstp/message.go`, `docker-compose-cluster-dev.yml:34`, `go.mod:23`
- [ISSUE-328] `gh -R i2-open/i2goSignals issue view 328` (open; DAO latency decorator; group commit / WC / WAL out of scope)

External:

- [RFC8935] https://www.rfc-editor.org/rfc/rfc8935.txt §2.1, §2.3
- [RFC8936] https://www.rfc-editor.org/rfc/rfc8936.txt §2.2, §2.3, §2.4, §2.4.3
- [MDB-BULKWRITE] https://www.mongodb.com/docs/manual/reference/command/bulkWrite/ (new in 8.0, `nsInfo`, `ordered`, per-op `idx`, 100k ops / 16 MB)
- [MDB-WC] https://www.mongodb.com/docs/manual/reference/write-concern/ (majority definition, `writeConcernMajorityJournalDefault`, `wtimeout`)
- [MDB-JOURNAL] https://www.mongodb.com/docs/manual/core/journaling/ (`commitIntervalMs`, j:true sync)
- [MDB-TXN] https://www.mongodb.com/docs/manual/core/transactions/ (commit write concern, snapshot history)
- [GODRV-CLIENTOPTS] go.mongodb.org/mongo-driver/v2 v2.9.1 `mongo/options/clientoptions.go:899,914-916`
- [GODRV-BULK] go.mongodb.org/mongo-driver/v2 v2.9.1 `mongo/{errors.go,client.go:976-984}` (`BulkWriteException`, `Client.BulkWrite`)
- [GO-NETHTTP] Go 1.27 `net/http/transport.go` (`ForceAttemptHTTP2`, `MaxIdleConnsPerHost`, `MaxConnsPerHost`)
