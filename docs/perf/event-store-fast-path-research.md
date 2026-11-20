# Event store fast path — two-stage, split, or tune Mongo? — research note

Date: 2026-09-26
Status: research only. No code, ADR, or issue follows from this note.

## TL;DR

Ingest is bound by one majority-acked, journaled MongoDB replica-set round trip per accepted SET, not by document count, document size, or the Go code around it.

- **What a 202 costs today.** The router issues two majority-acked writes concurrently — one `events` body in an unordered `InsertMany` and one `pending` marker per matching stream in a second `InsertMany` — and joins them before the handler writes 202 [event_router.go:1016,1045-1057; api_receiver.go:2051-2057]. ADR 0038 measured each write at about 9 ms server-side on the 3-node dev replica set [ADR-0038]. The replica set has to fsync a journal on a majority of members before it replies, so that 9 ms is a replication + fsync floor, not something the driver or DAO can shave.
- **Throughput scales with concurrency, not per-op latency.** The e2e harness reaches about 1000 ev/s at p50 13–15 ms with concurrent ingest [e2e-history]; batched ingest pays 311 µs per SET at 16 workers [ADR-0038]. Nothing in `docs/perf/` breaks the remaining ingest time down inside Mongo; the profiles are CPU-only and never mention the driver [pprof.md].
- **(c) Tune Mongo first.** Two cheap, measurable moves: relax `pending` (and only `pending`) from `w:majority` to journaled `w:1` on its own collection handle, and add a DAO-level group commit so concurrent single-SET pushes share one `InsertMany`. Neither changes the acknowledgement contract for the body. Both need a DAO latency histogram that does not exist today [Metrics.md].
- **(a) Two-stage store is the real fast path, and it changes what 202 promises.** A local fsynced WAL (`tidwall/wal` or `bbolt`) can ack in well under a millisecond of local disk time, but the event is then durable on one node's disk, not on a majority of Mongo members. A node crash makes those events invisible to the rest of the cluster until the node returns, and the lease takeover in `docs/Cluster.md` cannot see them. RFC 8935 says "validated and persisted" without defining persisted, so this is defensible, but it is strictly weaker than today.
- **(b) Split store is not worth it.** The cost is the Mongo write, not the bytes in it; moving raw SET bytes off Mongo keeps the `pending` write and adds a cross-node raw store, a second retention sweep, and a new consistency seam for no measured gain.
- **Recommendation:** measure first (per-DAO-call histogram + a `pending`-at-`w:1` A/B on the bench harness), then prototype group commit behind the existing `EventDAO` decorator seam. Only if the ceiling after (c) is still the Mongo round trip should (a) be prototyped — and only as an opt-in, with the durability downgrade documented on the stream.

## 1. The write path today (verified)

- **Handler.** Push ingest is `ReceivePushEventHandler` [api_receiver.go:1920]; after auth and JWT validation it calls `sa.GetEventRouter().HandleEventCtx(ctx, received.Token, received.TokenString, sid)` [api_receiver.go:2051]. An error becomes a 400 via `goSetPush.WriteDeliveryError` [api_receiver.go:2053]; success is `goSetPush.WriteAccepted(w)` [api_receiver.go:2057]. Poll-side receivers batch via `HandleEvents` [api_receiver.go:1794-1836].
- **Router.** `HandleEventCtx` → `handleEvents` [event_router.go:948,999-1061]. Every write is issued on `r.ctx`, not the request context, "so ingest durability does not depend on the caller's request staying connected" [event_router.go:999-1061 comment].
    - Leg A: `ingest := r.eventService.BeginAddEvents(r.ctx, eventTokens, sid, rawEvents)` [event_router.go:1016] starts a goroutine that runs `s.eventDAO.InsertMany(ctx, b.recs)` [event_service.go:162-206]. Duplicate JTIs come back as `interfaces.ErrDuplicateJTI` per index [dao_interfaces.go:21; mongo/event_dao.go:107-147].
    - Leg B, concurrently: `planFanoutLocked` matches streams and calls `AddEventsToStream` → `AddPendingMany` [event_router.go:1045,1160-1180; event_service.go:245-254].
    - Join: `reconcileIngest` waits for leg A [event_router.go:1050,1065]; `commitFanoutLocked` retracts `pending` markers whose body failed (`DiscardPending` → `RetractPending`) and wakes push workers [event_router.go:1057,1186-1220; event_service.go:225-233].
- **Mongo documents per accepted SET.** One `events` document (body, `jti`, `sortTime`, sparse-unique `eventJtiUnique` index) plus one `pending` document `{jti, sid}` per matching stream [mongo_provider/provider.go:371-380,470-493; mongo/event_dao.go:236-268]. Delivery later adds one `delivered` document `{jti, sid, ackDate}` per stream [mongo/event_dao.go:482-502].
- **Write concern.** Set once, client-wide: `opts.WriteConcern = &writeconcern.WriteConcern{W: "majority"}` [mongo_provider/provider.go:711-713]. `Journal` is unset. Nothing in `internal/dao/mongo/event_dao.go` overrides it per collection. Per MongoDB, `w:"majority"` implies `j:true` when `writeConcernMajorityJournalDefault` is true, which is its default [MDB-WC; MDB-JOURNAL]. So every ingest write waits for a majority of members to fsync their journal.
- **Batching.** `InsertMany` on `events` is unordered (`SetOrdered(false)`) [mongo/event_dao.go:121]; `AddPendingMany` is one `InsertMany` (ordered default) [mongo/event_dao.go:266]. Batching exists only within one request: a push of one SET is one document in each `InsertMany`. There is no cross-request batching anywhere in the DAO or service.
- **Where 202 returns.** After both legs join and `commitFanoutLocked` has run [event_router.go:1050-1057], then back in the handler [api_receiver.go:2057]. A crash between the two legs leaves either an orphan body (harmless, ADR 0017 dedup on retransmit) or a body-less `pending` marker, which delivery skips [event_router.go:2433-2437; ingest_crash_consistency_test.go:16-21; ADR-0038].

## 2. How events are read later (verified)

| Reader | Calls | Cite |
|---|---|---|
| Push worker | `GetEventIds` (→ `GetPendingForStream`) then `GetEventRecords` (→ `FindByJTIs`), deliver, `AckEvents(r.ctx, ackJtis, sid, fencingToken)` | event_router.go:2284-2289,2416-2540; event_service.go:286,307-308,343-361 |
| Poll handler | `AckEvents` for the client's `ack` list, `GetEventIds`, `GetEventRecords` | event_router.go:1529-1576,1630-1632 |
| SSTP outbound | same trio | sstp_outbound.go:219,380,527 |
| Ack | `RemovePendingMany` + `MarkDeliveredMany` | event_service.go:348,356 |
| Retention | `ListDeliveredForStream` → `RemoveDelivered` → `DeleteBodyIfUnreferenced` (counts `pending` and `delivered` refs, then `DeleteOne` on `events`) | retention.go:113-150; mongo/event_dao.go:553-592 |
| Wake-up | `WatchPending` change stream on `pending` | event_router.go:454; mongo/event_dao.go:607-661 |

Every read is keyed by JTI or by `{sid, jti}`; none reads the body by time range on the hot path. That is what makes a JTI-keyed side store plausible at all.

## 3. Cluster model and in-flight events (verified)

- Push/poll delivery for a stream runs only on the node holding its Mongo lease (30 s lease, 10 s heartbeat, atomic `FindOneAndUpdate`) [Cluster.md:12-15,26-48]. Wake-up is the `pending` change stream plus a periodic backfill from Mongo [Cluster.md:70-91; event_router.go:2284].
- Node crash: another node takes over after lease expiry (about 30 s) and backfills from `pending` [Cluster.md:102-106]. This works today only because everything a takeover needs is already in Mongo at majority.
- The fencing token is threaded into `AckEvents` but unused: both `AckEvent` and `AckEvents` carry `// TODO: Use fencingToken to verify lease ownership before marking delivered` [event_service.go:321-361]. Any design that adds a per-node store makes this gap more important, not less.
- Mongo down: lease renewal and delivery stop [Cluster.md:102-106]. Today ingest also stops (the handler returns 400 when the write fails). A two-stage store would change this: ingest could keep acking while Mongo is down, which is the one operational property of (a) that is unambiguously better.

## 4. What "safely stored" must mean (spec text)

- RFC 8935 §2: "Once the SET has been validated and persisted, the SET Recipient SHOULD immediately return a response indicating that the SET was successfully delivered." Duplicates: "The SET Recipient MUST respond as it would if the SET had not been previously received." Retransmit only on "potentially recoverable errors (such as network outage or temporary service interruption...)" [RFC8935 §2]. §2.2 maps success to 202 [RFC8935 §2.2].
- RFC 8936 §2: "Once a SET is acknowledged, the SET Recipient SHALL be responsible for retention, if needed" and "After successful (acknowledged) SET delivery, SET Transmitters are not required to retain or record SETs for retransmission." §2.4: recipients "SHOULD acknowledge receipt in a timely fashion" and "SHOULD accept repeat SETs and acknowledge the SETs regardless" [RFC8936 §2, §2.4].
- OpenID SSF 1.0 delegates transport to the two RFCs and adds nothing about persistence [SSF §6.1.1, §6.1.2].
- **Inferred:** neither RFC defines "persisted". The transmitter may delete the SET on 202/ack, so the recipient's persistence must survive whatever failures the deployment considers in scope. Today that is "majority of the replica set, journaled". A single-node fsync satisfies the letter of RFC 8935; it does not satisfy the cluster model in `docs/Cluster.md`, where a dead node's work is supposed to be resumable by a peer.

## 5. Candidate stores (from their own docs)

| Store | License | CGO | Durability knob | Own benchmark numbers | Maintenance (gh api, 2026-09-26) |
|---|---|---|---|---|---|
| Mongo `w:majority` (today) | — | — | majority + journal fsync on each member [MDB-WC; MDB-JOURNAL] | ADR 0038: ~9 ms per write server-side on dev RS [ADR-0038] | — |
| Mongo `w:1`, `j:true` | — | — | primary journal fsync only; "can be rolled back if the primary steps down before the write operations replicate" [MDB-WC] | none in repo | — |
| Mongo `w:1`, `j:false` | — | — | journal synced every 100 ms (`commitIntervalMs`) [MDB-JOURNAL] | none in repo | — |
| `etcd-io/bbolt` | MIT | pure Go | two `fsync()` per tx; `DB.Batch` "opportunistically combined into larger transactions" (must be idempotent); `NoSync` escape hatch; "random writes can be slow" [BBOLT] | no primary benchmark found | pushed 2026-09-15, 9757 stars, active |
| `hypermodeinc/badger` v4 | Apache-2.0 | "Pure Go (no Cgo)" [BADGER] | `SyncWrites` default **false**; writes via mmap "survive process crashes"; `true` adds an `msync` "to survive hard reboots. Most users of Badger should not need to do this." [BADGER-OPT] | referenced to badger-bench, no numbers in README | pushed 2026-09-23, 15773 stars, active |
| `cockroachdb/pebble` | BSD-3-Clause | not stated in README | `WriteOptions.Sync`: "required for durability of individual write operations but can result in slower writes"; unsynced "a recent write may be lost" [PEBBLE-OPT] | none published in README | pushed 2026-09-26, 6043 stars, CockroachDB production since v20.1 [PEBBLE] |
| `tidwall/wal` | MIT | pure Go (inferred: no cgo in module) | `NoSync` default false, fsync after each write; `WriteBatch` writes several entries in order [WAL-OPT] | no primary benchmark found | pushed 2025-08-31, 734 stars — 13 months idle |
| Redis AOF `appendfsync always` | — | — | group commit: "single write and a single fsync (before sending the replies)"; "Very very slow, very safe"; AOF is local, not replication [REDIS] | none quoted | — |
| Hand-rolled WAL + in-memory JTI index | — | pure Go | one `fsync` per group commit, exactly Redis's model | none | ours to maintain |

Notes:

- All four Go stores carry licenses that pass `go-licenses check --disallowed_types=forbidden,restricted,unknown` [Makefile:127-133]; MIT, Apache-2.0 and BSD-3-Clause are all "notice" type.
- Badger's durability default is the wrong way round for this use: process-crash safe but not power-loss safe unless `SyncWrites=true`, which its docs discourage.
- Every store's fsync-bound floor is the disk's, not the library's. No project publishes a number we can quote; the only way to know the local floor is to measure `fsync` on the deployment's disk (see §7).
- The only durable, node-independent store in the table is Mongo at majority. Everything else is single-node durability plus whatever we build on top.

## 6. Design analysis

### 6a. Two-stage store (local staging, async drain)

- **Where it plugs in.** The `EventDAO` interface [dao_interfaces.go:75-135] already has a decorator precedent, `notifyingEventDAO` [memory_provider/notifying_dao.go:116-262], wrapped at `memory_provider/provider.go:138` and consumed by `services.NewEventService` at `:148`; the Mongo side wires `NewEventDAO` → `NewEventService` at `mongo_provider/provider.go:189,200` and exposes the DAO through `Persistence.EventDAO` [factory.go:36-46]. A `stagingEventDAO` decorator that intercepts `InsertMany` and `AddPendingMany` and forwards everything else is the smallest possible seam; the router and service stay untouched.
- **Staging schema (inferred).** One WAL record per accepted batch: `{jti[], sid, raw SET bytes[], pending targets[]}`. An in-memory map `jti → WAL offset` serves `FindByJTI`/`FindByJTIs` for events still in the window. The drain loop replays records into the real DAO's `InsertMany` + `AddPendingMany` in order, then truncates the WAL front (`tidwall/wal` `TruncateFront`, or a bbolt bucket delete).
- **Ack.** 202 returns after the local fsync (group-committed across concurrent requests, Redis-style). This is the whole win.
- **Replay idempotency.** Already free: the sparse-unique `eventJtiUnique` index turns a replayed body into `ErrDuplicateJTI`, which `completeAddEvents` already treats as "existing" [event_service.go:186-206; ADR-0017]. `pending` has no unique index, so replaying `AddPendingMany` after a crash mid-drain double-queues the event; the drain must mark each record's `pending` leg done in the WAL before the body leg, or add a `{sid, jti}` unique index (the `pendingSidJti` index exists but is not unique [mongo_provider/provider.go:377-380,390-449]).
- **Backpressure.** If the drain falls behind, the WAL grows without bound while Mongo is slow or down. Needs a cap (bytes or age) beyond which ingest reverts to synchronous Mongo writes or returns 503. Without this, (a) turns a Mongo outage into a disk-full outage.
- **Read-by-JTI during the window.** Push and poll workers on *this* node see staged events through the decorator. Workers on *other* nodes do not: `pending` is not in Mongo yet, so the change stream [event_router.go:454] never fires for them, and backfill [event_router.go:2284] cannot find them. Since delivery is lease-owned per stream [Cluster.md:12-15], an event ingested on node A for a stream whose lease is on node B is invisible to B until A drains. The delivery latency floor becomes the drain interval, not the write latency.
- **Cluster-lease interaction.** Node A dies with N records in its WAL: those N SETs were 202'd, the transmitter has deleted them (RFC 8936 §2), and no other node can deliver them until A's disk comes back. Lease takeover in `Cluster.md` cannot help. This is the ack-contract risk and it is not mitigable without replicating the WAL, which is re-implementing what Mongo majority already does.
- **Observability.** Add `goSignals_staging_depth`, `goSignals_staging_age_seconds`, `goSignals_staging_drain_duration_seconds` next to the router counters [Metrics.md:12-24].

### 6b. Split store (raw bytes permanently in a fast store, metadata in Mongo)

- **What Mongo must keep.** Everything the readers in §2 query: `jti`, `sortTime`, `types`, `sid`, the `pending` and `delivered` sets, and enough to run `MatchesStream` (event types, subject) [event_service.go:391]. That is the `events` document minus the token body — and the body is the part `FindByJTIs` needs on every delivery.
- **What it saves.** Bytes per `events` document. It does not remove the `events` insert (metadata still lands there) nor the `pending` insert, so the majority round trip stays. The cost model in §1 says the round trip, not the payload, is the floor; ADR 0038's before/after numbers moved 27% by removing a *round trip*, not by shrinking documents [ADR-0038].
- **What it adds.** Sharing the raw store across nodes (each delivery node needs the body; a local store means every node needs every body, or delivery must fetch from the ingest node); a second retention sweep coordinated with `DeleteBodyIfUnreferenced` [mongo/event_dao.go:553-592]; a consistency seam where Mongo says "pending" but the raw store lost the body — the same body-less-marker case as today, now permanent instead of transient.
- **Verdict:** not recommended. It keeps the cost and adds the risk.

### 6c. Tune the existing Mongo path

- **Per-collection write concern.** The driver's `CollectionOptionsBuilder.SetWriteConcern` exists [GODRV-OPTS], so `pending` can be opened at `w:1, j:true` while `events` stays at majority. Semantics: the body is majority-durable before 202; the marker may be rolled back on a primary step-down [MDB-WC]. A rolled-back marker is exactly the orphan-body case ADR 0038 already tolerates, *except* that the transmitter has been 202'd and will not retransmit — the event would be stored but never delivered. ADR 0038 rejected this option for that reason [ADR-0038]. It is worth re-measuring only because the ADR's own numbers show the two legs cost the same (9.30 vs 8.82 ms) and run concurrently, so the ceiling gain is bounded by whichever leg is slower, not by their sum. **Inferred: probably small.**
- **Group commit across requests.** A DAO decorator that collects concurrent single-SET `InsertMany` calls for up to ~1 ms (or N documents) and issues one unordered `InsertMany` [MDB-INSERTMANY: unordered, one oplog entry]. Per-record errors already come back index-aligned [mongo/event_dao.go:107-147], so fan-in/fan-out of results is mechanical. The same works for `AddPendingMany` per `sid`. Expected effect (inferred from ADR 0038's batch100 figure of 311 µs/SET vs 1.744 ms/op single): the majority round trip is amortised across the batch, so throughput at a fixed concurrency rises and p50 latency rises by the collection window. This keeps the acknowledgement contract exactly as it is.
- **Fewer documents.** Folding the `pending` marker into the event document was rejected in ADR 0038 because it serialises the two legs and makes the per-stream index awkward [ADR-0038]. Not revisited here.
- **Fewer indexes.** `events` has one unique index; `pending` two; `delivered` two [mongo_provider/provider.go:371-380]. Index maintenance cost is unmeasured; unlikely to dominate a majority fsync.

## 7. What the current numbers do and do not say

- ADR 0038 gives server-side timings per write (9.30 ms `events`, 8.82 ms `pending`) and router-level benches before/after concurrency (2.387 → 1.744 ms/op single; 444 → 311 µs/SET batched at 16 workers) [ADR-0038]. The bench harness is `BenchmarkMongoRouter` [handle_event_bench_test.go:176-250].
- `e2e-history.md` tail: 935 / 1041 / 1006 ev/s, p50 15.1 / 13.0 / 14.1 ms, p99 43.1 / 43.6 / 40.4 ms [e2e-history].
- `e2e-benchmark.md` lists "per-event Mongo round trips" as a hot spot and records the fixes (#286, #287, #288); it does not split the remaining ingest time between driver, network and `mongod` [e2e-benchmark.md:276-300]. `pprof.md` and `go127-baseline.md` are CPU/GC profiles with no Mongo breakdown [pprof.md; go127-baseline.md:140-165].
- `docs/Metrics.md` has an HTTP duration histogram and router counters but no DAO/Mongo latency metric [Metrics.md:12-24,69].
- **Measurement needed before any of (a)/(b)/(c):**
    1. A `goSignals_dao_duration_seconds{method}` histogram wrapped around `EventDAO` via the same decorator seam. This separates "waiting on Mongo" from everything else per call.
    2. `fsync` floor on the deployment disk (a 50-line Go program: open, write 1 KiB, `fsync`, loop; report p50/p99). This is the (a) ceiling.
    3. `BenchmarkMongoRouter/ingest` re-run with `pending` at `w:1,j:true` and with a 1 ms group-commit window, holding the body at majority.

## 8. Recommendation

1. **Instrument, then (c).** Add the DAO histogram and the `fsync` probe; run the three benches in §7. Prototype the group-commit decorator behind `interfaces.EventDAO` [dao_interfaces.go:75] and wire it at the two provider sites [memory_provider/provider.go:138; mongo_provider/provider.go:189]. This is the only option that raises throughput without touching what 202 means.
2. **Do not do (b).**
3. **Treat (a) as an opt-in durability mode, not the default.** Prototype it only if (c) still leaves the majority round trip as the ceiling *and* an operator has a stated tolerance for "events acked on one node's disk". Use `tidwall/wal` (simplest, MIT, matches the append-then-truncate shape) or bbolt (better maintained, `DB.Batch` gives group commit for free); reject badger for its `SyncWrites=false` default. Ship it with the WAL cap, the drain-order rule for `pending`, and the metrics in §6a, and document on the stream that a node loss can lose acked events until the node returns.

**Acknowledgement-contract risks, in one list:**

- (a): events 202'd but lost to peers on node crash until the node returns; permanently lost if the disk is. Lease takeover cannot recover them.
- (a): cross-node delivery latency floor becomes the drain interval.
- (a): a Mongo outage becomes unbounded WAL growth without a cap.
- (a): replaying `AddPendingMany` after a crash mid-drain double-queues unless drain order or a unique `{sid, jti}` index prevents it.
- (c, `pending` at `w:1`): a primary step-down can roll back the marker after 202; the body is stored but never delivered, and the transmitter will not retransmit. ADR 0038 rejected this; re-measure before re-deciding.
- (c, group commit): none to the contract; adds up to the collection window to p50 latency.
- Any option that keeps events outside Mongo makes the unused fencing token [event_service.go:321-361] a live bug rather than a TODO.

## Unverified claims (summary)

- That `writeConcernMajorityJournalDefault` is `true` on the dev and production replica sets (MongoDB default; not checked against the running config — `.mongo/` is `.aiignore`d).
- The fsync-bound latency of any candidate store on the deployment's disk; no project publishes a primary number.
- That `pebble` and `tidwall/wal` are CGO-free (inferred from module contents, not stated in their READMEs).
- The size of the (c) `pending`-at-`w:1` gain; ADR 0038's timings suggest it is small because the legs already overlap.
- Where the remaining ~13 ms ingest p50 goes between driver, network and `mongod`; no profile in `docs/perf/` measures it.
- ADR 0055 (retention decision 3, "keep forever" in community) lives in the planning repo and was read only through its references in `application.go:314-324` and `factory.go:36-46`.

## Sources

Repository (i2goSignals, branch `release-0.12.0` @ cf069cb):

- `internal/server/api_receiver.go`, `internal/eventRouter/event_router.go`, `internal/eventRouter/sstp_outbound.go`, `internal/eventRouter/ingest_crash_consistency_test.go`, `internal/eventRouter/handle_event_bench_test.go`
- `pkg/services/event_service.go`, `pkg/services/retention.go`, `pkg/dao/dao_interfaces.go`, `pkg/dao/memory/event_dao.go`
- `internal/dao/mongo/event_dao.go`, `internal/providers/dbProviders/factory.go`, `internal/providers/dbProviders/mongo_provider/provider.go`, `internal/providers/dbProviders/memory_provider/provider.go`, `internal/providers/dbProviders/memory_provider/notifying_dao.go`, `internal/server/application.go`
- `CONTEXT.md`, `docs/Cluster.md`, `docs/Metrics.md`, `Makefile`
- `docs/adr/0017-jti-is-the-event-dedup-key.md`, `docs/adr/0038-ingest-durability-contract.md`, `docs/adr/0039-per-request-and-short-ttl-ingest-read-caches.md`, `docs/adr/0040-set-delivery-ordering-contract.md`
- `docs/perf/e2e-history.md`, `docs/perf/e2e-benchmark.md`, `docs/perf/pprof.md`, `docs/perf/go127-baseline.md`, `docs/perf/grpc-set-transfer-exploration.md`

External:

- [RFC8935] Push-Based Security Event Token (SET) Delivery Using HTTP, §2, §2.2, §2.3 — https://www.rfc-editor.org/rfc/rfc8935.html
- [RFC8936] Poll-Based Security Event Token (SET) Delivery Using HTTP, §2, §2.2, §2.4 — https://www.rfc-editor.org/rfc/rfc8936.html
- [SSF] OpenID Shared Signals Framework 1.0, §6.1.1, §6.1.2, §8.1.2.1 — https://openid.net/specs/openid-sharedsignals-framework-1_0.html
- [MDB-WC] MongoDB Write Concern — https://www.mongodb.com/docs/manual/reference/write-concern/
- [MDB-JOURNAL] MongoDB Journaling (journal commit interval, `j: true`) — https://www.mongodb.com/docs/manual/core/journaling/
- [MDB-INSERTMANY] `db.collection.insertMany()` (ordered vs unordered, oplog consolidation) — https://www.mongodb.com/docs/manual/reference/method/db.collection.insertMany/
- [GODRV-WC] Go driver `writeconcern` package — https://pkg.go.dev/go.mongodb.org/mongo-driver/v2/mongo/writeconcern
- [GODRV-OPTS] Go driver `options.CollectionOptionsBuilder.SetWriteConcern`, `InsertManyOptionsBuilder.SetOrdered` — https://pkg.go.dev/go.mongodb.org/mongo-driver/v2/mongo/options
- [REDIS] Redis persistence (AOF `appendfsync`) — https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/
- [BBOLT] etcd-io/bbolt README — https://github.com/etcd-io/bbolt/blob/main/README.md
- [BADGER] hypermodeinc/badger README — https://github.com/hypermodeinc/badger/blob/main/README.md
- [BADGER-OPT] hypermodeinc/badger `options.go` `WithSyncWrites` — https://github.com/hypermodeinc/badger/blob/main/options.go
- [PEBBLE] cockroachdb/pebble README — https://github.com/cockroachdb/pebble/blob/master/README.md
- [PEBBLE-OPT] cockroachdb/pebble `options.go` `WriteOptions.Sync` — https://github.com/cockroachdb/pebble/blob/master/options.go
- [WAL-OPT] tidwall/wal package docs (`Options`, `WriteBatch`, `TruncateFront`) — https://pkg.go.dev/github.com/tidwall/wal
- [GH-API] `gh api repos/{etcd-io/bbolt,hypermodeinc/badger,cockroachdb/pebble,tidwall/wal}` — license, `pushed_at`, stars, archived flag, 2026-09-26
