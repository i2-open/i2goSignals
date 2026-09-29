<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 46. The local WAL is an append-only segment log, one fsync per group

Date: 2026-09-29

## Status

Accepted (community; spec-111 Stage 3 follow-up to ADR 0045).

Amends ADR 0045 §4 ("The store: bbolt"). The contract, the ingest path, the
drain worker, ring-fed delivery and the multi-node rule in ADR 0045 are
unchanged. Only the store behind the `internal/wal` interface changes.

## Context

ADR 0045 chose bbolt for the node-local WAL. Measured on the benchmark
stack, the WAL was the ceiling of `local` mode rather than the floor: every
group commit cost bbolt two fsyncs (data pages, then the meta page), and the
B+tree rewrote pages for a workload that is a pure queue. On the macOS host
(`F_FULLFSYNC`) one 16-way group took 18.5 ms and one serial append 9.4 ms
(`BenchmarkBoltAppend16`, `BenchmarkBoltAppendSerial`), so ingest with
`durability=local` acknowledged at about a fifth of the majority rate.

The access pattern is append at the tail, read from the head, truncate the
head. That is a segment log, and it needs one write and one fsync per group.

## Decision

### 1. Format

The WAL directory holds numbered segment files, `ingest-00000001.seg`,
`ingest-00000002.seg`, ... plus `wal.lock`.

```
segment: "I2SIGWAL" | u32 version = 1 | u64 firstSeq          (20 bytes)
record:  u32 payloadLen | u32 crc32c(type|seq|payload) | u8 type | u64 seq | payload
```

Record types: `1` entry (payload is the encoded WAL entry), `2` truncate
marker (seq is the highest sequence removed, no payload). Sequence numbers
are dense, never reused, and continue across restarts and truncation.
`firstSeq` in the header is the next sequence at the time the segment was
opened, so a segment with no live records still pins the counter.

### 2. Commit

Group commit keeps the leader/follower shape of ADR 0045 §4: while one
group is committing, every `Append` and `Truncate` queues, and the oldest
waiter leads the next group. A group is one truncate marker (if any
truncates queued) followed by the entries, written with **one positional
write and one `fdatasync`** (`File.Sync` where `fdatasync` does not exist).
Callers are acknowledged only after the sync returns. The truncate rides the
same fsync, so the drain still costs the ingest path nothing extra.

A segment rolls over when the next group would take it past 64 MiB. Rolling
creates the next file with `O_EXCL`, fsyncs it and fsyncs the directory.

### 3. Read and truncate

An in-memory index (seq, segment, offset, length) is built at open and
maintained on commit. `ReadFrom` copies the index span and reads the
payloads with `ReadAt`, so readers never block a commit. `Truncate` drops
index entries and appends a marker; a segment whose live count reaches zero
and that is not the active one is deleted, followed by a directory fsync.

### 4. Recovery

Open scans the segments in order. Each record is checked for length and
CRC. The scan stops at the first short or corrupt record, which is the torn
tail of the last group written before a crash, and the file is truncated
back to the last good record so the next group starts on a clean boundary.
Nothing after the torn record was ever acknowledged, because the
acknowledgement waits for the fsync. A last segment with a torn header (a
crash during rollover) is removed. An unknown record type is an error, not a
skip: the file was written by a newer version and must not be silently
drained short. Markers are replayed so a truncate that was fsynced stays
truncated.

`TestSegment_KillDuringAppend` SIGKILLs a child mid-stream and checks every
acknowledged sequence survives with its exact payload.
`TestSegment_TornTailTrimmed` and `TestSegment_CorruptRecordEndsPrefix`
cover the two damage cases.

### 5. Migration from bbolt

If `ingest.wal` (the ADR 0045 bbolt file) exists in the WAL directory, open
reads it, carries its undrained records into the segment log with sequence
numbers that continue after bbolt's counter, removes the file and fsyncs the
directory. The migration runs once, before ingest starts, and needs no
operator action. bbolt stays in `go.mod` for this reader only and can be
dropped once every deployment has passed through a segment-log release.

### 6. One process per directory

`wal.lock` is held with `flock(LOCK_EX|LOCK_NB)` for the life of the log. A
second process opening the same directory fails at once with
`wal: <dir>/wal.lock is locked by another process` instead of corrupting the
tail. This is a same-kernel guard: two containers on one Docker host sharing
a bind mount are caught, two hosts sharing an NFS export are not.

### 7. Metric

`goSignals_wal_append_seconds` is a histogram of one append as ingest sees
it: the wait behind the current group plus the write and fsync. Together
with `goSignals_wal_drain_duration_seconds` it separates "the disk is slow"
from "the drain is slow", which the depth gauge alone could not.

## Cluster deployment

`local` mode was designed single-node durable (ADR 0045), and the segment
log does not change that. What running it on more than one node requires:

- **One WAL directory per node, never shared.** The log is owned by one
  process. `config/goSignals1.env` is loaded by both same-cluster nodes in
  `docker-compose-cluster.yml` and `docker-compose-cluster-dev.yml`, and the
  dev variant bind-mounts the repo at `/app` for both. The second node,
  `goSignals1b`, therefore overrides `I2SIG_STORE_WAL_DIR` in its
  `environment:` block. Without the override it fails at start on the
  directory lock, which is the intended failure. A per-node named volume, as
  in `docker-compose-benchmark.yml`, is the right shape for a real
  deployment: it keeps the tail across a container restart and never crosses
  nodes.
- **Ring-fed delivery is mandatory with more than one node** (ADR 0045 §5a,
  #343). A joining local-mode node without `I2SIG_STORE_WAL_RING_FED=true`
  refuses to start, and a running one suspends local ingest. The segment
  log's `ReadFrom` is index-backed, so ring-fed reads do not wait on the
  commit path.
- **Failover semantics are unchanged.** A graceful stop drains before it
  releases its leases (#341). A `kill -9` or host loss leaves the undrained
  tail on that node's disk; it replays when that node restarts with the same
  directory, and is lost if the disk is. The lease TTL decides how quickly
  another node takes the streams over, not whether the tail survives. The
  ADR 0045 failure matrix stands.
- **Duplicates on recovery are absorbed, not prevented.** A node that
  drained a batch to Mongo and crashed before its truncate marker was fsynced
  re-drains that batch on restart; ADR 0017 JTI dedup at insert makes the
  second drain a no-op.
- **A node's WAL directory is not portable to another node.** Moving a
  directory between nodes replays SETs under the new node's identity, which
  is safe for the store (dedup) but is an operator action, not a recovery
  the cluster performs.
- **Known gap, measured 2026-09-29:** the cross-node hand-off (a wake-up
  call without the JTIs, then a bounded backfill on the owner) delivers
  about 100 SETs per second for PUSH and stalls SSTP after a dropped wake,
  in both durability modes. Ring-fed `local` mode adds to it: the target is
  woken at append, before the peer's drain has committed the SET to Mongo,
  and never again. `docs/perf/cluster-perf.md` has the measurements and
  the fix options; until they land, a two-node deployment scales ingest,
  not delivery.

## Consequences

- One fsync per group instead of two, and sequential writes instead of
  page rewrites. Measured on the same macOS host: 16-way group 18.5 ms →
  9.7 ms, serial append 9.4 ms → 4.5 ms. On Linux, where `fdatasync` skips
  the inode update, the gain is expected to be larger.
- Recovery cost is one sequential read of the live segments. Segments are
  bounded at 64 MiB and drained segments are deleted, so a healthy node
  opens in milliseconds; a node that ran with Mongo down for a long time
  reads whatever it accumulated.
- The on-disk format is now this repo's, versioned in the header. A
  newer-version record is refused, not skipped.
- The WAL directory contents changed shape: operators who back up or
  inspect `ingest.wal` now see `ingest-*.seg` files and `wal.lock`.
- A second process on the same directory fails fast. Any deployment that
  accidentally shared a WAL directory between nodes was already unsafe
  under bbolt; it is now visible at start.
