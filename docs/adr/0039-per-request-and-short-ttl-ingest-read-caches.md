<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 39. The per-event ingest reads are served from three scoped caches

Date: 2026-09-08

## Status

Accepted (community #287).

## Context

ADR 0038 removed one of the two majority-acked writes from the ingest critical
path by overlapping them. What remained on that path was not writes but reads:
every ingested SET re-asked questions that had already been answered.

Profiler level 2 over a 5000-event `--mix push` run on `goSignals1` counted, for
those 5000 events:

| Collection | Queries | What was being re-asked |
|---|---|---|
| `streams` | 10021 | the same inbound stream record, twice per event |
| `tokens` | 5015 | is this bearer revoked? |
| `cluster_leases` | 5000 | who owns this push stream's transmitter lease? |

Four avoidable round trips per event. None of the three questions changes at
event rate: a stream record changes when an operator changes it, a revocation
when someone revokes, a lease when it changes hands.

Caching any of the three trades staleness for round trips, and the three have
very different tolerances for being stale. A stale stream record is a
correctness problem (ingesting onto a stream that was just disabled); a stale
"not revoked" is a **security** problem; a stale lease owner is neither,
because it only steers a wake-up.

## Decision

Three separate caches, each scoped to what its own question can tolerate.
Nothing is shared between them and there is no general-purpose cache layer.

**1. Request-scoped stream memo — no TTL.** `pkg/services/stream_request_cache.go`
hangs a map off the request `context.Context`. It cannot outlive the handler, so
it needs no expiry: the only staleness it can express is within a single
request. It is opt-in — a context with no memo attached takes byte-for-byte the
old read path — and **every `StreamService` write invalidates the whole memo**,
so a handler that disables or updates a stream and then re-reads it inside the
same request sees the write. That includes the fail-closed disable paths
(`persistDisabledRecord`, `disableInvariantViolation`), which drop the memo
around their `Update`.

**2. Revocation TTL — 2 seconds, with two exact edges.** A revoke issued
*through this node* drops the entry as part of the revoke, so it takes effect
immediately. A **deferred** revocation (ADR 0022 §2 rotate-on-GET grace window)
caps the entry at the token's own `revoked_at`, so the grace window ends when it
says it does rather than up to a TTL late. The TTL therefore bounds exactly one
case: **a peer node revoking a token this node has recently validated.** Two
seconds is the accepted worst-case propagation delay for that case.

Because a stale "not revoked" is a security defect rather than a slow path, the
cache also carries an invalidation generation. A reader captures it before its
store read and the write is refused if a revoke landed in between — without it,
a revoke can be straddled: the reader loads a pre-revoke record, the revoke runs
both its invalidations against a map that has no entry yet, and the reader then
installs "not revoked" for the full TTL.

**3. Push-lease-owner TTL — 2 seconds, as a backstop only.** The authoritative
signal is this node's own acquire / renew / lose / exit transitions, which
update the cache first-hand; the TTL only bounds the case where another node's
lease changed and this node was not party to it. The cached owner **steers a
wake-up and never authorises a delivery** — delivery authority remains the
coordinator's fenced lease check.

The SSTP-client lease is deliberately **not** cached. That lease is acquired,
renewed and released by the dialer in `internal/server`, not by the router, so
there is no first-hand transition for a cache here to hook; it would be a bare
TTL with no invalidation story. The per-event `cluster_leases` cost the profiler
measured was on the push leg, and the SSTP read happens once per fan-out batch.

## Consequences

- **A peer node's revocation is honoured up to 2 s late.** This is the one
  security-relevant window the decision opens, and it is why the TTL is seconds
  rather than minutes. A revoke through the node handling the request is
  unaffected. Deferred revocation is exact, not approximate.
- **The stream memo can serve a stale record only to a caller that bypasses
  `StreamService` to write.** Any new write path must invalidate; the memo is a
  correctness surface, not a convenience.
- Measured on the dev replica set, three runs each side: ingest p50 19.3, 18.5,
  17.9 → 15.1, 13.0, 14.1 ms and 742, 763, 782 → 935, 1041, 1006 ev/s. Profiler
  counts per 5000 events: `streams` 10021 → 5033, `tokens` 5015 → 25,
  `cluster_leases` 5000 → 2.
- The revocation memo is bounded at 4096 entries and swept, then dropped
  wholesale, because JTIs are unbounded over a process lifetime. Dropping costs
  a re-read, never a wrong answer.
- Rejected: one shared cache with a single TTL. The three questions have
  different staleness tolerances and different invalidation hooks, and a shared
  TTL would have to be the shortest of them, which would give back most of the
  saving on the two that can tolerate more.
