<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 48. Delivered ping events are purged after 24 hours

Date: 2026-10-27

## Status

Accepted (community and enterprise; spec planning#142). Overrides planning
ADR 0055's keep-forever default for ping events only.

## Context

A ping event is an SSF Verification Event, whoever sent it (see
`CONTEXT.md`). goSignals transmits one as the push keepalive (every 5
minutes per idle push stream by default, `I2SIG_PUSH_KEEPALIVE_INTERVAL`)
and on an operator `POST /verify`, and stores every one it receives from a
peer. Pings are diagnostic, not data: they are worth keeping for a day to
answer "was this stream alive yesterday afternoon", and nothing after that.

Planning ADR 0055 made keep-forever the default for every event. The
community server binds no retention engine, and the enterprise server's
retention driver applies per-stream data retention only, so in both servers
a ping on a keep-forever stream is never removed. At one keepalive per
stream every 5 minutes, a 1,000-stream deployment stores about 288,000
pings a day.

## Decision

1. **Scope.** A ping that has been delivered on every stream that queued
    it, or that was received and never queued anywhere, is purged once it
    is 24 hours older than the time this server stored it. A ping still
    pending on any stream is never purged (ADR 0055 A5.22). Data events
    keep their own retention (ADR 0055, ADR 0077, enterprise per-stream
    retention); nothing here changes them.
2. **Outside family-retention policy.** The ping purge is not an ADR 0055
    family rule, so the A5.30 seven-day floor does not apply. When the
    A5.36 event-side legal hold is built, it gates the ping purge like any
    other body delete.
3. **Clock on the body.** `EventRecord` gains a server-stamped
    `ReceivedAt`, in the shape ADR 0055 A5.23 and planning#75 expect, so
    the later event-family work reuses it. `deliveries.createdAt` is not the
    clock: a ping that was never queued has no delivery row, and re-pending
    rewrites it. Bodies stored before the upgrade fall back to their Mongo
    ObjectId timestamp.
4. **Setting.** `I2SIG_PING_RETENTION` (Go duration, default `24h`; `0`
    turns the purge off; an unparseable value warns and uses the default).
    The 6-hour run interval and the first-run delay after start are fixed
    in code, not settings.
5. **One runner per cluster.** A cluster-wide lease, taken through
    `ClusterCoordinator` with its fencing token, picks the one node that
    purges. The coordinator stores the cluster's last purge time, and the
    next run is due 6 hours after it, whichever node takes the lease. The
    stream-table reaper exempts this lease kind, so its row and the last
    purge time survive between runs.
6. **One runner, both servers.** The purge runner is exported from
    community `pkg/` and takes the `EventDAO` and the coordinator. The
    community server and the enterprise server each start it.
7. **Delete shape.** Each run deletes with query-based `deleteMany` calls,
    one per time window, oldest window first, with a fixed pause between
    windows. Delivery rows of pings carry a marker so they can be selected
    by query. Delivery rows go first; a ping body is deleted only when no
    pending delivery row references it. A run stops between windows if the
    node loses the lease or is shutting down, and the next run picks up
    from the oldest remaining window.
8. **Visibility is logs only.** Each server's startup retention-posture
    line states ping retention (or that the purge is off), and each run
    logs one INFO summary: delivery records deleted, bodies deleted,
    windows processed, duration. No metrics.
9. **No `compact`.** Mass deletes leave free space inside the collection
    files; reclaiming it with `compact` stays an operator action,
    documented in `docs/operations.md`.

## Considered options

- **Every node purges, idempotently**, as `purgeClusterRows` does for
    cluster rows. Rejected: N nodes issue the same deletes against the same
    documents, multiplying the load the purge must keep off the event path.
- **A MongoDB TTL index** (a partial TTL index can target pings). Rejected:
    the TTL monitor runs on its own schedule with no pause between batches,
    and it cannot express "no pending reference remains".
- **Delete by ID list** (find a batch of JTIs, then delete them). Rejected:
    two round trips per batch and client-side work, where a time-window
    query lets the server select and delete in one call.
- **One unbounded `deleteMany`.** Rejected: MongoDB deletes one document
    at a time and writes one oplog entry each, so a large first run becomes
    one long operation and a replication-lag burst. Time windows with a
    pause bound both.
- **Community server only.** Rejected: the enterprise business router
    generates the same keepalives, so leaving it out keeps the problem.

## Consequences

- The purge needs the `ReceivedAt` field, the ping marker on delivery rows
    (backfilled, or handled by the first-run drain), and indexes for the
    type + time query on both collections. Building those indexes on a large
    existing collection has its own cost, which the release notes call out.
- The first run on an upgraded deployment is a drain of everything stored
    before it, not one day's worth. Oldest-first windows with a pause make
    that drain safe to spread over several runs.
- Enterprise's daily retained-event metering counts delivered ping
    references, so the purge lowers that count.
- The memory adapter implements the same purge, so the two DAO adapters
    stay mechanically equivalent.
