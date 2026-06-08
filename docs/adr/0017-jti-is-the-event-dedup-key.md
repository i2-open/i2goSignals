<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 17. JTI is the event dedup key

Date: 2026-06-07

## Status

Accepted

## Context

RFC 8417 §2.2 requires that every Security Event Token carry a globally unique
`jti`. goSignals nevertheless treated `eventCol` as an append-only log: there
was no unique index on `jti`, and the two `EventDAO` implementations diverged on
duplicate behaviour. The Mongo DAO inserted a fresh document on every call and
grew duplicate rows; the memory DAO silently overwrote the prior entry in its
`map[jti]Event`. Neither path told the router that the event had already been
seen, so a re-delivery (a receiver retry, a transmitter recovery sweep, a poll
reissue) was treated as a brand-new event: `eventsIn` double-incremented, the
matcher fanned the event out to every outbound stream a second time, and push
buffers re-enqueued a JTI they had already delivered. The duplicate was visible
downstream as a second SET on the wire — a protocol-level surprise that RFC 8417
explicitly forbids.

The same gap blocks SSTP. The crash-recovery model in
draft-hunt-secevent-sstp-00 relies on the transmitter being able to ingest the
same SET twice and have the second ingestion be a single-document atomic no-op
— i.e. on JTI uniqueness being enforced inside the persistence layer, not
re-derived above it. PRD #153 closes the gap as a prerequisite for SSTP and as a
correctness fix for the existing RFC 8935 and RFC 8936 paths.

## Decision

The JTI is the persistence-layer deduplication key for `eventCol`. There is no
`(jti, sid)` compound key — RFC 8417 already promises global JTI uniqueness, and
goSignals is one transmitter scope, so JTI alone is sufficient.

The contract is enforced at the storage edge and carried up to the router as a
typed sentinel:

- **Mongo DAO** (`internal/dao/mongo/event_dao.go`): a sparse-unique index on
  `eventCol.jti` is created at startup (in
  `internal/providers/dbProviders/mongo_provider/provider.go`). Inserts that
  violate it surface as MongoDB error code 11000; the DAO translates that into
  the exported sentinel `interfaces.ErrDuplicateJTI`.
- **Memory DAO** (`internal/dao/memory/event_dao.go`): a map-existence check
  before insert returns `interfaces.ErrDuplicateJTI` directly. No silent
  overwrite.
- **Event service** (`internal/services/event_service.go`) loads the existing
  record via `FindByJTI` on the sentinel branch and returns
  `(existingRec, ErrDuplicateJTI)` — the storage edge is authoritative; the
  service does not pre-check (which would race). An INFO log line
  `"Duplicate JTI ingestion suppressed"` (with `jti` and `sid`) records the
  no-op.
- **Router** (`internal/eventRouter`) short-circuits on
  `errors.Is(err, interfaces.ErrDuplicateJTI)`: `eventsIn` is *not* incremented
  a second time, the matcher does not run, no JTI is added to any outbound
  stream's pending queue, and no push/poll buffer is woken. The handler
  returns 202 Accepted, matching the RFC 8935 idempotency expectation.

At server startup the Mongo provider runs a one-shot safety net: if duplicate
JTIs already exist in `eventCol`, the sparse-unique index creation is skipped
and a WARN is logged with a remediation hint pointing at the release-note
cleanup snippet. Duplicate-suppression is OFF until the operator deletes the
extras and restarts. The missing index is also visible to operators as an
`eventsIn` discrepancy in the Prometheus view. Documented in the v0.12.0
release notes alongside a Mongo shell snippet for cleanup.

## Consequences

### Positive

- Idempotent ingestion across all three delivery methods: RFC 8935 push,
  RFC 8936 poll, and (subsequently) SSTP. A re-delivered SET is a no-op at the
  storage edge and never reaches the matcher.
- `eventsIn` and outbound fan-out stop double-counting on retries; metrics
  reflect distinct events rather than wire deliveries.
- SSTP's single-document atomic crash-recovery contract is satisfied without
  adding an SSTP-specific dedup table — the persistence layer is already
  idempotent.
- The sentinel `interfaces.ErrDuplicateJTI` gives every caller (router today,
  SSTP handler tomorrow) one stable signal to branch on.

### Negative

- Modest write-path cost: every ingestion is a unique-indexed insert rather
  than an unchecked append. Acceptable — the index is sparse and the duplicate
  case is rare in steady state.
- One-shot operational work for deployments that already carry duplicate JTIs:
  the startup safety-net leaves the index off until the duplicates are cleared.
  Mitigated by the WARN log line and the release-note cleanup snippet.
- No `(jti, sid)` escape hatch — a buggy upstream that re-uses JTIs across
  different logical events will be rejected, surfacing the upstream bug rather
  than masking it. This is the intended behaviour under RFC 8417 §2.2.

## Related

- PRD #153 — Idempotent SET ingestion (this ADR is the documentation slice).
- Issue #155 — sentinel + memory DAO + service + router short-circuit.
- Issue #156 — Mongo DAO translation + sparse-unique index + startup safety-net.
- ADR 0010 (provider decomposition) — the per-domain DAO seam this contract
  rides on.
- RFC 8417 §2.2 (`jti` globally unique), RFC 8935 §2.4 (push idempotency),
  draft-hunt-secevent-sstp-00 (crash recovery relies on single-document
  atomic idempotency).
- `internal/dao/interfaces` (sentinel),
  `docs/releases/v0.12.0.md` (operator-facing migration note).
