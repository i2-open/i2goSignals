# SSF Subject Filtering in goSignals

This document describes how the OpenID Shared Signals Framework §8.1.3 subject
filtering is implemented in goSignals, and what choices an operator has when
configuring it. It is the implementation companion to:

- `CONTEXT.md` — the "Subject filtering vocabulary" section (terms used here).
- `docs/adr/0002-subject-filtering-at-delivery-time.md` — why filtering is
  applied at delivery time, not at routing time.
- `docs/adr/0003-split-subject-filter-storage.md` — the storage shape, the
  per-node match-result cache, and the sparse `enforce_at` index.
- `docs/security_model.md` — the SSF §9 security posture (§9.1 / §9.2 / §9.3).
- `docs/configuration_properties.md` — the environment variables referenced
  below.

It is a deliberate replacement for the file's earlier design-question notes:
those questions are now answered by PRD #89 (subject filtering) and PRD #97
(admin review + §9.3 removal grace).

## What goSignals does

goSignals can sit between SSF transmitters and receivers as a router. A
receiver may want only a *subset* of subjects that the upstream transmitter
sends, and the SSF Add Subject / Remove Subject endpoints (§8.1.3.2 / §8.1.3.3)
are how it expresses that. goSignals' subject-filtering layer is the local
machinery that implements those endpoints:

- It accepts Add Subject / Remove Subject requests from downstream receivers.
- It maintains a per-stream filter table of the non-default subject set.
- It drops events that the filter says should not be delivered, at the moment
  the stream's pending buffer is drained.
- For receiver streams whose downstream transmitter shares an upstream, it can
  relay Add/Remove upstream — directly (`PASSTHRU`) or reference-counted
  (`HYBRID`).
- It defers a delivery-stopping change by a configurable grace period (SSF §9.3,
  "Malicious Subject Removal").
- It exposes a read-only admin review endpoint so an operator can see the
  filter's current state without inspecting the database.

It is **disabled by default**. Operators opt in by setting
`I2SIG_SUBJECT_FILTERING=ENABLED`. When disabled the Add/Remove Subject
endpoints return 404 and are absent from SSF discovery metadata; the §9.3 grace
mechanism and the admin review endpoint are inert.

## Enabling subject filtering

| Env var                       | Effect                                                                                                                                                                            |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `I2SIG_SUBJECT_FILTERING`     | `ENABLED` advertises `add_subject_endpoint` / `remove_subject_endpoint` in SSF discovery and makes `defaultSubjects` settable. `DISABLED` (default) hides the endpoints and returns 404.   |
| `I2SIG_SUBJECT_REMOVAL_GRACE` | Server-wide default for the SSF §9.3 grace window, in seconds. `0` (default) = immediate enforcement. Per-stream overrides on transmitter streams.                                |

When subject filtering is `ENABLED`:

- The endpoints `add_subject_endpoint` and `remove_subject_endpoint` appear in
  the well-known SSF Transmitter Configuration metadata.
- The per-stream `defaultSubjects` field becomes a settable policy knob.
- The admin review endpoint `POST /subject-filter/review` is registered.
- A non-zero `I2SIG_SUBJECT_REMOVAL_GRACE` (or per-stream override) starts
  honouring §9.3 grace behaviour for `LOCAL` and `HYBRID` streams.

Disabling subject filtering after streams have been created leaves any existing
filter rows in the database but stops consulting them — delivery reverts to
"send everything that routes here."

## The two policy axes

A stream has two independent subject-filtering knobs. Together they say what
gets delivered and how Add/Remove requests are honoured.

### `defaultSubjects` (transmitter side, baseline policy)

A goSignals extension — *not* an SSF stream-config field. Two values:

- **`ALL`** — every subject that routes to this stream is delivered by default.
  The filter table holds the subjects that have been *removed*.
- **`NONE`** — no subject is delivered by default. The filter table holds the
  subjects the receiver has explicitly *added*.

It is a *default*, not a delivery guarantee. Per SSF a transmitter MAY ignore
Add/Remove requests and MAY deliver subjects out-of-band on its own policy. So
a `NONE` upstream can still send subjects goSignals never added; an `ALL`
upstream may withhold some. goSignals therefore applies the downstream filter
to **whatever arrives**, judged purely on the downstream stream's own
`defaultSubjects` + filter table, never on how or why the event arrived.

Changing `defaultSubjects` on a live stream is a deliberate reset: the filter
table is cleared, because old entries carry the opposite meaning under the new
baseline. The reset bypasses the §9.3 grace period (it is an operator action,
not the §9.3 threat).

### `subjectFilterMode` (receiver side, relay strategy)

A setting on a **receiver stream** giving the operator explicit control over
how Add/Remove Subject requests arriving at the fed downstream transmitter
streams are handled:

- **`PASSTHRU`** — raw 1:1 relay of Add/Remove to the upstream transmitter.
  No reference counting, no local filtering. Downstream transmitter streams
  share one upstream subscription and share fate: one downstream's Remove
  removes the subject for all. goSignals keeps **no local filter table** for a
  `PASSTHRU` stream. The upstream transmitter's own §9.3 handling is
  authoritative.
- **`LOCAL`** — filter locally, independently per downstream transmitter
  stream. The upstream is never touched. Mandatory when the upstream does not
  advertise Add/Remove endpoints, or when events arrive by means other than an
  SSF stream (e.g. direct POST).
- **`HYBRID`** — reference-counted relay *and* local fan-out filtering, so each
  downstream sees only the subjects it asked for. goSignals tracks, per subject
  handler + subject, the set of interested downstream streams; it relays an
  `add` upstream when the set goes 0→1 and a `remove` only when it goes 1→0.
  `HYBRID` is meaningful **only against a `defaultSubjects=NONE` upstream** —
  against an `ALL` upstream everything already arrives, so it behaves as pure
  local filtering. It is **required** for a `NONE` upstream that fans out to
  multiple selective downstreams, because a `LOCAL`-only stream would never
  see events for subjects the upstream had not been asked about.

`PASSTHRU` and `HYBRID` further require:

- The upstream to advertise `add_subject_endpoint` / `remove_subject_endpoint`
  in its SSF Transmitter Configuration metadata.
- An unambiguous **subject handler** — when several receiver streams share an
  issuer, the operator MUST nominate the relay target at configuration time via
  Explicit (SID) event source. The configuration is rejected otherwise.

The associated **event source** axis (`DIRECT` / `AUDIENCE` / `EXPLICIT`)
further constrains mode validity; `validateSubjectRemovalGrace` and the other
config validators reject inconsistent combinations at stream-update time, not
at runtime.

## Add Subject / Remove Subject

The standard SSF §8.1.3.2 / §8.1.3.3 endpoints. goSignals' behaviour:

- `Add Subject` POST returns **200** regardless of whether the subject has ever
  been seen on the wire. `defaultSubjects` is policy, not a delivery guarantee;
  the endpoint is therefore a *statement of interest*, not a directory lookup.
  This is deliberate §9.1 posture — goSignals does not expose a probing oracle
  (see `docs/security_model.md` §9.1).
- `Remove Subject` POST returns **204**.
- Both carry `stream_id`, `subject`, and (Add only) an optional `verified`
  flag. `verified` is stored for audit and relayed upstream verbatim but does
  not influence delivery — goSignals is not an identity verifier.
- A receiver token authorizes only its own stream. An admin-scoped caller may
  target any stream by supplying `stream_id` — no separate administrative
  mutation API exists.
- Add/Remove take effect for **future events only** — there is no replay. A
  receiver that wants history uses `ResetDate` / `ResetJti` instead.

**Relay errors are tolerated.** When goSignals relays an Add or Remove
upstream on a `PASSTHRU` or `HYBRID` stream and the upstream returns 404, any
other 4xx, 5xx, or a transport error, goSignals logs the upstream response at
`WARN` and **returns success to the downstream receiver**. Surfacing the
upstream status verbatim would re-create the §9.1 oracle goSignals does not
expose for itself; the local filter write (for `HYBRID`) and the receiver's
expression of interest are authoritative; the upstream subscription is
best-effort.

## When the filter is applied

The filter is consulted at **delivery time**, not at routing time. The decision
is `Allows(stream, event) → deliver | drop`. See
`docs/adr/0002-subject-filtering-at-delivery-time.md` for the rationale; the
short version is that routing runs on whichever node ingests an event, so a
routing-time filter would force every node to hold every stream's filter with
no existing cluster channel to keep them consistent.

- **PUSH** — in `runPushLoop` on the node holding the
  `push-transmitter:<sid>` lease. A filtered-out JTI is **discarded (acked),
  not pushed** — the pending list still drains and stays bounded. The filter
  is read from Mongo through a per-node match-result cache (see ADR-0003);
  Add/Remove on any node triggers a cluster wake-up to the lease owner so the
  cache stays correct.
- **POLL** — at poll-response time on whichever node serves the poll. The
  filter is read straight from Mongo (polls are cold and batched).
- **Operational events** (`Operational=true` — `verify`, `stream-updated`)
  carry no subject and always pass the filter.

## Storage shape

A subject filter may legitimately reach **millions of entries** (a watchlist
of every account or email a receiver cares about), so the storage is split by
subject kind. See `docs/adr/0003-split-subject-filter-storage.md` for the
amendment; the highlights:

- **Simple subjects** (the §8.1.3.1 "exactly identical" match) canonicalize
  per RFC9493 per-format rules to one stable key and live in a hash-indexed
  set: O(1) membership.
- **Complex subjects** (field-wise with undefined-as-wildcard) cannot collapse
  to a single key, so they sit in a small linear-scanned list. Complex
  subjects are the rare device/session composites; the list stays short in
  practice.
- A per-node, bounded-size, short-TTL **match-result cache** absorbs the hot
  re-lookups when many events arrive about the same subject in a short window.
  PUSH and POLL both go through it.
- A **sparse partial index on `enforce_at`** (the §9.3 grace timestamp) makes
  pending removals enumerable for the admin review endpoint and the
  push-transmitter sweep without scanning the whole table. The index is
  sparse: only entries currently inside their grace window carry the field.

Cache accuracy is deliberately soft. A stale **"deliver"** merely
over-delivers for a few seconds — harmless, and consistent with §9.3's
tolerance for events delivered after a removal. A stale **"drop"** is the
hazardous direction, so cluster invalidation fires promptly on
delivery-*increasing* operations (Add). Delivery-*decreasing* operations are
already softened by the §9.3 grace period.

Both the Mongo and in-memory DAOs implement the storage shape mechanically the
same way (`internal/dao/mongo/subject_filter_dao.go`,
`internal/dao/memory/subject_filter_dao.go`).

## SSF §9.3: removal grace period

A configurable interval during which a subject whose delivery was just
*stopped* continues to be delivered, so a malicious or coerced receiver cannot
instantly blind a downstream by quietly removing a victim subject.

### Rules

- **Gate the effect, not the verb.** Any operation that *stops* delivery for a
  subject — regardless of whether it was Add or Remove, regardless of `ALL`/
  `NONE` — is deferred by the grace period. Any operation that *starts or
  resumes* delivery takes effect immediately.
- **Re-Add cancels.** A re-Add during the grace window revives the entry and
  clears `enforce_at`. The entry lifecycle is upsert / stamp / lazy-purge —
  never a mid-grace hard delete.
- **`LOCAL` and `HYBRID` local fan-out only.** `PASSTHRU` adds no grace of its
  own — the upstream transmitter's §9.3 handling is authoritative.
- **`defaultSubjects` flip bypasses grace.** A flip is a deliberate operator
  action, not the §9.3 receiver-initiated threat. The flip clears the filter
  table immediately and discards any pending removals.
- **Implemented as a timestamp, not a scheduler.** Stopping delivery stamps
  the entry with `enforce_at = now + grace`. The delivery-time filter treats
  a pending-removal entry as **still active until `now ≥ enforce_at`**. Pure
  lazy comparison: restart-safe, cluster-safe, no scheduled job.
- **Events delivered during the grace window are normal deliveries** (per
  SSF §9.3); they flow through the unmodified delivery path and the receiver
  must not treat them as errors.

### HYBRID deferred upstream `remove`

When a `HYBRID` interested-set goes 1→0, goSignals does **not** relay the
upstream `remove` immediately. The deferral is to the same `enforce_at`, so
the upstream keeps feeding events through the grace window and §9.3 is honored
consistently with `LOCAL`. The deferred relay fires from a sweep on the
**`push-transmitter:<sid>` lease owner**, reusing the existing
recovery/backfill ticker (`internal/eventRouter/event_router.go`
`sweepDeferredHybridRelays`) — no new scheduler is introduced. A re-Add (set
0→1) before `enforce_at` cancels the pending upstream `remove`.

### Configuring the grace

- **Server-wide default**: `I2SIG_SUBJECT_REMOVAL_GRACE`, in seconds.
  `0` (default, or unset) = immediate enforcement, no behavior change.
  Negative or non-integer values fall back to `0`.
- **Per-transmitter-stream override**: `subject_removal_grace_seconds` on the
  stream's `StreamStateRecord`, set via the management API. `0` means
  immediate. Streams with different risk profiles can carry different
  windows.
- **Receiver-stream values are ignored with a `WARN`**, mirroring how
  `defaultSubjects` is treated on a receiver stream — the knob lives on the
  same record but is only honoured on the side where it has meaning.
- The override is validated alongside the other PRD #89 mode/event-source
  config rules at stream-update time, so a misconfiguration is caught before
  it can change runtime behaviour.

## Admin review endpoint

`POST /subject-filter/review` (PRD #97 issue #101): a read-only view of a
stream's locally managed subject filter. Authorized with the goSignals admin
scope (`ScopeStreamAdmin`, `ScopeStreamMgmt`, or `ScopeRoot`) — distinct from
the per-stream receiver scope used by the SSF Add/Remove endpoints. A
receiver-scoped token is rejected.

**Request body:**

```json
{
  "stream_id": "...",
  "subject": { "format": "email", "email": "alice@example.com" }
}
```

`stream_id` is required. `subject` is optional; supplying it adds a point-
lookup result to the response. The endpoint is deliberately not paginated and
does not enumerate the filter table — the hash index makes "is subject X
filtered here?" O(1), and millions of rows are never streamed to an operator
(ADR-0003).

**Response body:**

```json
{
  "stream_id": "...",
  "mode": "LOCAL|HYBRID|PASSTHRU",
  "default_subjects": "ALL|NONE",
  "event_source": { "type": "AUDIENCE|EXPLICIT|DIRECT", ... },
  "subject_removal_grace_seconds": 0,
  "passthru_no_local_filter": false,
  "counts": { "total": 0, "pending": 0 },
  "pending": [
    { "subject": { ... }, "canonical_key": "...", "kind": "email", "enforce_at": "..." }
  ],
  "lookup": {
    "subject": { ... },
    "found": true,
    "kind": "email",
    "canonical_key": "...",
    "enforce_at": "...",
    "pending": false,
    "delivers": true
  }
}
```

A `PASSTHRU` stream returns `passthru_no_local_filter=true` and omits
`counts` / `pending` — there is no local filter table to summarize. That
behaviour is explicit, not an error.

**Status codes:**

| Status | Meaning                                                                                  |
| ------ | ---------------------------------------------------------------------------------------- |
| 200    | Review returned.                                                                         |
| 400    | Malformed body or missing `stream_id`.                                                   |
| 401    | Unauthenticated.                                                                         |
| 403    | A stream-bound token names a different stream than `stream_id`.                          |
| 404    | Subject filtering disabled server-wide, or the stream does not exist.                    |
| 500    | DAO error.                                                                               |

## CLI tooling

`cmd/goSignals` exposes the operator surface against the same endpoint and the
existing PRD #89 stream-update path:

```text
goSignals> review subject-filter [<alias>] [--subject '<SubjectIdentifier JSON>']
goSignals> subject-filter show [<alias>]
goSignals> subject-filter set  [<alias>]
                                  [--default-subjects ALL|NONE]
                                  [--mode PASSTHRU|LOCAL|HYBRID]
                                  [--event-source DIRECT|AUDIENCE|EXPLICIT]
                                  [--grace-seconds <n>]
```

- **`review subject-filter`** prints the summary (counts + pending list) by
  default; `--subject '<SubjectIdentifier JSON>'` opts in a point-lookup
  result. The CLI never dumps the full filter table — the server endpoint is
  point-lookup + counts by design.
- **`subject-filter show`** prints the four operator knobs alone
  (`defaultSubjects`, mode, event source, grace override) — the policy
  fields without the filter-table summary.
- **`subject-filter set`** writes the same four knobs through the existing
  stream-update path (no new server endpoint). Empty/omitted fields mean "do
  not change". After the update it re-reads the persisted settings via the
  review endpoint, so the post-update display surfaces the server's
  WARN-and-ignore behaviour for a grace override set on a receiver stream
  (the persisted value comes back as 0).

Administrative subject mutation reuses the SSF endpoints — there is no
"admin add" / "admin remove" verb. An admin-scoped caller targets any stream
by supplying its `stream_id` on the existing Add/Remove Subject endpoints.

## SSF §9 security posture

goSignals' full §9 posture is documented in `docs/security_model.md` ("SSF §9
Subject Filtering Security Posture"). The short version:

- **§9.1 Subject Probing.** goSignals maintains no subject directory and never
  returns 404 for "subject unknown" — its only 404 is feature-disabled
  (capability statement). Add Subject is treated as a statement of interest,
  not a directory lookup. Upstream relay errors are absorbed and not surfaced
  to the downstream receiver, so an upstream's §9.1 oracle is not transitively
  exposed.
- **§9.2 Information Harvesting.** Not solved (it is a property of the
  receiver's authorization model), but the blast radius is contained: a
  receiver token is scoped to a single stream; subject filtering is opt-in
  server-wide; the review endpoint that exposes filter state requires the
  admin scope, distinct from the per-stream receiver scope.
- **§9.3 Malicious Subject Removal.** Addressed by the removal grace period
  described above.

## Quick reference

**Environment variables** (full reference in
`docs/configuration_properties.md`):

| Variable                      | Default     | What it does                                                                                  |
| ----------------------------- | ----------- | --------------------------------------------------------------------------------------------- |
| `I2SIG_SUBJECT_FILTERING`     | `DISABLED`  | Server-wide gate for the SSF subject-filtering endpoints, advertisement, and §9 layer.        |
| `I2SIG_SUBJECT_REMOVAL_GRACE` | `0`         | Server-wide default §9.3 grace in seconds. Per-stream override via the management API.        |

**Per-stream fields** (`StreamStateRecord`, set via the management API):

| Field                            | Side           | Effect                                                                  |
| -------------------------------- | -------------- | ----------------------------------------------------------------------- |
| `default_subjects`               | Transmitter    | `ALL` or `NONE` baseline delivery policy.                               |
| `subject_filter_mode`            | Receiver       | `PASSTHRU` / `LOCAL` / `HYBRID` relay strategy.                         |
| `event_source.type`              | Transmitter    | `DIRECT` / `AUDIENCE` / `EXPLICIT` — constrains mode validity.          |
| `subject_removal_grace_seconds`  | Transmitter    | §9.3 grace override (seconds). `0` = immediate. Receiver-side: WARN.    |

**Key files** (for future readers):

- `internal/services/subject_filter_service.go` — Add/Remove, RelayDecision,
  grace plumbing, deferred-relay sweep entry point.
- `internal/services/subject_grace.go` — pure §9.3 timestamp logic (the
  cheapest test surface).
- `internal/services/subject_filter_review.go` — review request handling
  (point lookup, counts, pending list).
- `internal/services/subject_filtering.go` — env-var parsing and the
  `SubjectFilteringEnabled()` gate.
- `internal/services/stream_service.go` — config validation
  (`validateSubjectRemovalGrace`, `applyRemovalGraceOverride`).
- `internal/server/api_subject_filter_review.go` — the admin endpoint.
- `internal/server/api_stream_management.go` — Add/Remove handler with WARN-
  and-tolerate on upstream relay errors.
- `internal/eventRouter/event_router.go` — `sweepDeferredHybridRelays`,
  called from the existing push-transmitter backfill ticker.
- `internal/dao/{mongo,memory}/subject_filter_dao.go` — storage adapters
  with the sparse `enforce_at` partial index.
- `cmd/goSignals/commands.go` — `ReviewSubjectFilterCmd`,
  `SubjectFilterShowCmd`, `SubjectFilterSetCmd`, `SubjectFilterCmd`.
