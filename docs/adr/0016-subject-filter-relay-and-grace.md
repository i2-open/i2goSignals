<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 16. Subject-filter relay modes, §9.3 removal grace, and anti-oracle posture

Date: 2026-05-20

## Status

Accepted

## Context

goSignals is both an SSF receiver and an SSF transmitter. When a downstream
receiver calls Add/Remove Subject on a goSignals transmitter stream, the change
can be handled three ways: filtered locally (`LOCAL`), relayed 1:1 to the
upstream transmitter (`PASSTHRU`), or both at once (`HYBRID`). Doing this
correctly needs an unambiguous upstream, must honour the SSF §9.3 removal-grace
window, and must not turn the Add/Remove endpoints into a §9.1/§9.2
subject-probing oracle. This ADR records the relay design layered on top of the
filtering architecture in ADRs 0002–0004 (PRD #89 and PRD #97).

## Decision

**Relay-target resolution and config-time validation** (`subject_relay.go`):
`ResolveRelayTarget` finds the feeding receiver stream — an explicitly named
Subject-handler SID (`EventSource.SourceStreamIds`) wins; otherwise an
AUDIENCE-routed stream is matched by issuer equality. Several issuer matches are
ambiguous (reject at config time); none is not-found. `ClassifyUpstreamSupport`
reads the upstream's discovery: an upstream advertising neither add- nor
remove-subject endpoints does not support filtering, so `PASSTHRU`/`HYBRID` is
rejected at config time and `LOCAL` earns a WARN (it still runs).

**HYBRID interested-set is derived, not stored.** The set of downstream streams
interested in a subject is computed from the existing per-stream filters (HYBRID
siblings fed by the same relay-target receiver whose filter still `Selects` the
subject) — no new persisted structure, drift-free and cluster-correct. The relay
fires only on the **0↔1 boundary**, and only against a `defaultSubjects=NONE`
upstream (against an `ALL` upstream, HYBRID is pure local filtering — relaying a
remove could starve a not-yet-created downstream).

**HYBRID relay tracks the *enforced* interest state, not the receiver's
instantaneous request.** A pure helper `planHybridRelay(before, plannedChange,
add, graceSeconds)` returns one of three `RelayDecision`s:

- `Deferred` — a §9.3 stop-delivery change stamped a pending entry; the
  push-transmitter lease owner's backfill sweep (`ListPendingDue`, riding the
  sparse `enforce_at` index) fires the upstream `remove` at `enforceAt` and then
  deletes the local entry. A re-Add during the grace window clears `EnforceAt`
  and fires **no** upstream `add` (the subscription was never dropped).
- `None` — a re-Add of a still-pending entry, or an idempotent re-stop.
- `Immediate` — a fresh Add (true 0→1) or the grace-zero fallback; the handler
  relays synchronously.

**Anti-oracle posture (§9.1/§9.2).** goSignals holds no subject directory, so Add
Subject is a statement of interest that returns `200` regardless of whether the
subject has been seen — it cannot be a §9.1 probe. Upstream relay errors are
logged at `WARN` and **never surfaced downstream**: returning the upstream's
`4xx`/`5xx` verbatim would re-create the very oracle goSignals does not expose
(which subjects an upstream refuses). `PASSTHRU` and `HYBRID` therefore behave
identically on upstream failure — the earlier `PASSTHRU` "return 502" behaviour
is **superseded**.

## Consequences

**Positive**

- Relay is drift-free and cluster-correct with no new DAO — the interested-set
  rides the filters that already exist.
- The §9.3 grace window is honoured end-to-end: local delivery continues while
  the upstream tap stays open until `enforceAt`, and a re-Add does not duplicate
  a subscription that was never dropped.
- No subject-existence oracle on the goSignals Add/Remove endpoints.

**Negative**

- The asymmetric relay variant (relay adds but not removes, or vice-versa) is not
  built.
- A relay-callback error in the deferred sweep must leave the local entry in
  place so the next backfill tick retries — the sweep is not fire-and-forget.

## Related

- ADR 0002 (delivery-time filtering), ADR 0003 (filter storage at scale),
  ADR 0004 (event-source type / relay-mode validation).
- PRD #89 — issues #95 (PASSTHRU relay + relay-target validation), #96 (HYBRID
  refcounted relay); PRD #97 — issues #100 (grace-aware relay decision), #103
  (§9.1/§9.2 posture, relay-error tolerance).
- `internal/services/subject_relay.go`; `docs/subject_processing.md`,
  `docs/security_model.md`.
