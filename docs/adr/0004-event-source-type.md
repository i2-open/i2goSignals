<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Event-source Type as a transmitter declaration

A transmitter stream's `event_source.type` is one of `DIRECT`, `AUDIENCE`, or
`EXPLICIT` — an operator declaration of where the stream's events originate.
It is consulted at **stream-create / stream-update time** to validate the
chosen subject-filter relay mode and to enforce the `EXPLICIT ⇔
source_stream_ids` pairing. The runtime pivot — at the moment a subject
filter Add/Remove must resolve its upstream relay target — is the
**presence of `source_stream_ids`**, not the Type tag itself
(`ResolveRelayTarget` in `internal/services/subject_relay.go`). Type is a
config-time guard; `source_stream_ids` is the runtime witness.

Three values, three operator meanings:

- **`DIRECT`** — events arrive in Mongo by means other than an SSF stream
  (another service writes to the pending event list, or events are POSTed
  directly to the stream's inbound endpoint). There is no upstream SSF
  transmitter to relay subject filter Add/Remove to, so `LOCAL` is the only
  valid subject-filter mode.
- **`AUDIENCE`** — events are routed in by `iss`/`aud`/event-type matching
  from a receiver stream (the historical default). The relay target is the
  receiver stream whose `iss` matches the transmitter stream's `iss`. If
  several receivers share that `iss`, the configuration is ambiguous and
  must be resolved with `EXPLICIT`.
- **`EXPLICIT`** — the operator names the source stream SID(s) in
  `source_stream_ids`. The first SID is the relay target. Used when
  `AUDIENCE` matching is ambiguous (e.g. a cluster of upstreams transmitting
  on the same audience) — the operator nominates the **subject handler**.

Validation rules enforced at create/update time:

- **R1.** `Type=DIRECT` + `subject_filter_mode ∈ {PASSTHRU, HYBRID}` → reject.
  A DIRECT stream has no upstream to relay to.
- **R2.** `Type=EXPLICIT` with empty `source_stream_ids` → reject.
- **R3.** `Type ≠ EXPLICIT` with non-empty `source_stream_ids` → reject.
- **R4.** `EventSource` set on a receiver stream → WARN-and-drop, mirroring
  the `subject_removal_grace_seconds`-on-receiver precedent
  (`applyRemovalGraceOverride` in `internal/services/stream_service.go`).

Unset `Type` defaults to `AUDIENCE`. The defaulting is silent — it matches
the historical behavior, lets pre-existing streams keep working, and keeps
the Type tag genuinely optional for the common case.

## Considered options

- **Make Type the runtime pivot.** Reimplement `ResolveRelayTarget` to
  branch on `Type` rather than on `source_stream_ids` presence. Rejected:
  duplicates the source of truth (every EXPLICIT stream necessarily already
  has `source_stream_ids`), and inflates the surface for stale/inconsistent
  state.
- **Auto-derive Type at create/update.** Compute `Type` from
  `source_stream_ids`-presence and issuer-matching. Rejected: obscures
  operator intent (the operator stating "this is DIRECT, I run it
  out-of-band" is meaningfully different from "the system inferred DIRECT
  because no receiver matched"), and turns a clear config error into a
  silent demotion.
- **Require explicit Type whenever `subject_filter_mode` is set.** Rejected:
  back-incompatible with pre-PRD-97 streams that have no Type set, and
  needlessly noisy for the common AUDIENCE case.

## Consequences

- The wire-and-storage shape (`pkg/ssfModels/model_stream_state.go`
  `EventSource{Type, SourceStreamIds}`) is unchanged from PRD #89.
- `validateSubjectFilterMode` in `internal/services/stream_service.go`
  gains R1–R3; `applyEventSource` (new, alongside the existing
  `applyRemovalGraceOverride`) handles R4.
- The CLI's existing `EXPLICIT ⇔ --source-stream-ids` pairing check
  (`cmd/goSignals/commands.go:2356-2360`) is no longer the only line of
  defense, but stays for fail-fast and clearer error messages.
- `ResolveRelayTarget`'s SID-first / issuer-match-fallback behavior is
  unchanged — it never had to read `Type`, and still doesn't.
- An operator-facing summary of all four knobs lives in
  `docs/subject_processing.md`; this ADR is the design record behind why
  Type is shaped this way.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub><img src="../../brand/logo/gosignals-favicon-simple.svg" width="12" height="12" alt="goSignals"> (C)2026 Independent Identity Inc.</sub></p>
