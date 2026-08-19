<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 32. The supported-event catalog is extensible by configuration

Date: 2026-08-19

## Status

Accepted (GH #261)

## Context

`model.GetSupportedEvents()` was a compiled-in list: the SCIM (RFC 9967), CAEP,
RISC and WISE packs, and nothing else. Three surfaces read it, and together they
make the catalog a routing gate rather than a mere advertisement:

- registration negotiates `events_delivered = events_requested ∩ events_supported`
  (SSF 1.0 §7.1.1), for SSF streams and for each direction of an SSTP pair;
- the router matches a SET's event types against `events_delivered`
  (`matchesEventType`);
- validator engagement is computed from `events_delivered` ∩ catalog.

The consequence for an event type outside the catalog was a silent drop. The
registration succeeded with `201` and a non-empty `events_requested`; the
negotiated `events_delivered` was empty; SETs carrying that type were accepted,
verified, persisted and counted — and matched no stream, so they were never
routed. `"*"` short-circuited to the same catalog, so no registration input was a
workaround. ADR 0031 fixed the SSTP inbound `RouteMode` gate, and the aud-routed
two-hop topology it was filed for still did not carry a custom vocabulary,
because the vocabulary was the second gate.

The catalog is deliberately narrow — see the `WiseEvents` comment: it advertises
only what `pkg/goSetValidate` can vouch for, so an advertised type is never one
that reports Unsupported and is rejected by a STRICT receiver. That reasoning is
right for the *built-in* packs and wrong as a hard limit: a deployment routing
its own event vocabulary through goSignals cannot recompile the gateway, and
should not have to.

## Decision

A server-level environment variable, `I2SIG_EVENT_TYPES_EXTRA`, extends the
catalog for the process. `GetSupportedEvents()` returns the built-in packs plus
the configured extension; every existing caller therefore sees one consistent
set with no new wiring.

- **Read in `pkg/ssfModels`, not injected.** The catalog is consumed by the CLI,
  the services layer and the server, and an injected value would have to be
  plumbed to each — three chances to miss one and produce two disagreeing
  catalogs in one process. Reading `os.Getenv` at the single point of truth
  cannot disagree with itself. The variable is read with `os.Getenv` rather than
  through the deprecated-alias shim (`internal/envcompat`) because it is new and
  has no pre-v0.11.0 spelling to be aliased from — and reading it directly keeps
  `pkg/ssfModels`, the one package the standalone `goSet*` libraries sit beside,
  from taking an `internal/` dependency for a lookup with nothing to translate.
- **Parsed once per distinct raw value, not once per process.** A `sync.Once`
  would make the variable untestable with `t.Setenv`; parsing on every call would
  re-emit the invalid-entry `WARN` on a path that runs per registration and per
  received SET. Memoizing on the raw string gives both.
- **Entries must be absolute URIs.** An event type is an identifier a peer puts
  on the wire, so a relative reference could never appear in a SET's `events` map
  and would only pollute `events_supported`. A rejected entry is named in a
  `WARN`: the failure it causes is otherwise invisible.
- **Duplicates are dropped, case-insensitively.** `events_supported` is a set and
  `"*"` resolves `events_delivered` straight out of it, so a duplicate would be
  advertised twice and negotiated twice onto every wildcard stream.
- **A `PATCH` re-negotiates against the live catalog.** `UpdateStream` previously
  negotiated against the *request's* `events_supported`, falling back to the
  stream's stored copy. Both are wrong here: the stored copy is a snapshot taken
  at create, so re-negotiating against it would make a newly configured
  vocabulary permanently unreachable for every pre-existing stream —
  delete-and-recreate as the only remedy — and the request's copy is a
  client-supplied value for a field SSF 1.0 §7.1.1 declares **Read-Only**, which
  a receiver could otherwise use to widen its own `events_delivered` past what
  this transmitter supports. `UpdateStream` now ignores the request's copy
  outright and negotiates against `GetSupportedEvents()`, refreshing the stored
  catalog alongside so `events_delivered ⊆ events_supported` holds.
- **No validator is synthesized.** An extended URI has no built-in payload
  validator and takes the existing Unsupported path per validation mode
  (ADR 0029): forwarded under `NONE`/`WARN`/`ENFORCE`, rejected under `STRICT`.

## Consequences

**Positive**

- A private or not-yet-published event vocabulary can be negotiated and routed
  end to end — push, poll and SSTP — without a fork or a rebuild. The aud-routed
  two-hop SSTP topology of #261 works.
- Behaviour with the variable unset is byte-for-byte unchanged, so the extension
  is invisible to every existing deployment.
- The catalog↔validator drift guards (`*_validator_coverage_test.go`) are
  unaffected: they select by pack URI prefix over the built-in half, which is now
  a named function (`builtinEventTypes`).

**Negative**

- A catalog entry can now exist that `pkg/goSetValidate` cannot vouch for, which
  is exactly the situation the narrow `WiseEvents` list was written to avoid. It
  is opt-in and one mode deep: an operator who configures a vocabulary and runs
  `STRICT` will have their own events rejected. Documented at the variable.
- The catalog becomes process-scoped configuration rather than a build constant,
  so two nodes in a cluster with different values will negotiate different
  `events_delivered` for otherwise identical registrations. Operators must set it
  uniformly across the cluster — and across every node in a multi-hop path.
- Extension is registration-time, not retroactive: records already persisted keep
  the `events_delivered` they negotiated until they are updated or recreated. For
  an **SSTP pair** that means recreated — `updateSstpPair` is a narrow patchable
  whitelist (Q35) that does not touch events, so a pair provisioned before the
  vocabulary was configured cannot pick it up by `PATCH`. Widening that whitelist
  is a separate decision, deliberately not taken here.
- Making `events_supported` genuinely Read-Only is a behaviour change beyond the
  catalog itself: a client that had been sending `events_supported` on a `PATCH`
  and relying on it to steer negotiation now sees it ignored. The field was
  already documented Read-Only and the previous behaviour was a way to inject
  arbitrary types into a stream's `events_delivered`, so this is a correction
  rather than a regression — but it is visible.

## Related

- ADR 0011 — `I2SIG_<AREA>_*` environment-variable taxonomy. This ADR opens the
  `EVENT` area under it, with the matching `## Event` section in
  `docs/configuration_properties.md` that the taxonomy requires.
- ADR 0029 — event-validation modes and the validator registry (the Unsupported
  path an extended URI takes).
- ADR 0031 — SSTP inbound honours its direction's `RouteMode` (the first gate;
  this ADR removes the second).
- GH #261 — the silent-drop bug and its reproducer.
- `docs/configuration_properties.md` § Event — the operator-facing reference.
- `docs/SSTP.md` § Routing also requires the event type to be in the catalog.
