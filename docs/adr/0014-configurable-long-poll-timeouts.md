<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 14. Configurable long-poll default and inbound max timeout

Date: 2026-05-14

## Status

Accepted

## Context

The per-stream `EventPollBuffer` long-poll behaviour had a hard-coded 30-second
fallback and **no upper bound** on a receiver-supplied `timeoutSecs`. A receiver
could request an arbitrarily long timeout and tie up a goroutine plus a buffer
notifier on every poll stream — an un-defended resource-exhaustion surface
(closes #49).

## Decision

Two environment variables govern the behaviour, read once at `NewRouter` startup
and plumbed positionally through
`buffer.CreateEventPollBuffer(jtis, defaultTimeoutSecs, maxTimeoutSecs)`:

- **`I2SIG_POLL_DEFAULT_TIMEOUT`** (default `30`) — the fallback applied when a
  receiver omits `timeoutSecs`.
- **`I2SIG_POLL_MAX_TIMEOUT`** (default `300`) — caps inbound `timeoutSecs`;
  larger values are **silently clamped**.

`0` is the documented escape hatch for each: `I2SIG_POLL_DEFAULT_TIMEOUT=0`
disables implicit long-polling; `I2SIG_POLL_MAX_TIMEOUT=0` disables the cap.
Negative/unparseable values WARN and fall back to the code default; a
`default > max` misconfiguration clamps the default down to max with a startup
WARN. The server starts in all cases.

The timeouts are **constructor parameters, not package globals or setters** — per-buffer
`int` fields set at construction. This keeps `event_buffer_test.go` free of
`os.Setenv` and the buffer package free of an env-reading dependency.

## Consequences

**Positive**

- Resource defence is now the default: shipping `I2SIG_POLL_MAX_TIMEOUT=300`
  closes the unbounded-goroutine gap for every operator who does not override it.
- The clamp is spec-compliant: RFC 8936 §2.4 makes `timeoutSecs` a SHOULD, so
  silently clamping (rather than rejecting) does not break conforming receivers.

**Negative**

- A disclosed behaviour change: receivers sending `timeoutSecs: 600` are clamped
  to `300s` (documented; `I2SIG_POLL_MAX_TIMEOUT=0` is the opt-out).
- Poll transmitters do not take cluster leases, so every node reads these vars at
  its own startup. Inconsistent settings across nodes produce per-node-divergent
  receiver-visible behaviour (no data loss/duplication); operators are instructed
  to set both vars uniformly. This is operator hygiene, not a correctness bug.

## Related

- `docs/configuration_properties.md`.
- ADR 0011 — the `I2SIG_POLL_*` area in the env-var taxonomy; legacy
  `POLL_DEFAULT_TIMEOUT` / `POLL_MAX_TIMEOUT` are read as deprecated fallbacks via
  `envcompat.Lookup`.
- PRD #61, Issue #62, closes #49.
