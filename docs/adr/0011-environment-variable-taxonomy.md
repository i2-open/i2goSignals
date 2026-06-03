<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 11. Environment-variable taxonomy (`I2SIG_<AREA>_*`)

Date: 2026-05-14

## Status

Accepted

## Context

goSignals is configured entirely by environment variables (no config file). By
v0.10 the names had grown organically — `POLL_SRV_BEHAVIOR`,
`TRANSMITTER_BACKFILL_INTERVAL`, `MONGO_*`, and so on — with no common prefix,
no 1:1 mapping to documentation sections, and no way to grep "every server-side
knob." PRD #64 rationalised the whole surface.

## Decision

Every server-side environment variable is renamed under an `I2SIG_<AREA>_*`
prefix taxonomy, with the area name mapping 1:1 to a section of
`docs/configuration_properties.md`:

- `I2SIG_STREAM_*`, `I2SIG_ISSUER_*`, `I2SIG_AUTH_*`, `I2SIG_CLUSTER_*`,
  `I2SIG_STORE_MONGO_*`, `I2SIG_STORE_MEM_*`, `I2SIG_PUSH_*`, `I2SIG_POLL_*`,
  `I2SIG_TLS_*`, `I2SIG_SPIFFE_*`.

Every old name continues to be read through the `internal/envcompat` shim, which
prefers the new name, falls back to the old, and emits **one WARN per process**
when an operator is still relying on a deprecated name.

**Industry-standard exemptions.** Seven variables keep their bare names because
external tooling and conventions expect them, and they will not be renamed:
`PORT`, `BASE_URL`, `LOG_LEVEL`, `LOG_FORMAT`, `POD_NAME` (Kubernetes Downward
API), `MONGO_URL` (Mongo driver convention), and `SPIFFE_ENDPOINT_SOCKET`
(SPIFFE Workload API spec, consumed by `go-spiffe`).

**Value translation.** One rename also changes the value vocabulary:
`POLL_SRV_BEHAVIOR` → `I2SIG_POLL_RESPECT_STATUS`, where the old `MODE` maps to
`true` and `ALWAYSON` to `false`, inside `envcompat.LookupWithTranslate`, so an
operator with the old name set keeps the same runtime behaviour.

**Deprecation timeline.** In v0.11.0 both old and new names are accepted (each
old name WARNs once per process). In v0.12.0+ the deprecated names are removed;
`envcompat.Lookup` survives as the read seam but its old-name argument goes empty
for every renamed knob.

## Consequences

**Positive**

- Every server-side knob is greppable under one prefix and the area maps 1:1 to
  its doc section.
- No silent regressions for operators upgrading — the shim honours existing
  config and logs a loud WARN per deprecated name; there is no quiet failure
  mode.
- Verifiable on boot: `internal/server/test/env_old_names_e2e_test.go` boots the
  full server with **only** pre-v0.11.0 names set and asserts both that boot
  succeeds and that a deprecation WARN is emitted, catching any future call site
  that drops the old-name fallback.

**Negative**

- A transition window where two names mean the same thing, and a v0.12.0 cleanup
  that must remember to retire the WARN path.

## Related

- `docs/configuration_properties.md` — the source of truth, including the
  old→new mapping under "Migrating from pre-v0.11.0 names."
- `internal/envcompat/envcompat.go` — the shim (`Lookup`,
  `LookupWithTranslate`).
- PRD #64.
