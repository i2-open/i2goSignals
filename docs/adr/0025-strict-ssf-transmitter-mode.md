<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 25. Strict-spec SSF transmitter mode for `goSsfServer` (`I2SIG_STRICT_SSF`)

Date: 2026-06-22

## Status

Accepted (PRD #196 — Strict-mode SSF transmitter).
Builds on ADR 0023 (local-issuer addressing) and ADR 0024
(transmitter-assigned identity).

## Context

`cmd/goSsfServer` is the standalone SSF-server **simulator** — a minimal
transmitter we stand up to behave like a properly-administered, third-party
SSF transmitter (the way the OpenID conformance suite expects one). In that
deployment the issuer is **declared by an administrator**: a single value is
both the discovery issuer and the JWKS key name, and `jwks_uri` is derived
from it (ADR 0023). A receiver fetches
`/.well-known/ssf-configuration/<issuer>` (RFC 8615 path insertion), confirms
`iss` equals that issuer, and fetches `jwks_uri` to verify SETs.

For that to hold, the issuer's signing key must exist *before* the server
advertises discovery. `goSsfServer` previously relied on `InitializeTokenKey`
to seed the default-issuer key — but that seeding happens **only on first
init** (it short-circuits once the token key already exists), so an issuer
added to an established deployment, or a server whose issuer was never
explicitly declared, would advertise an issuer it cannot sign for and
`/.well-known/ssf-configuration/<issuer>` would `404`. In the conformance
runs this was papered over by setting `I2SIG_ISSUER_DEFAULT` to a path-bearing
issuer and letting first-init create the key — workable, but implicit and
fragile.

This ADR is deliberately **narrow**. It does **not** change the `/stream`
registration contract for any binary: stream creation stays ADR 0024
presence-based everywhere (a caller-asserted `iss`/`aud` is honored, an absent
one is minted), which goSignals cluster federation depends on. The only thing
strict mode does is make the `goSsfServer` simulator provision its declared
issuer deterministically.

## Decision

Introduce an opt-in posture switch **`I2SIG_STRICT_SSF`**
(`services.StrictSsfEnabled()`, truthy = `true`/`1`/`enabled`/`yes`), **scoped
to `cmd/goSsfServer`**. It is **off by default**. `cmd/goSignalsServer` (the
full cluster server) does not consult it; the stream-management API is
unchanged for both binaries.

When on, `cmd/goSsfServer` calls `SsfApplication.ProvisionStrictMode` at
startup, which:

1. **Requires an administrator-declared issuer (fail-fast).**
   `I2SIG_ISSUER_DEFAULT` must be set to an absolute `http(s)` issuer URL —
   the base-URL / `DEFAULT` fallback that the default mode accepts is
   **refused and the server exits**. In strict mode the operator declares the
   issuer explicitly, the way the conformance harness configures it.

2. **Idempotently provisions that issuer's SET-signing key** via the new
   `KeyService.EnsureSigningKey`, which (unlike `InitializeTokenKey`) re-checks
   on every call and is therefore restart-safe and late-add-safe. This binds
   `iss == discovery issuer == JWKS key name` (ADR 0023), so the
   issuer-specific discovery endpoint and `/jwks/<path>` resolve and emitted
   SETs sign under the declared issuer.

The returned error is fatal: the server must not begin advertising an issuer
it cannot sign for.

## Considered alternatives

- **Enforce SSF §8.1.1.1 on the server's `/stream` create path (reject a
  caller-asserted `iss`/`aud` with `400`).** Rejected — out of scope. That
  changes how stream creation works for both binaries and would break
  goSignals cluster federation, where sisters assert `iss`/`aud` on create by
  design (ADR 0024), and the conformance receiver's read-modify-write replace.
  Strict mode is a `goSsfServer` *provisioning* concern, not a registration
  contract change.
- **Apply `I2SIG_STRICT_SSF` to `cmd/goSignalsServer` as well.** Rejected —
  `goSignalsServer` is the full cluster server whose issuer handling is driven
  by its own configuration; the simulator-only flag would only add confusion.
- **Always provision the issuer key on every startup (no flag, fix
  `InitializeTokenKey`).** Deferred — that changes non-strict behavior, and the
  first-init seeding is adequate for the lenient default. Strict mode gets the
  deterministic, restart-safe `EnsureSigningKey` instead.
- **Keep relying on first-init seeding with the base-URL fallback.** Rejected
  for strict mode — implicit and fragile; an explicit, validated issuer
  declaration is the whole point of the posture.

## Consequences

**Positive**

- `cmd/goSsfServer` reproduces a properly-administered strict SSF transmitter
  from one declared issuer value: discovery, JWKS, and SET signing all line up
  — the behavior the conformance runs exercised, now explicit rather than
  implicit.
- Misconfiguration fails fast at startup instead of surfacing as a `404`
  discovery or a signature-mismatch at verify time.
- No change to the `/stream` API or to `cmd/goSignalsServer`: ADR 0024
  presence-based acceptance and cluster federation are untouched.

**Negative / accepted trade-offs**

- A new env switch to document and reason about (scoped to one binary).
- `EnsureSigningKey`'s existence check is best-effort against concurrent
  cluster nodes (a TOCTOU window); acceptable for single-binary strict-mode
  startup, and a duplicate `sig` record under the same issuer is harmless.

## Related

- PRD #196 — Strict-mode SSF transmitter.
- ADR 0023 — local-issuer addressing (`iss`/`jwks_uri` derivation, RFC 8615
  path insertion).
- ADR 0024 — transmitter-assigned identity (presence-based `iss`/`aud`),
  unchanged by this ADR.
- SSF §7.2.4 (issuer binding), §8.1.1 / §8.1.1.1 (Transmitter-Supplied
  `iss`/`aud`).
- `pkg/services/strict_ssf.go` — `StrictSsfEnabled`.
- `pkg/services/key_service.go` — `EnsureSigningKey`.
- `pkg/goSsfServer/ssf-application.go` — `ProvisionStrictMode`;
  `cmd/goSsfServer/main.go` — startup wiring.
