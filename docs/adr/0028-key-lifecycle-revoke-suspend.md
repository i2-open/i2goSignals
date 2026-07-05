<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 28. Key lifecycle: revoke/suspend as a retained-but-unusable primitive

Date: 2026-07-04

## Status

Accepted (GH #223)

## Context

A signing keypair had exactly one retirement primitive: hard delete
(`DELETE /key/{keyName}`, handler `DeleteJwksIssuerKeyHandler`, re-exported by
`pkg/goSsfServer`). Hard-deleting a signing key strands relying parties still
holding tokens signed under that key and destroys the audit continuity the key
axis exists to preserve. The admin control plane settled the family policy —
**no hard keypair deletion; revoke/suspend instead** (admin ADR 0013, admin
#265 / PR #281) — and removed its hard-delete affordance, but the community key
model had no primitive to implement revoke/suspend against:

- no lifecycle state on a keypair, and
- no operation to set that state.

Rotation (`KeyService.RotateKey`) is additive — old kids are retained and stay
published — but there was no "mark this key unusable yet keep it for audit"
operation. This is the key-axis analog of what streams (`stream/revoke`) and
tokens (`revoked_at`, ADR 0022) already do.

## Decision

**Status is derived from timestamps, never stored.** Each key record
(`JwkKeyRec`, Mongo `keyDoc`, memory record) gains two nullable timestamps:
`SuspendedAt` (reversible, clearable) and `RevokedAt` (terminal — once set,
never cleared or re-stamped; wins over suspension). Status derives as
`revoked` if `RevokedAt` is set, else `suspended` if `SuspendedAt` is set, else
`active`. This mirrors the `TokenRecord` timestamp pattern (ADR 0022) and leaves
room for future-dated or windowed policy without a schema change. The derived
status and the timestamps ride on `KeySummary` per kid, so `GET /keys` shows
lifecycle state without a second call.

**JWKS / issuance policy splits by status:**

| Status | Signing/issuance candidate | Published in JWKS (public AND auth) |
|---|---|---|
| active | yes | yes |
| suspended | no | yes |
| revoked | no | no — excluded immediately |

Issuance selection becomes "latest **active** record for the keyName"
(`KeyService.GetPrivateKeyWithKeyname`, used by the event router and token
signing). Both JWKS builders (`GetPublicJWKS` and the internal auth-JWKS
builder) skip revoked records but keep suspended ones so already-issued tokens
still verify. If a transition leaves a keyName with **zero active keys** the
operation still succeeds but the response carries a warning; the next signing
attempt fails loudly with a clear ERROR log naming the issuer and the remedy
(rotate or reactivate). There is no auto-rotation and no fallback to an older
inactive kid.

**Set operation.** `POST /key/{keyName}/status` with body
`{ "status": "active" | "suspended" | "revoked", "kid": "<optional>" }`.
Omitting `kid` applies to all records under the keyName; a supplied `kid` must
belong to that keyName (else 404). `active` clears `SuspendedAt` (reactivation);
any transition away from `revoked` is refused (400, terminal); re-asserting the
current status is idempotent (200). Authorization is `stream_admin` or `root`
only — the bare `key` scope is denied, because status mutation is takeover-class
under ADR 0006's create-allowed / takeover-denied line. The response is the
updated per-kid summary plus the no-active-key warning when applicable. The
transition rules (fat service) live in `KeyService.SetKeyStatus`; the DAO's
`SetKeyStatus` only writes timestamps (thin DAO, no status-query filtering) and
enforces one integrity invariant — `RevokedAt` is write-once.

**Hard-delete HTTP surface removed.** The `DELETE /key/{keyName}` (and the
legacy `DELETE /jwks/{keyName}`) routes, the `DeleteJwksIssuerKeyHandler`, and
the `pkg/goSsfServer` re-export are gone. The **Go** delete APIs
(`KeyService.DeleteKeysByName`, `DeleteKey`, and the `KeyDAO` delete methods)
**stay**: the enterprise repo imports them (its replace flow and `key/delete`
command) and the community `force=replace` path uses them. Only the HTTP surface
is retired.

**Deliberate asymmetry with admin ADR 0013.** The enterprise SSTP `key/delete`
control-stream verb remains live pending
independentid/i2gosignals-enterprise#107 (the companion issue that adds the
control-stream set-status command and the enterprise key model). This community
change ships the timestamp model, the REST set-status operation, the
JWKS/issuance filtering, and the HTTP-delete removal; the enterprise transport
half is out of scope here.

## Consequences

**Positive**

- Retiring a key no longer strands relying parties or breaks audit continuity:
  the material and timestamps are retained.
- Suspension is reversible; revocation is terminal and enforced at both the
  service (transition guard) and DAO (write-once `RevokedAt`) layers.
- Lifecycle state is visible on `GET /keys` with no extra round trip.
- The timestamp representation admits future retention windows / future-dated
  revocation without a schema change.

**Negative**

- A revoke/suspend that empties a keyName of active keys is allowed and only
  warns; the operator must rotate or reactivate before signing resumes for that
  issuer. This is intentional (no auto-rotation, no silent fallback) and is
  surfaced by a loud ERROR on the next signing attempt.
- The family is briefly asymmetric: admin has removed hard delete while the
  enterprise `key/delete` control-stream verb is still live until #107.

## Related

- Community: GH #223 (this change); ADR 0006 (the `key` scope / takeover line),
  ADR 0022 (timestamp-derived deferred revocation on tokens), ADR 0008
  (admin-by-id vs holder-by-token revocation), ADR 0023 (local issuer
  addressing / percent-encoded keyName), ADR 0027 (pkg admin route surface).
- Admin: ADR 0013 (revoke/suspend, not hard delete), admin #265 / PR #281.
- Enterprise: independentid/i2gosignals-enterprise#107 (control-stream
  set-status command + enterprise key model; fate of `key/delete`).
