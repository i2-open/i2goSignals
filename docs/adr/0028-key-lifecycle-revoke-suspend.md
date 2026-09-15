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

## Update (2026-09-14): stranding guard, missing-key rule, cross-node expiry (GH #308, #311, #312, #313)

**A suspend that strands signing transmitters is refused, not warned.** The
Decision above lets a transition that leaves a keyName with zero active keys
succeed with a warning. Since #311, a suspend (`POST /key/{keyName}/status` with
`suspended`) or a replace (`force=replace`, on create or key load) that would
leave any signing transmitter with no active key for its `iss` and `signing_alg`
returns **409**, listing the affected streams; resending with `?confirm=true`
applies it. Revoke, reactivate and rotate are never blocked: an absolute revoke
of a leaked key must always go through. The 409 applies only when a transmitter
would be stranded; a keyName no stream signs with still takes the warning path.

**"Fails loudly on the next signing attempt" is now the missing-key rule.** A
signing transmitter with no active key never sends an unsigned or empty SET.
Push (#308), poll and SSTP (#312) transmitters pause with a reason naming the
issuer and algorithm, resume on their own when a key becomes active, and disable
at the retry limit. The loud ERROR is logged **once per key-unavailable pause**
(and again on disable), not on every key read: `KeyService`'s "all signing keys
are suspended or revoked" line is a WARN, because a paused transmitter re-reads
the key on every retry. Saving or re-enabling a signing transmitter with no
active key is refused up front.

**Every node follows a key change within a bound.** Each node's in-memory signing
key per issuer and algorithm expires after 2s (#313), so a suspend, revoke,
reactivate, rotate or replace made through one node reaches every node's
transmitters within that bound, not only the handling node's.

**"Latest active record" means newest by creation time** (amended 2026-09-15,
GH #316). Each key record carries a `CreatedAt`, which `KeyService` stamps when
it mints the record and no status transition changes. Issuance selection takes
the active record with the latest `CreatedAt`. Record id order decides only
between records whose creation times are equal to the millisecond (the precision
Mongo stores) and between records that have no `CreatedAt`, and a record that
has one is newer than any record that does not. One rule, `JwkKeyRec.NewerThan`,
decides every choice of a keyName's newest record: signing and issuance
selection, the stranding guard's active-key check, the `use` a rotation carries
over, which record wins a kid collision in the auth JWKS, and each community
`KeyDAO.FindLatestByKeyName` (Mongo sorts on `created_at` then `_id`, both
descending). Records minted by v0.11.0 through v0.12.0-alpha.19 carry random ids
and no `CreatedAt`. They keep their order among themselves, so an upgraded store
selects the key it selected before, and any key minted after the upgrade is
newer than all of them, so a rotation takes effect at once. The earlier
workaround, suspending the old key to complete a rotation, is retired. There is
no migration and no backfill. `ids.NewObjectID` still mints ids in the MongoDB
ObjectID layout (timestamp, per-process value, counter), which keeps the id
tie-break in mint order.
