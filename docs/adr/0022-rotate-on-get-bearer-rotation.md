<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 22. Rotate-on-GET bearer rotation: possession-proof trigger, deferred revocation, unconditional masking

Date: 2026-06-12

## Status

Accepted (design settled in GH #152 triage; implementation tracked there)

## Context

The SSF spec expects a GET of a stream's configuration to return a
freshly-minted delivery bearer (rotate-on-GET). goSignals had never
implemented it, and a naive implementation has two traps:

1. **Rotating on every GET breaks administration.** Admin reads of
   stream config would invalidate the live credential each time, and
   admins would see (and could leak) live secrets they never need.
2. **Revoking the old bearer instantly bricks unlucky clients.** A
   request racing the rotation gets a spurious 401, and a client whose
   rotation response is lost on the wire is left holding only a dead
   credential, with no self-service recovery.

Three callers can reach the config read surface: the credential holder
(receiver/peer presenting the stream's delivery bearer), management
sessions, and admin tokens. Only the holder should be able to rotate;
nobody else should see the live value.

## Decision

**Trigger — proof of possession.** Rotation fires only when the GET is
authenticated by the stream's *current server-issued bearer*: after
normal JWT validation, the presented `Authorization` value is
constant-time-compared to the credential stored on the stream record
(`PollTransmitMethod` / `PushReceiveMethod` / SSTP responder
`SstpMethod`). Exact match → mint replacement, persist, return live
value, schedule old for revocation. Anything else that is authorized to
read → masked value, no rotation. Two explicit guards ride on top of
the string match:

- **Issuer role** — rotation applies only where this server minted the
  credential. A peer-supplied outbound credential (e.g. the bearer an
  SSTP initiator stores) never rotates on a local GET, even if an
  admin presents a string-matching value.
- **Stream binding** — a presented EAT asserting `StreamIds` must
  contain the stream being read, and the replacement EAT is always
  minted bound to the current stream id(s) (`[sid]`, or
  `[txSid, rxSid]` for SSTP pairs) via the same issuing function the
  create path used, with the old JTI as lineage parent (ADR 0007).
  Rotation preserves scopes/project and can only tighten, never widen,
  the stream binding.

**Revocation — deferred, with idempotent re-read.** At rotation the old
bearer's token record gets `revoked_at = now + grace`
(`I2SIG_BEARER_ROTATE_GRACE`, default `1h`, `0` = immediate).
`IsRevoked` changes from "revoked_at is set" to "revoked_at is set and
in the past" — admin revocation (`revoked_at = now`) behaves exactly as
before. During the window the old bearer still validates, and a GET
presenting it returns the *same* current bearer again without minting a
third credential — this is the self-service recovery path for a lost
rotation response. No cluster cache is involved: every node already
checks revocation against Mongo per validation, so deferral is pure
policy, not cache coherence.

**Masking — unconditional, sentinel `***`.** Every credential field
(`authorization_header` in all delivery methods, `SstpMethod`'s bearer,
`tx_token`) reads as the literal `***` on every read surface (config
GET, state listings). No env var disables masking. The live value
appears exactly twice in a credential's life: the create response and
the rotation response. The update path treats an incoming `***` as
"leave unchanged" so read-edit-write round-trips cannot clobber live
credentials. Masking is applied to a deep copy, never the stored
record.

**Gating.** Rotation itself is gated by `I2SIG_BEARER_ROTATE_ON_GET`,
default `false` for the first release (existing receivers that re-read
config without persisting the response would otherwise be revoked out
from under themselves). Masking is not gated.

## Considered alternatives

- **Separate rotation endpoint** (keep GET purely management-plane) —
  rejected: fights the SSF spec shape, and the plane-boundary concern
  is answered by the narrow carve-out (a delivery token may read only
  its own stream's config).
- **Redemption-confirmed revocation** (old bearer dies when the new one
  is first used, per ADR 0007 machinery) — rejected: adds a state
  machine the fixed window already covers, and a client that rotates
  then goes quiet would keep the old credential alive indefinitely.
- **Omit masked fields (± a `masked: true` flag)** — rejected: plain
  omission is ambiguous with "no bearer configured" (a real state), and
  a flag grows the SSF wire schema for a redaction concern.

## Consequences

**Positive**

- Only the credential holder can rotate, and only by proving possession
  — self-verifying, and immune to misfiring on OAuth-realm tokens
  (which never string-match a stored internal bearer).
- Lost-response recovery is self-service within the grace window.
- Admin reads can no longer leak or invalidate live credentials.
- Rotation lineage is auditable through parent JTIs.

**Negative / accepted trade-offs**

- During the grace window a stolen *old* bearer can re-read the live
  new one. Inherent to possession-proves-rotation; bounded by the
  window, and `I2SIG_BEARER_ROTATE_GRACE=0` closes it entirely.
- An operator who loses a credential can never read it back — recovery
  is rotate or patch a replacement. Deliberate (shown-once model).
- SSTP initiator-side automation (proactively GETting the peer to
  self-rotate) is not built; the responder side is uniform and the
  contract is "the caller persists". Tracked as follow-up to GH #152.
- The management-token empty-`StreamIds` wildcard is deliberately left
  untouched; binding management tokens to specific SIDs would be a
  separate, breaking auth-model change.

## Related

- `CONTEXT.md` — "Rotate-on-GET", "Masked credential", "Rotation
  grace", and the amended management/data-plane carve-out.
- ADR 0007 — token lineage / redemption tracking (parent-JTI chain).
- ADR 0008 — revocation endpoints (`revoked_at` semantics extended to
  allow future-dating).
- ADR 0012 — scope checks via `HasScope`, never bare `Eat`.
- SSTP design Q38/Q42 (PRD #154) — pair-bearer shape; future
  bearer-type enforcement policy (OAuth-supersedes-static) remains a
  backlog ADR candidate.
- GH #152 — implementation tracking.
