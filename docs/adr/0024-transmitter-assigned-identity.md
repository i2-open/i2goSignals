<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 24. Transmitter-assigned identity on `/stream` create (presence-based `iss`/`aud`)

Date: 2026-06-20

## Status

Accepted (PRD #196 — Strict-mode SSF transmitter; first slice, GH #198).
Builds on ADR 0023 (local-issuer addressing).

## Context

A strict SSF receiver — the OpenID conformance suite is the canonical
example — registers a stream against a transmitter and then validates the
returned Stream Configuration against the transmitter's discovered
metadata. Per SSF §8.1.1.1 the receiver does **not** supply `iss` or `aud`
on create; those are *Transmitter-Supplied*. Post-registration the
receiver MUST confirm that the configuration's `iss` equals the `issuer`
it discovered in the transmitter's `.well-known` metadata (§8.1.1), and it
relies on `jwks_uri` being consistent with that `iss` to fetch the keys
that verify delivered SETs.

goSignals previously populated a transmitter stream's `aud`, when the
caller asserted none, by echoing the most specific *caller* identity
available — the registered `client_id` of the locally issued token,
falling back to the `project_id`. That made `aud` carry an internal,
caller-side handle rather than a transmitter-assigned audience. It is also
not what §8.1.1.1 means by "Transmitter-Supplied": the value should be the
transmitter's own opaque designation of the receiver stream, stable for
its lifetime, not a reflection of who happened to call create.

Separately, a non-strict / agnostic peer *may* assert `iss`/`aud` on
create (goSignals does this for its own cluster sisters so operator-set
values land). Acceptance must therefore distinguish "the caller asserted a
value" from "the caller left it for the transmitter to assign".

## Decision

Acceptance on the transmitter-side `/stream` create path is
**presence-based**: a caller-asserted `iss` or `aud` is honored verbatim;
an absent one is **minted** by the transmitter. Presence does not get
overridden by minting, and minting does not happen when the caller
asserted intent.

When goSignals is the SSF transmitter (delivery `urn:ietf:rfc:8935` /
`urn:ietf:rfc:8936`, and the bare/poll `DEFAULT` create) and the value is
absent:

- **`iss` = the server's advertised issuer** (`GetDefIssuer()`) — the same
  `issuer` returned in the `.well-known` Transmitter Configuration. This
  makes the strict receiver's "`iss` == discovered issuer" check pass with
  no special case. A **per-stream `iss` is explicitly ruled out by SSF
  §8.1.1.1** and is *not* introduced: every transmitter stream signs under
  the one advertised issuer.

- **`jwks_uri` derives from that issuer** — `baseURL + /jwks.json`, the
  same JWKS the `.well-known` metadata advertises (ADR 0023
  local-issuer addressing). Derivation is gated on the minted-issuer case
  (`config.Iss == defaultIssuer`); a caller-asserted *foreign* `iss` is
  left untouched, since goSignals is not that issuer's key source.

- **`aud` = a transmitter-assigned, fixed, immutable, opaque, URI-shaped
  identifier**, generated once at stream creation (JTI-like: a ksuid under
  the `urn:i2-open:ssf:aud:` URN prefix), persisted on the stream record,
  and stable for the stream's lifetime. It is deliberately **opaque** — it
  does **not** leak the caller's `client_id` or `project_id`. This minted
  `aud` doubles as the AUDIENCE routing handle that a later PRD #196 slice
  consumes; this slice only mints and persists it and does not change
  routing.

Receiver streams (`...:receive`) are unaffected: they connect to a foreign
transmitter, so the prior `client_id` → `project_id` default for an absent
`aud` remains the most specific stable local identity for them.

## Considered alternatives

- **Keep echoing `client_id` / `project_id` as the default `aud`** —
  rejected. It puts a caller-side handle in a transmitter-supplied field,
  is not opaque, and ties the audience claim on every delivered SET to who
  registered the stream rather than to the stream itself.
- **Per-stream `iss`** (mint a distinct issuer per stream) — rejected,
  ruled out by SSF §8.1.1.1: the receiver confirms `iss` against the *one*
  discovered transmitter issuer, so a per-stream `iss` would fail the
  strict check. All transmitter streams share the advertised issuer.
- **Mint `aud` as a URL under the server base** — rejected for this slice.
  A bare opaque URN is sufficient as an audience designator and as a
  routing handle, and avoids implying a dereferenceable endpoint.

## Consequences

**Positive**

- A strict SSF receiver can register without asserting `iss`/`aud` and its
  post-registration `iss`-equals-discovered-issuer check passes; `jwks_uri`
  is consistent with that `iss` so it can fetch keys and verify SETs.
- The audience claim on delivered SETs is a stable, transmitter-owned
  identifier for the life of the stream.
- Flexible peers that assert `iss`/`aud` keep their explicit values
  (presence-based; no override).

**Negative / accepted trade-offs**

- The default `aud` for a transmitter stream changes shape (opaque URN
  instead of `client_id`/`project_id`); any consumer that read the old
  echoed value as a caller handle must not rely on it.
- The minted `aud` is a published value the receiver may cache; it is
  immutable by design, so it cannot be re-minted on an existing stream.

## Related

- PRD #196 — Strict-mode SSF transmitter; GH #198 (this slice).
- ADR 0023 — local-issuer addressing (`iss`/`jwks_uri` derivation).
- SSF §7.1 (transmitter metadata), §7.2.4 (issuer binding),
  §8.1.1 / §8.1.1.1 (Transmitter-Supplied `iss`/`aud`; receiver MUST
  confirm `iss`).
- `pkg/services/stream_service.go` — `CreateStream`, `mintStreamAud`,
  `isTransmitterMethod`.
