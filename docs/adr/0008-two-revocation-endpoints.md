<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 8. Two revocation endpoints: RFC 7009 `/revoke` and `DELETE /token/{jti}`

Date: 2026-05-31

## Status

Accepted

## Context

Token revocation has two genuinely different callers, and they hold different
things:

1. **A token holder** — a transmitter, receiver, or tool that possesses the
   token string and wants to kill it. This is the RFC 7009 model: present the
   token in a form body and the server revokes it.
2. **An administrator working from a list** — an operator looking at the
   management-plane token table (or its GoSignalsAdmin console equivalent). By
   design `TokenRecord` *does not store the token string* — only the JTI and
   metadata. The admin has a JTI to act on, never the token itself.

RFC 7009 cannot serve caller 2: the admin has no token string to present. And
the pre-existing `DELETE /token/{jti}` is not RFC 7009 — it is a
revoke-by-identifier operation. Collapsing to a single endpoint would force one
caller into an unnatural shape (either admins reconstruct tokens they don't
have, or holders look up a JTI they may not know).

## Decision

We keep **both** endpoints, each serving its natural caller.

- **`POST /revoke` (RFC 7009)** — for holders. Accepts a `token` form field
  (and an accepted-but-ignored `token_type_hint`); parses the JWT to extract
  the JTI; revokes by JTI. Per RFC 7009 §2.2 it **always returns HTTP 200**,
  even for an unknown, already-revoked, or expired token — never leaking
  existence.
- **`DELETE /token/{jti}`** — for admins acting from a table row, revoking by
  identifier.

Both share one authorization rule: a non-admin caller may revoke only tokens
within their **own project** (`AuthContext.ProjectId` must match the target's
project); `admin`/`root` may revoke anything. This blocks a low-scope
delivery-token holder in one project from revoking another project's tokens.

Revocation sets `revoked_at`; the record is retained (introspection still
reports `active:false`, and lineage survives) until the Mongo TTL reaps it
after `I2SIG_TOKEN_RETENTION`.

## Consequences

**Positive**

- Each caller uses the shape that fits what it holds: a token string, or a JTI.
- RFC 7009 conformance for holders (always-200, `token_type_hint` tolerated)
  without distorting the admin path.
- One consistent project-scoping rule across both endpoints and `/introspect`.

**Negative**

- Two endpoints and one more thing to keep aligned (both must apply the same
  project guard and write the same `revoked_at`).
- "Two ways to revoke" is surprising at first read; this ADR is the answer to
  "why not just one?"

## Related

- `CONTEXT.md` — "Token administration vocabulary".
- RFC 7009 (Token Revocation), RFC 7662 (Token Introspection).
- ADR 0007 — track redemption, not issuance (same management-plane work).
