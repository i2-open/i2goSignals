<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 23. Local-issuer addressing for SSF discovery (issuers rooted at the server base URL)

Date: 2026-06-17

## Status

Accepted (design settled in GH #188 grilling; implementation tracked there).
Server-side companion to #187 (the receiver/CLI path-insertion fix).

## Context

SSF §7.2.4 binds three values together: the `issuer` returned in the
Transmitter Configuration MUST be byte-identical to (1) the Issuer URL the
receiver used to *fetch* the configuration (built by RFC 8615 path
**insertion** per §7.2 — `/.well-known/ssf-configuration` inserted between
host and path), and (2) the `iss` claim in the SETs that transmitter signs.
`jwks_uri` is otherwise free-form: any HTTPS URL that actually serves that
issuer's keys.

goSignals stores every issuer (signing key) under an opaque `keyName`
string captured as a single URL-encoded path segment. When that string is
itself a URL (`https://host/issuer1`), the legacy behavior URL-encodes it
and advertises `jwks_uri = https://host/jwks/https%3A%2F%2Fhost%2Fissuer1`.
That neither matches the insert-style fetch URL nor reads as a clean key
location — a §7.2.4 violation the moment an issuer carries a path. The
default host-only deployment never hit this because insertion of a
path-less issuer yields the plain `/.well-known/ssf-configuration`.

A naive fix — "always advertise our own `/jwks/<issuer>`" uniformly — is
wrong, and the reason is goSignals' router role. goSignals is not only a
publisher; it **relays**. In forward mode a relayed SET keeps the
**original publishing entity's `iss`**, and the downstream receiver
verifying it must fetch *that* entity's keys. If discovery/relay rewrote
every issuer under a goSignals-hosted path, goSignals would be claiming
itself as the key source for SETs it did not publish — breaking the
§7.2.4 issuer/`iss`/`jwks_uri` binding for the next hop.

## Decision

Split issuers into two classes by whether their root
(`scheme://host[:port]`) equals the server's configured base URL, and
address them differently.

- **Local issuer** (root == base URL) — goSignals *is* the publisher.
  Address it by its **path component**:
  - discovery served at the §7.2 insert path
    `/.well-known/ssf-configuration/<path>` (multi-segment: the route
    captures `{issuer:.+}`);
  - `issuer` echoed as the reconstructed full URL `baseURL + /<path>`
    (satisfies §7.2.4), not the bare captured segment;
  - `jwks_uri = baseURL + /jwks/<path>` — a clean path component, never a
    URL-encoded full string;
  - key lookup reconstructs `baseURL + /<path>` to find the stored key
    (the same `keyName`-is-issuer contract; the path is just the local
    handle). `/jwks/{keyName:.+}` reconstructs local issuers first, then
    falls back to the captured value as-is.
  - An unknown reconstructed issuer returns **404** (closes the prior
    `TODO`), rather than synthesizing metadata for an arbitrary string.

- **Foreign issuer** (root != base URL) — goSignals *relays* something
  published elsewhere. Its identity and keys reference the **original
  publishing entity** verbatim and are left in the legacy opaque form.
  goSignals never serves *transmitter discovery* for a foreign issuer (it
  is not that issuer's transmitter); the keys exist only to verify /
  forward relayed SETs on the next hop.

Endpoints other than discovery/JWKS stay root-level (`/stream`,
`/status`, `/verify`, `/register`); stream identity remains carried in the
token, not the URL path. Per-issuer endpoint namespacing (full
multi-tenant routing) is explicitly out of scope.

## Considered alternatives

- **Uniform encoding for all issuers** (`/jwks/<urlencoded-full-url>`
  everywhere) — rejected. Simplest code, but it is exactly the §7.2.4
  violation, and applied to relayed foreign issuers it would falsely
  claim goSignals as the key source for SETs it did not publish.
- **Per-issuer endpoint mounting** (`/<issuer>/stream`, `/<issuer>/jwks`,
  …) — rejected here. Full multi-tenancy; an enterprise/tenancy concern,
  and unnecessary while the data plane carries identity in the token.

## Consequences

**Positive**

- A path-bearing local issuer's discovery doc satisfies §7.2.4: the
  `issuer` field equals the insert-style fetch URL and the `iss` of the
  signed SETs (which already defaults to the stream's issuer == default
  issuer, signed by the key stored under that name — no signing-side
  change needed).
- The relay/next-hop chain stays correct: foreign issuers keep pointing
  at the original publishing entity's keys.
- Host-only deployments are unaffected — a path-less issuer inserts to
  `/.well-known/ssf-configuration` and hits the existing handler.

**Negative / accepted trade-offs**

- Two issuers stored the same way (both URL strings) are addressed by
  *different* schemes depending on a runtime comparison against the base
  URL. A future contributor "simplifying" this to one uniform scheme
  would silently reintroduce the §7.2.4 bug — this ADR is the guardrail
  against that, and the reconstruction site carries a pointer comment.
- `BaseUrl` becomes load-bearing for issuer *identity*, not just routing.
- `jwks_uri` is a published contract receivers cache; changing the
  addressing scheme later forces re-discovery.

## Related

- `CONTEXT.md` — "Local issuer" / "Foreign issuer".
- GH #188 — server-side multi-issuer discovery (this decision).
- GH #187 — receiver/CLI RFC 8615 path-insertion discovery URL.
- SSF §7.2 / §7.2.4 — path insertion; issuer/`iss`/`jwks_uri` binding.
- ADR 0004 — event-source type (relay direction model).
