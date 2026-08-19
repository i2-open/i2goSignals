<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 33. Expected verification material is discriminated by issuer-JWKS-URL presence

Date: 2026-08-19

## Status

Accepted (GH #264) — recorded ahead of the fix, as a constraint on it.

## Context

`StreamService` keeps `receiverStreams`, a per-process map from receive SID to
the stream record, with the resolved `*keyfunc.JWKS` hung off it as
`ValidateJwks`. `GetIssuerJwksForReceiver` treats **entry presence** as a cache
hit and returns `ValidateJwks` verbatim — including when it is nil. Four call
sites populate the map (the startup preload in `LoadReceiverStreams`,
`CreateStream`, and both miss paths in `GetIssuerJwksForReceiver` — pair-by-
inbound-SID and plain receiver); exactly one evicts from it (`DeleteStream`).

`fetchReceiverJwks` collapses three unrelated outcomes into that same nil:

- a URL is configured and the fetch failed transiently;
- no URL is configured and no internally-registered key was found;
- the inbound direction of an SSTP pair is not enabled.

On the first of those it logs `"Temporary error loading JWKS, will retry"`, and
the function's own doc comment says transient errors are "left for retry". There
is nothing to retry from. The nil is cached under the SID and every later lookup
is a hit, for the life of the process.

The two error classes are asymmetric in a way that hides the live one. A
*permanent* error (`isPermanentJwksError`: 4xx other than 429, unusable URL,
undecodable body) disables the record and persists `Status` + `ErrorMsg`, so an
operator can see it. A *transient* error (connection refused, timeout, 5xx) —
the class that is actually expected to recover — leaves the stream `enabled`
with an empty reason while it verifies nothing. Nothing an operator can query
distinguishes it from a healthy stream. Verification is fail-closed at every
consumer (`goSetSstp`, `goSetPush`, `goSetPoll`), so inbound SETs are rejected
rather than admitted unverified: this is an availability defect, not a
verification bypass.

A second silent failure sits behind the same nil. `keyService.GetPublicJWKS`
swallows every per-key error with `continue` and returns whatever accumulated,
so a total failure yields `{"keys":[]}` — which `keyfunc.NewJSON` parses into a
**non-nil, zero-key** JWKS with a nil error. A presence check on the pointer
cannot tell "resolved" from "resolved to nothing".

Fixing the caching therefore requires a distinction the codebase does not
currently have: *verification material is expected here and I do not have it*
versus *nothing is expected here*. Only the first may retry, and the predicate
that separates them is the whole decision. Too permissive and every
bearer-authenticated stream enters a permanent retry loop against an endpoint it
was never given; too strict and the original bug reopens on the branch that was
supposed to recover. The pull toward the permissive reading is strong, because
from inside the verification path "no keys" reads as a fault — which is why the
rule is recorded here rather than left implicit in the retry code.

## Decision

- **Issuer-JWKS-URL presence is the discriminator, and nothing else is.** A
  receive direction expects verification material if and only if it has an
  issuer JWKS URL configured. Not `SigningOnly` — `StreamConfiguration` already
  states it MUST NOT be inferred from "an issuer is configured", and the
  inference does not hold in the other direction either. Not "a key was found",
  which is the outcome being classified and cannot also be the classifier.
- **`"NONE"` is absence, not a URL.** `normalizeStreamTrustFields` maps
  `IssuerJWKSUrl == "NONE"` (any case) to the empty string precisely because
  SCIM peers write it to mean *the key is internal to this server* — the
  no-URL branch by intent. The predicate must be evaluated against the
  normalised value, or normalise before evaluating; a record persisted before
  that normalisation existed can still carry the literal, and reading it as a
  URL would send the resolver to fetch `https://…/NONE` forever.
- **URL configured: absence of a usable JWKS is a retryable fault.** The
  direction is recorded *unresolved* rather than caching a resolved-nil. A
  lookup past the backoff deadline re-attempts and, on success, caches the real
  JWKS and clears the marker. A JWKS that parses but carries **zero keys** is
  unresolved, not resolved — non-nil is not the test, and `GetPublicJWKS` above
  is the proof that a zero-key body is reachable in practice.
- **Permanent-error handling is unchanged.** `isPermanentJwksError` still
  disables the record and persists the reason. That path is already visible to
  operators and is not a retry candidate.
- **No URL configured: a valid resting state, never unresolved, never
  retried.** The internal key lookup is authoritative and its result — including
  "no key at all" — is legitimate. This rests entirely on the ADR-0066 §D2
  invariant enforced by `validateBusinessStreamSecurity`: `SigningOnly` (L2 =
  None) requires **both** `Iss` and `IssuerJWKSUrl`, so a URL-less direction is
  bearer-gated by construction and has no verification material to be missing.
  **That dependency is load-bearing**: if the create-time invariant is ever
  relaxed to permit a signing stream without a JWKS URL, this branch silently
  misclassifies it as not-configured and it will never retry. Relaxing 0066 §D2
  requires revisiting this ADR.
- **Retry is lazy and per-entry.** Attempted on lookup once the deadline has
  passed; never from a background sweep. `StreamService` has no goroutine,
  ticker, or shutdown hook today, and this decision declines to give it one for
  a condition that only matters when someone is asking. Backoff is exponential
  from ~10s, doubling, capped at 5 minutes — the cap chosen to match
  `RefreshRateLimit` in `pkg/goSet`'s JWKS loader so the server has a single
  story about how often it re-hits a JWKS endpoint. Bookkeeping is per cache
  entry, not global.
- **Readiness is node-local, derived, and never persisted.** Three values —
  `ready` (resolved and non-empty), `unresolved` (URL configured, resolution
  failing; carries last error and next-retry time), `not-configured` (no URL,
  nothing expected). It describes *this node's* current reachability of a remote
  endpoint, not a property of the stream, so two cluster members may legitimately
  disagree and neither is stale. Excluded from BSON; does not survive a restart.
  It is per-direction, with an inbound twin mirroring the existing
  `InboundStatus`/`InboundErrorMsg` convention, because the cache is keyed by the
  inbound SID for a pair (ADR 0018).
- **Stream `Status` is not the carrier.** An unresolvable stream keeps reporting
  `enabled`, and the SSF-defined stream status response body gains nothing.
  Readiness surfaces on the admin stream-state routes (ADR 0027) and as a
  per-stream Prometheus gauge beside the existing error gauge. Those admin
  routes source records from the DAO and never consult the receiver cache, so
  they must overlay readiness before serializing — the least obvious part of the
  change.
- **The `GetPublicJWKS` empty-set swallow is left in place, deliberately.** It
  is a real silent failure, but it lands on the no-URL branch, which by design
  does not retry; the zero-key predicate above already covers the URL branch
  where it would matter. Making the internal key lookup report failure instead
  of returning an empty set is a separate decision, not a gap in this one.

## Consequences

**Positive**

- A receiver whose issuer JWKS endpoint is down at startup — or at
  `CreateStream`, which poisons the entry at birth and is the case the original
  report did not cover — recovers without a restart.
- The three meanings previously folded into one nil become distinguishable, so
  a caller can tell "expected but unavailable" from "nothing expected" instead
  of inferring it from surrounding state.
- The transient branch gains the operator visibility the permanent branch
  already had, closing the asymmetry that made the live failure the invisible
  one.
- Zero-key JWKS bodies stop counting as successful resolution, which also covers
  a healthy endpoint that has published no keys yet.

**Negative**

- Correctness now depends on a create-time invariant recorded in a *different
  repository's* ADR, with nothing in this repo's retry path referencing it. The
  coupling is stated here and nowhere the compiler can see it.
- Readiness is observable per node and will differ across a cluster during a
  partial outage. An operator reading one node's admin route learns about that
  node only; alerting on it needs to account for that.
- Backoff means recovery is not immediate — a stream can stay unresolved for up
  to the 5-minute cap after its endpoint returns. Bounding outbound fetches was
  preferred over minimising that window.
- A direction that legitimately has no keys and no URL is indistinguishable from
  one that is misconfigured to omit a URL it should have had. That is the price
  of taking URL presence as the discriminator, and ADR-0066 §D2 is what makes it
  acceptable.
- The retry attempt must not hold the cache lock across the network call, so the
  resolver acquires the lock twice around an unlocked fetch and must tolerate a
  concurrent writer having resolved the same entry in between.

## Related

- planning ADR 0066 §D2 — the `SigningOnly` trust-root invariant this ADR's
  no-URL branch depends on; `validateBusinessStreamSecurity` is its enforcement
  point.
- ADR 0018 — bidirectional pair record; why receiver cache entries are keyed by
  inbound SID and why readiness needs an inbound twin.
- ADR 0023 — local-issuer addressing. Its relay caution governs the
  **advertising** direction (which `jwks_uri` goSignals publishes) and does not
  bear on the **verification** direction (how goSignals resolves a key for an
  inbound SET). Resolving locally-hosted issuers through the internal key store
  to skip the HTTP hop is explicitly out of scope for #264.
- ADR 0027 — `pkg` admin route surface; where readiness is reported.
- ADR 0028 — key lifecycle; a revoked or suspended key legitimately leaves a
  JWKS, which the zero-key predicate must not mistake for an outage on a
  direction that has no URL.
- ADR 0029 — event-validation modes; the other per-receiver-stream posture that
  is derived rather than persisted.
- GH #264 — the defect, its reproduction, and the agent brief.
- `docs/security_model.md` — operator-facing auth and verification model.
