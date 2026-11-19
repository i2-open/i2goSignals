<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 49. The verification key set is a family-owned `goSet.JWKS` over keyfunc v3

Date: 2026-11-19

## Status

Accepted (issue #399, release train 0.12.0). Amends ADR 0034 §4 and §5.

## Context

The 0.12.0 dependency refresh brings every module to latest stable,
majors included (planning ADR 0079). `MicahParks/keyfunc` moved from v2 to
v3, and v3 is a rewrite:

- The given-key API (`NewGiven`, `NewGivenRSA`, `NewGivenCustom`,
  `GivenKeyOptions`) is gone. ADR 0034 §4 used it to merge RFC 9964 AKP
  (ML-DSA) keys into a JWKS. jwkset, which v3 parses with, cannot read AKP
  keys.
- The background refresh moved into a `jwkset` HTTP client. That client
  re-reads only the JWK Set it parses, so an AKP key captured at the first
  load would never be refreshed. A rotated ML-DSA key would stay frozen
  until restart.
- `*keyfunc.JWKS` was part of this module's exported API, in
  `goSetSstp.VerifyConfig.JWKS`, `goSet.Parse` and the services layer.
  Sister repos compile against it, so any keyfunc major is a cross-repo
  break.

## Decision

**1. The exported type is family-owned.** `pkg/goSet` exports `JWKS`,
`VerificationKey{Key, Alg}`, `NewJwksFromKeys`, `NewJwksWithAKP`, `AKPKeys`,
`FetchJwks` with `JwksOptions`, and `ErrKIDNotFound`. No keyfunc or jwkset
type appears in the exported API, so a later keyfunc major is a change inside
`pkg/goSet` only. `Close` replaces `EndBackground`; it is nil-safe,
idempotent, and does nothing on a static set.

**2. A JWKS has two parts, built together from the same bytes.**
- **Pinned:** a kid → `VerificationKey` map. It holds the AKP keys, parsed
  by `pkg/goSet/mldsa`, and every key built in memory.
- **Classic:** the RSA and EC keys, held in a jwkset `MemoryStorage` behind a
  keyfunc v3 `Keyfunc`.

A refresh builds both parts from one fetched document and swaps them under
one lock, so an AKP key rotates exactly like an RSA key. This replaces ADR 0034
§4's "given keys merged back in on every refresh".

**3. goSet owns the fetch loop, not jwkset.** `FetchJwks` requires a
successful first fetch, then runs a ticker at `RefreshInterval` (default 1h).
It also refreshes when a token names a kid the set does not hold, at most
once per `RefreshRateLimit` (default 5m; `authSupport` uses 1s for issue
#115). The rules:
- Only an unknown-kid refresh starts the rate-limit window. As under v2, the
  first unknown kid after the initial load is fetched at once.
- A token with no `kid` never triggers a refresh.
- A kid that misses inside the window is not queued, unlike v2's deferred
  refresh. The background tick, or the first miss after the window, picks
  it up.
- The body is capped at 1 MiB.
- A response other than 200 is an error.
- A failed refresh keeps the previous keys and reports through
  `OnRefreshError` (by default a WARN log).

Owning the loop is what lets decision 2 hold. It also gives the refresher a
stable stack frame, `goSet.(*jwksRemote).loop`, which the GH #290 leak tests
count.

**4. Alg pinning at the key is kept (ADR 0034 §5).**
- A pinned key whose `Alg` differs from the token's `alg` header is refused.
- A classic key is checked by keyfunc v3 when its JWK carries `alg`.
- An in-memory key with an empty `Alg` is not pinned. Only test fixtures
  build one.

**5. One bad JWK is skipped, not fatal.** Each non-AKP key is parsed
separately and an unusable one is logged and skipped. jwkset's whole-set
parse would cost a receiver every key because of one bad entry.

**6. The not-found error keeps the v2 phrase.** `ErrKIDNotFound` reads
"goSet: the given key ID was not found in the JWKS", and a lookup wraps it
with the kid (`: "rsa-2"`). The text is not byte-identical to v2's, so match
with `errors.Is`. The classifiers that match the substring "key ID" still
work.

## Consequences

### Positive
- A rotated ML-DSA key is picked up on the next refresh. Under keyfunc v3's
  own refresher it would have stayed frozen, and under v2 it depended on the
  given-key merge.
- Later keyfunc and jwkset majors no longer break sister repos.
- The refresher is one goroutine with a cancel-and-wait `Close`, which makes
  the GH #290 leak accounting exact.

### Negative
- The fetch and refresh loop keyfunc used to provide now lives in
  `pkg/goSet/jwks_loader.go` (about 200 lines), and this project maintains it.
- Breaking change for the sister repos (0.12.0 train):
  - `*keyfunc.JWKS` becomes `*goSet.JWKS`;
  - `keyfunc.NewGiven*` becomes `goSet.NewJwksFromKeys` with
    `goSet.VerificationKey`;
  - `keyfunc.Get` becomes `goSet.FetchJwks`;
  - `AKPGivenKeys` becomes `AKPKeys`;
  - `EndBackground` becomes `Close`.
- An unknown-kid refresh runs on the caller's goroutine and is bounded by
  `RefreshTimeout` (default 60s). Fetches are serialized, so other
  unknown-kid lookups on the same set wait for an in-flight fetch.
  Known-kid lookups never wait. Under v2 the refresh was queued to the
  background loop. The rate limit keeps a burst of unknown kids to one
  fetch.

## Related

- [ADR 0034](0034-ml-dsa-set-signing.md): ML-DSA SET signing. §4 and §5 are
  amended here.
- Planning ADR 0079: toolchain bump brings dependencies to latest stable.
- Issues #399 (this migration), #290 (refresher leak), #115 (cold-cache
  OAuth grace).
