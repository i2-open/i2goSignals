<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 34. ML-DSA-65 SET signing is a per-stream opt-in over a dual-key JWKS

Date: 2026-08-27

## Status

Accepted (GH #278, planning spec #101 — Go 1.27 adoption).

## Context

Go 1.27 ships `crypto/mldsa`, an implementation of ML-DSA (FIPS 204) — the
NIST-standardised lattice signature scheme — and teaches `crypto/x509` and
`crypto/tls` to issue and negotiate ML-DSA certificates. RFC 9964 defines how an
ML-DSA key and signature are carried in JOSE: a JWS `alg` of `ML-DSA-44` /
`ML-DSA-65` / `ML-DSA-87`, and a new JWK key type `AKP` ("Algorithm Key Pair")
whose only key members are `pub` and `priv`.

A SET is a JWS. Nothing about RFC 8417 constrains the signature algorithm, so
signing SETs with ML-DSA is a matter of plumbing rather than protocol change.
The reason to do it now is that signatures are the part of this system with a
*retroactive* exposure: a SET archived today and verified — or forged against —
years from now is protected by whatever algorithm signed it at the time. That is
the "harvest now, forge later" shape, and it is why signature agility is worth
having in place before it is urgent rather than after.

Three facts constrain how it lands.

**The libraries are not ready.** `golang-jwt/jwt/v5` (v5.3.1) has no ML-DSA
signing method; the upstream work is open (golang-jwt#508, #519).
`MicahParks/keyfunc/v2` parses a JWK Set by switching on `kty` and *silently
skips* types it does not know, so an AKP key in a JWKS today is simply absent
from the parsed set. `MicahParks/jwkset` cannot render one. All three are
extension points away from working, but none of them works out of the box.

**The signature is large.** ML-DSA-65 signatures are 3309 bytes against
RSA-2048's 256 — about 3.3 KB of additional base64 on *every* SET. For a push
receiver taking one event at a time that is a bigger relative jump than it
sounds: the SET payloads this project emits are commonly under 1 KB, so the
token roughly quadruples. Public keys grow too (1952 bytes vs. 256), which the
JWKS pays once.

**Receivers are other people's software.** A transmitter that switched to
ML-DSA unilaterally would break every receiver that cannot verify it, with no
recourse short of reconfiguration on the far side.

## Decision

**1. ML-DSA-65 is the parameter set.** ML-DSA-44 (NIST Category 2) is the
FIPS 204 default and the smaller signature; ML-DSA-87 (Category 5) is the
largest. ML-DSA-65 (Category 3, roughly AES-192-equivalent) is chosen for
margin: a SET's signature is checked long after it was produced, and the
2420-vs-3309-byte saving from Category 2 does not buy enough to justify sitting
at the floor for a value with that lifetime. Category 5's 4627 bytes buys
correspondingly little. One parameter set is supported, not three — the
parameter set is part of the algorithm's identity, and a verifier that accepts
"whatever AKP key the JWKS holds" has widened its own trust decision.

**2. Signing is a per-stream opt-in, not a server posture.**
`StreamConfiguration.signing_alg` (`""` / `RS256` / `ML-DSA-65`) selects the
algorithm for one stream. `""` and `RS256` are the same thing, and `""` is the
zero value, so a stream configured before this field existed is byte-identical
on the wire to one configured after (the field is `omitzero`). The 3.3 KB is
paid by the receiver, so the receiver's own stream is where the choice belongs:
a PQ-ready peer opts in while a constrained one does not, on the same issuer.

**3. The issuer publishes both keys side by side.** An issuer with any
ML-DSA stream holds two signing key pairs, under distinct `kid`s, both published
in its JWKS: the RSA key exactly as before, and an `AKP` key next to it. This is
what makes (2) possible at all — a receiver that has never heard of AKP loads
the set, skips the key it does not understand, and keeps verifying its RS256
stream with no change whatsoever. The key store's records gained an `Alg`
discriminator whose empty value means RSA, so existing rows decode unchanged.

**4. The community-local code is shaped to be deleted.**
`pkg/goSet/mldsa` implements exactly two things — a `jwt.SigningMethod`
registered through `jwt.RegisterSigningMethod`, and the RFC 9964 AKP JWK codec —
and plugs into the extension points the libraries already publish
(`keyfunc.NewGivenCustom` for the key, `jwt.RegisterSigningMethod` for the
algorithm). When golang-jwt#519 ships, the swap is an import change at that
package, not a rewrite of the signing or verification paths. On the JWKS read
side, `goSet.NewJwksWithAKP` and `goSet.GetJwks` extract AKP entries and hand
them to keyfunc as *given keys*, which keyfunc merges back in on every
background refresh; nothing forks the library. On the write side the AKP JWKs
are spliced into the document jwkset produced, so no existing key's bytes move.

**5. The verifier allow-list is widened unconditionally.**
`goSet.AllowedAlgs()` returns `{RS256, ES256, ML-DSA-65}` on every node, whether
or not that node transmits ML-DSA. The allow-list gates the token *header*
before key lookup (the algorithm-confusion guard from ADR-0066 §D3 / #271), and
a receiver must be able to verify a PQ-signed SET from a peer regardless of what
it signs itself. The same pinning is applied a second time at the key: the AKP
given key declares `Algorithm: ML-DSA-65`, so keyfunc refuses to hand it to a
token claiming anything else.

**6. Internal mTLS gets an independent, off-by-default option.**
`cmd/genTlsKeys` accepts `CERT_KEY_ALG=ML-DSA-65` and then issues an ML-DSA leaf
from an ML-DSA CA (RSA-4096 remains the default). It is a separate switch from
`signing_alg` because the two protect different things with different blast
radii: the cluster CA is trusted by every node, so flipping its default would
invalidate every existing deployment's certificates on upgrade.

## Consequences

- **Wire growth is real and must be planned for.** Measured on the benchmark
  set's representative SCIM SET, the wire token grows from **1,113 bytes to
  5,188** — 4.7× — when a stream moves from RS256 to ML-DSA-65. Push receivers
  with request-size limits, poll responses batching many SETs, and SSTP frames
  all feel it. This is the single reason the opt-in is per-stream; an operator
  turning it on should expect the poll `maxEvents` that was comfortable before
  to move considerably more bytes.
- **The CPU picture is mixed, and the receiver pays.** Measured on the
  benchmark set (`docs/perf/go127-baseline.md`, #278's row): signing a SET is
  **2.3× faster** with ML-DSA-65 than with RSA-2048 (827 µs → 352 µs), because
  an RSA private-key operation is expensive and a lattice signature is not.
  Verification goes the other way — a verified `goSet.Parse` is **3.2× slower**
  (31.1 µs → 99.3 µs) — because RSA verification with `e=65537` is close to
  free by construction. So the transmitter gets cheaper and the receiver gets
  dearer, on top of paying the bytes. Both figures are small against a network
  hop; neither is small enough to ignore at fan-out.
- **Two keys per issuer to operate.** Rotation, suspension and revocation
  (ADR 0028) act per `kid`, so an issuer's RSA and ML-DSA keys rotate
  independently. `GetSigner(ctx, issuer, alg)` selects by algorithm rather than
  by recency, which is load-bearing: the ML-DSA record is the *newer* one, and
  selecting by recency would hand an RS256 stream a key RS256 cannot use.
- **The router caches per (issuer, algorithm).** One issuer signing two streams
  with two algorithms holds two live keys; a cache keyed on issuer alone would
  let whichever stream loaded first pin the wrong key for the other.
  Invalidation stays issuer-level and evicts both.
- **FIPS 140-3 mode v1.0.0 cannot do ML-DSA.** `crypto/mldsa` returns an error
  under the v1.0.0 module (v1.26.0+ is fine). A deployment pinned to the older
  module cannot opt a stream in; it fails at key generation, loudly, at stream
  configuration time.
- **The AKP JWK codec is ours to keep correct.** Until upstream ships, this
  project owns an RFC 9964 wire format that other implementations will read.
  Its tests assert the JSON members literally rather than only round-tripping,
  because a symmetric bug in the reader and the writer would survive a
  round-trip test.
