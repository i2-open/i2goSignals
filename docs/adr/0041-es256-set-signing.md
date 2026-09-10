<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 41. ES256 is a selectable per-stream SET signing algorithm

Date: 2026-09-09

## Status

Accepted (community #284, planning spec #102 — profiling-driven runtime
optimization).

Extends ADR 0034, which established the per-stream `signing_alg` seam and the
`JwkKeyRec.Alg` discriminator. ADR 0034 described that seam as carrying `""` /
`RS256` as the default and `ML-DSA-65` as the opt-in. This ADR adds a third
selectable value and widens the key store's encoding contract accordingly; ADR
0034 is extended rather than superseded, and its dual-key JWKS shape is
unchanged.

## Context

RSA-2048 signing was the largest single consumer of transmitter CPU on every
delivery leg. Profiling the dev cluster with `goSignalsBench` (5000 events, 16
concurrent clients, CPU profiles via `I2SIG_PPROF_ADDR`) put
`crypto/rsa.SignPKCS1v15`, reached through `goSet.(*SecurityEventToken).JWS`, at
**50.25%** of the push leg's cumulative CPU on a 14s window, with
`bigmod.(*Nat).Exp` at 44.42% underneath it.

It was also the dominant source of allocation pressure:
`crypto/internal/fips140/bigmod.NewNat` accounted for **78% of all bytes ever
allocated** by the process, which is what kept `runtime.gcBgMarkWorker` at
~13.41% of CPU. So the cost was being paid twice — once in the signature, once
in the garbage collection its garbage caused.

Measured per operation on the same host (Go 1.27, FIPS-140 bigmod path):

| Algorithm | Sign | Verify |
|---|---|---|
| RS256 (2048) | 0.822 ms | 0.025 ms |
| ES256 (P-256) | 0.019 ms | 0.043 ms |

Signing runs once per event per outbound stream, so the ~43x cheaper signature
scales directly with fan-out. Verification moves the other way, and by much
less: ES256 verify is roughly 1.7x RS256's, paid once per inbound SET.

The seam to carry this already existed. ADR 0034 put `signing_alg` on
`StreamConfiguration` and an `Alg` discriminator on the stored key record. What
blocked ES256 was only that `goSet.SigningMethodFor` accepted `""`, `RS256` and
`ML-DSA-65`, and `validateSigningAlg` rejected everything else at stream create
and update. `AllowedAlgs()` already included `ES256` on the *verify* side — ADR
0034 widened it so a node would verify a PQ or EC SET whether or not it signed
one — so this is the signing half of an algorithm the server could already
accept.

## Decision

**1. `ES256` becomes a third selectable value of `signing_alg`.** It is
accepted by `SigningMethodFor` and by `validateSigningAlg`, and it is opt-in per
stream. **`RS256` remains the default**: a stream that does not name an
algorithm signs exactly as it always did, and `signing_alg` stays `omitzero`, so
an existing stream is byte-identical on the wire.

**2. The curve is not a separate knob.** `ES256` names ECDSA on P-256 with
SHA-256, per RFC 7518. `EnsureSigningKeyForAlg` provisions
`ecdsa.GenerateKey(elliptic.P256(), ...)`; there is no configuration surface for
choosing a different curve, because a different curve would be a different JOSE
`alg` and would need its own selectable value.

**3. The key store's encoding contract widens to three shapes, discriminated by
`JwkKeyRec.Alg`.** RSA keys are stored PKCS#1 as before; an EC key is stored
**SEC 1** for the private half (`x509.MarshalECPrivateKey`) and **PKIX** for the
public half (`x509.MarshalPKIXPublicKey`); ML-DSA keys keep the ADR 0034 shape.
`storedAlgFor` maps a stream's configured `signing_alg` onto the stored
discriminator, so provisioning stays generic through `applySigningAlg` rather
than growing a per-algorithm branch at every call site. The empty discriminator
continues to mean RSA, so existing records need no migration.

**4. Decoding is pinned to the discriminated algorithm.** `ecdsaPublicKey`
parses the stored PKIX bytes and then **asserts the result is an
`*ecdsa.PublicKey`**, failing if it is not. This is deliberate and is the same
algorithm-confusion guard `givenKeyFor` applies at the JWKS boundary: a record
discriminated `ES256` must never hand an RSA key to a verification pinned to
ES256. Bytes that happen to parse as some other key type are an error, not a
fallback.

**5. The issuer publishes an ES256 key in its JWKS under its own `kid`.** This
is the ADR 0034 dual-key shape, unchanged, extended to a third key. Receivers
select the verification key by `kid`, so an ES256 stream needs no receiver-side
change provided the key is published — and a receiver that does not recognise a
key simply skips it and keeps verifying its own streams.

## Consequences

- **This is a throughput choice, not a security downgrade.** ES256 and RS256 at
  2048 bits are of comparable strength; the difference measured here is cost,
  not security margin. Neither is post-quantum — that is what ADR 0034's
  `ML-DSA-65` opt-in is for, and the two opt-ins are independent.
- **Verification gets slightly more expensive.** ES256 verify is ~1.7x RS256's
  (0.043 ms vs 0.025 ms). Signing happens per event per outbound stream and
  verification once per inbound SET, so the trade is strongly favourable for a
  transmitter and roughly neutral for a pure receiver. A deployment that is
  overwhelmingly receive-side gains nothing from opting in.
- **The default is unchanged, deliberately.** Before `ES256` could become a
  default, the enterprise and admin receivers would need auditing for algorithm
  assumptions. Keeping the opt-in per stream means that audit gates a future
  decision rather than this one.
- **`AllowedAlgs()` did not have to move.** It already listed `ES256`, so no
  node's accept posture changes with this ADR — only what a node can be
  configured to *emit*.
- **A third stored encoding is a third thing to get right.** The key store now
  persists RSA (PKCS#1), EC (SEC 1 / PKIX) and ML-DSA keys, and the error paths
  say so explicitly. `pkg/services/key_service_es256_test.go` and
  `pkg/services/es256_roundtrip_test.go` pin provisioning and a full push / poll
  / SSTP round trip respectively.
