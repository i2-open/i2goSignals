<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 42. Signing keys carry a validity period

Date: 2026-09-24

## Status

Accepted (community #318).

Supersedes in part ADR 0028: its statement that goSignals keys carry no expiry
and leave service only by suspend, revoke or replace. Suspend, revoke and the
derived-status model of ADR 0028 are unchanged; a validity period is one more
input to the derived status.

## Context

A signing key was active until an operator suspended, revoked or replaced it.
A key uploaded with its certificate ignored the certificate's dates, so a
transmitter kept signing SETs with a key whose certificate had expired, and a
generated key never aged out at all. The `application/x-pem-file` upload also
read only the first PEM block and only RSA, so a key could not be loaded
together with its certificate, and ES256 or ML-DSA-65 keys (ADRs 0034, 0041)
could not be uploaded.

## Decision

1. **The key record carries `NotBefore` / `NotAfter`.** A zero bound is open; a
   record with neither never expires, so every existing record keeps its
   behaviour and nothing is backfilled. `NotAfter` is exclusive, as in X.509.
2. **Where the period comes from.**
    - A private key uploaded with its certificate takes the certificate's
      dates. They win over any lifetime.
    - A generated key (create, rotate) and a cert-less private-key upload are
      valid from creation for a lifetime: the `lifetime` query parameter
      (`90d`, a Go duration, or `0`/`never`), else
      `I2SIG_ISSUER_KEY_LIFETIME` (default `180d`; `0`/`never` means no
      expiry). `NotBefore` is left open rather than stamped with the creation
      time, so a node whose clock runs slightly behind the minting node's never
      sees a brand-new key as not yet valid.
    - Verification-only keys (public keys, certificates without a private key,
      `jwks_uri` keys) have no enforced expiry.
    - The token issuer's key and the keys the server provisions itself at
      startup carry no lifetime: their expiry would lock out administration or
      strand streams with nobody having asked for it.
3. **Validity is derived on every read against a clock**, never stored as a
   status. The listing reports `expired` or `not-yet-valid` with
   `not_before` / `not_after`. Signing selects the newest key that is active
   and valid now, so a newer key pre-staged with a future `NotBefore` takes
   over at that instant.
4. **An expired key is key-unavailable.** Saving or enabling a signing stream
   with only an expired or not-yet-valid key is a 400 naming the issuer, the
   algorithm and the time. Under a running stream, expiry follows the #308 /
   #312 missing-key rule: a push stream pauses and is disabled at the retry
   limit; a poll transmitter or SSTP pair takes the stored pause, which the
   background key check re-evaluates. The router's key cache holds a key no
   later than the instant its selection changes, and a key store outage never
   extends a key past its `NotAfter`. The stranding guard (#311) counts an
   expired or not-yet-valid key as unavailable.
5. **Expiry is warned of in advance.** Inside `I2SIG_ISSUER_KEY_EXPIRY_WARNING`
   (default `30d`) the background key check WARNs once a day per key, naming
   the issuer, algorithm, kid, expiry and days remaining; a stream save inside
   the window succeeds and WARNs.
6. **The JWKS keeps expired public keys**, so SETs signed before the expiry
   still verify. Only revocation removes a key from the JWKS (ADR 0028).
7. **PEM uploads read every block.** A private key (PKCS#8, PKCS#1 or SEC 1)
   of RSA, ECDSA P-256 or ML-DSA-65, plus optionally its certificate, loads a
   signing key of RS256, ES256 or ML-DSA-65. A certificate for another key is a
   400; any other key type is a 400 naming the type.

## Consequences

- Operators must rotate generated keys at least every 180 days unless they set
  `I2SIG_ISSUER_KEY_LIFETIME=never`; the WARN gives 30 days' notice.
- An uploaded key whose certificate has already expired is stored and listed as
  `expired`; it never signs, and it does not count as a replacement for the
  stranding guard.
- Idle poll and SSTP streams are not paused at the moment of expiry; the pause
  is taken at the next signing attempt.
- Out of scope: expiry of verification-only keys, publishing `x5c` in the
  JWKS, and backfilling a validity period onto existing records.
