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
   behaviour and nothing is backfilled. Both bounds are inclusive, as in
   RFC 5280: a key is valid at `now` when `!now.Before(NotBefore) &&
   !now.After(NotAfter)`, so it still signs at exactly its `NotAfter`.
2. **Where the period comes from.**
    - A private key uploaded with its certificate takes the certificate's
      dates. They win over any lifetime, for the token issuer too (below).
    - A key the server generates — create, rotate, and the keys provisioned
      at startup (`CreateKeyPair`, `EnsureSigningKeyForAlg`) — and a cert-less
      private-key upload are valid from creation for a lifetime: `NotBefore`
      is the creation time and `NotAfter` the creation time plus the
      `lifetime` query parameter (`90d`, a Go duration, or `0`/`never`), else
      `I2SIG_ISSUER_KEY_LIFETIME` (default `180d`). A zero lifetime
      (`0`/`never`) leaves `NotAfter` empty: no expiry.
    - Verification-only keys (public keys, certificates without a private key,
      `jwks_uri` keys) have no enforced expiry.
    - The token issuer's key is exempt from the configured lifetime only: a
      generated or cert-less token-issuer key has no `NotAfter`, since a
      lifetime nobody asked for would lock out administration. Uploaded with
      a certificate, the certificate wins: the key takes the certificate's
      `NotBefore` / `NotAfter` and stops signing outside them.
3. **Validity is derived on every read against a clock**, never stored as a
   status. The listing reports `expired` or `not-yet-valid` with
   `notBefore` / `notAfter`. Signing selects the newest key that is active
   and valid now, so a newer key pre-staged with a future `NotBefore` takes
   over at that instant.
4. **An expired key is key-unavailable.** Saving or enabling a signing stream
   with only an expired or not-yet-valid key is a 400 naming the issuer, the
   algorithm and the time. Under a running stream, expiry follows the #308 /
   #312 missing-key rule: a push stream pauses and is disabled at the retry
   limit; a poll transmitter or SSTP pair takes the stored pause, which the
   background key check re-evaluates. The pause is taken at expiry, not at the
   next signing attempt: each pass of the background key check re-evaluates
   validity against the key service clock, pauses an enabled poll transmitter
   or SSTP pair whose only key is expired or not yet valid, even with nothing
   pending, and nudges each push runner to check its own key. A key that is
   simply missing (as in the brief gap of a replace) still pauses at the next
   signing attempt. The reason names the expired key and
   its `NotAfter` (or the future key and its `NotBefore`). Rotating in a valid
   key resumes the stream as before. The router's key cache holds a key no
   later than the instant its selection changes, and a key store outage never
   extends a key past its `NotAfter`. The stranding guard (#311) counts an
   expired or not-yet-valid key as unavailable.
5. **Expiry is warned of in advance.** Inside `I2SIG_ISSUER_KEY_EXPIRY_WARNING`
   (default `30d`) the background key check WARNs once a day per key (keyed
   on issuer and kid), naming
   the issuer, algorithm, kid, expiry and days remaining. It warns only of the
   key signing selects for each issuer and algorithm, not of an older key a
   newer one has replaced; a stream save inside
   the window succeeds and WARNs. The once-a-day limit is held in memory on
   each node, so in a cluster every node running the key check WARNs once a
   day.
6. **The JWKS keeps expired public keys**, so SETs signed before the expiry
   still verify. Only revocation removes a key from the JWKS (ADR 0028).
7. **PEM uploads read every block.** A private key (PKCS#8, PKCS#1 or SEC 1)
   of RSA, ECDSA P-256 or ML-DSA-65, plus optionally its certificate, loads a
   signing key of RS256, ES256 or ML-DSA-65. The key's certificate is the one
   whose public key matches the private key's, in whatever order the chain was
   concatenated; with no such certificate the upload is a
   400; any other key type is a 400 naming the type. A public key or
   certificate alone, as PEM or as `application/pkix-cert` DER, loads a
   verification-only key of the same three types; any other type is a 400
   naming it.

## Consequences

- Operators must rotate generated keys, including the ones provisioned at
  startup, at least every 180 days unless they set
  `I2SIG_ISSUER_KEY_LIFETIME=never`; the WARN gives 30 days' notice.
- An uploaded key whose certificate has already expired is stored and listed as
  `expired`; it never signs, and it does not count as a replacement for the
  stranding guard.
- An idle stream is paused within one background key check interval of its
  key's expiry, so its status tells a receiver why nothing is being sent.
- Out of scope: expiry of verification-only keys, publishing `x5c` in the
  JWKS, and backfilling a validity period onto existing records.
