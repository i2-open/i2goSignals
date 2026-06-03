<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 15. Stream `remote_address` tracking

Date: 2026-05-06

## Status

Accepted

## Context

Operators and the management plane need to know *where a stream is actually
connecting from* — for de-provisioning, incident response, and the
token-redemption view (ADR 0007), which joins a stream's last-seen IP onto
stream-typed tokens. The data plane already had the peer address at hand on every
connection; it was simply not captured.

## Decision

`StreamStateRecord` carries a `*RemoteIP` (`pkg/ssfModels`) populated for all
four delivery modes:

- **Inbound** — `ReceivePush` and `DeliveryPoll`, from `r.RemoteAddr` plus
  `X-Forwarded-For` / `X-Real-IP`.
- **Outbound** — `DeliveryPush` and `ReceivePoll`, captured via
  `httptrace.WithClientTrace` on the resolved TCP peer.

It surfaces in stream-state JSON as `remote_address` with `protocol`, `ip`, and
`forwarded` sub-fields, omitted on streams that have never had a successful
connection.

Invariants:

- **Capture only after authorization succeeds** — unauthenticated probes never
  pollute the field.
- **`X-Forwarded-For` / `X-Real-IP` are informational metadata only** — no auth
  or trust path consumes them.
- Mongo persistence uses a `$set` scoped to `remote_address`, so it does not race
  with concurrent `UpdateStreamStatus` writes on the same document.
- `pushEvent` and `runPollLoop` mirror the persisted value back into their local
  stream pointer after a successful update, so the only-when-changed guard
  short-circuits redundant DB writes on the next iteration (regression #27).

## Consequences

**Positive**

- The management plane and the token-redemption view answer "where is this stream
  connecting from" with no extra writes on the hot path — the address is captured
  at connection time at no added cost.

**Negative**

- The forwarded headers are stored verbatim and are spoofable; the invariant that
  nothing trusts them must be preserved by any future consumer.

## Related

- ADR 0007 — track token redemption, not issuance (consumes the stream's
  last-seen `RemoteIP`).
- `pkg/ssfModels` — `StreamStateRecord`, `RemoteIP`.
