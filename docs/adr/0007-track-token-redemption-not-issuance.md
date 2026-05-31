<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 7. Track token redemption, not issuance

Date: 2026-05-31

## Status

Accepted

## Context

We are adding a management-plane view of issued tokens (IATs and stream
tokens) so an administrator can list, introspect, and revoke them. The
original request asked to show "the IP address each token was issued to."

Taken literally, that means recording the remote address of the request that
*minted* the token — the caller of `GET /iat`, or whoever registered a stream
client. On reflection that signal is near-worthless:

- An issued token is a **bearer credential**. The overwhelmingly common
  workflow is that an administrator mints a token and then **copies and pastes
  it** into some other system — a CI pipeline, a partner's configuration, a
  receiver running elsewhere. The address the token was minted from is almost
  always an admin's laptop or a CLI host, not where the token actually lives.
- The audit question an operator actually asks during de-provisioning or
  incident response is "**where is this token being used?**" — not "where was
  it typed?"

The codebase already has the right raw material for the "where is it used"
question on the stream side: a stream's `RemoteIP` (`StreamStateRecord`) is
refreshed every time the peer connects, and it is captured on the data plane
at no extra cost. The gap was only on the IAT side, where "use" means a
`/register` call — a **cold path**, cheap to instrument.

## Decision

We track **redemption**, not issuance.

- **No issuance IP.** We do not record the address a token was minted from.
- **IAT redemption** is captured at `/register`: `last_redemption_ip`,
  `last_redemption_at`, and a `redemption_count` on the IAT's `TokenRecord`.
  Last-only — not a full per-redemption trail (deep forensics live in the SET
  event journal). The write is **best-effort** (logged at `WARN` on failure,
  never blocking registration), matching the existing `TrackToken` posture.
- **Stream-token "redemption"** is the ongoing push/poll connection. The
  management view *joins* the stream's existing `RemoteIP` (last-seen IP) onto
  stream-typed tokens rather than storing a second copy.
- **Lineage** is recorded as `Parent` = the immediate parent JTI at each mint
  site (IAT → stream-client token → delivery token), for trace/audit display.

`redemption_count` is deliberately positioned as the data primitive a future
**max-uses / redeem-once** policy would consume, and the redemption IP as the
input a future **IAT-to-IP-mask restriction** would check. Neither policy is
built today.

## Consequences

**Positive**

- The IP shown to an operator answers the question they actually have ("where
  is this used") instead of a misleading one ("where was it minted").
- No new writes on the hot event-delivery path: stream last-seen IP reuses
  existing capture; IAT redemption is on the cold `/register` path.
- The data model seeds future use-count and IP-restriction policies without
  committing to them now.

**Negative**

- A token minted but never redeemed shows no usage IP at all. That is correct
  (it has not been used) but may surprise an operator expecting *some* address.
- `redemption_count` may under-report if a best-effort write is lost. Acceptable
  for an audit aid; a future max-uses policy that needs a reliable count would
  have to revisit the best-effort posture.

## Related

- `CONTEXT.md` — "Token administration vocabulary": Redemption, Last-redemption
  IP, Last-seen IP.
- ADR 0006 — `key` scope and closing the anonymous IAT endpoint (the IAT
  lifecycle this view administers).
- `pkg/ssfModels/model_token.go` — `TokenRecord`.
