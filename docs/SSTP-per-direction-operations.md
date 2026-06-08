<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# SSTP per-direction status & verify (operator runbook)

> Scope: how to observe and verify each direction of an SSTP pair from a single
> node. This is the per-direction observability surface (PRD #154 Q40/Q41). The
> full SSTP pair model, bootstrap, and lifecycle live in the SSTP design doc; this
> page is the focused operator runbook for status/verify.

An SSTP pair is a single bidirectional object with **two stream identifiers** on
each node:

- **txSid** — the transmit (outbound) side. On the record this is the primary
  `StreamConfiguration.Id`, which equals the pair's `PairId` (the on-wire SSF
  `stream_id`).
- **rxSid** — the receive (inbound) side. On the record this is
  `SstpInbound.Id`.

Per-direction operations route via the `stream_id` parameter (query for `GET`,
body for `POST`). There is no separate endpoint per direction — the SID you name
selects the direction.

## GET /status — per direction

`GET /status?stream_id=<sid>` reports the status of exactly the direction named:

- `stream_id=<txSid>` → returns `Status` + `ErrorMsg` (the outbound direction).
- `stream_id=<rxSid>` → returns `InboundStatus` + `InboundErrorMsg` (the inbound
  direction).

The two directions report independently: pausing the tx side leaves the rx side
`enabled`, and vice versa. (`disabled` is a pair-level lifecycle state and couples
both directions — see the pair lifecycle doc.)

## POST /verify — per direction

`POST /verify` with `{"stream_id": "<sid>"}` targets the **outbound side of the
direction the SID names**, emitting an SSF verification SET scoped to that
direction's `iss`/`aud`:

- `stream_id=<txSid>` → verifies the transmit direction from this node.
- `stream_id=<rxSid>` → verifies the inbound direction's outbound leg from this
  node's perspective.

This keeps `/verify` per-SSF-spec — no new endpoint shape.

### Reverse-direction verification (verify the side the *peer* transmits)

To verify the leg that the **peer** transmits to you (i.e. confirm the peer can
deliver into your inbound side), you do **not** call a special local endpoint.
Per the SSF spec, verification is initiated by the transmitter, so you call the
**peer's** `/verify` against the **peer's `txSid`** — which is your rxSid's
upstream. Concretely, from your side:

1. Resolve the peer's SSF transmitter configuration (its `verification_endpoint`).
2. `POST <peer>/verify` with `{"stream_id": "<peer's txSid>"}`, authenticated
   with the pair bearer the peer accepts.

The peer then emits the verify SET, which arrives on your rxSid — confirming the
inbound path end-to-end. No new local route is needed for this; it is ordinary
SSF transmitter-initiated verification pointed at the peer.

## Listing pairs

SSTP pairs appear in the existing flat `GET /states` listing — there is no
`/pairs` endpoint. Each pair record carries `PairId`, the outbound
`StreamConfiguration`, and the inbound `SstpInbound`. Tools (goSignalsAdmin,
`cmd/goSignals`) expand a pair record into two rows (txSid + rxSid) and group them
client-side by `PairId`.
