# Subject filtering applied at delivery time, not routing time

The SSF §8.1.3 subject filter is consulted when a stream's pending buffer is
drained — `runPushLoop` for PUSH streams, poll-response time for POLL streams —
not at event-routing time alongside `EventService.MatchesStream`. Routing-time
filtering was chosen first (to keep stream buffers bounded), then reversed:
routing runs on whichever node ingests an event, so routing-time filtering
would force *every* node to hold *every* stream's filter, with no existing
cluster channel to keep those copies consistent. Delivery-time filtering pins
the hot PUSH path to the single `push-transmitter:<sid>` lease owner — which the
existing wake-up scheme already targets point-to-point — so an Add/Remove
Subject arriving on any node simply notifies that owner to reload its filter
cache. The bounded-buffer concern that motivated routing-time filtering
dissolves: a filtered-out JTI is discarded (acked), not pushed, so the pending
list still drains and stays bounded.

## Considered options

- **Routing-time filtering, consulted alongside `MatchesStream`** — rejected:
  routing executes on an arbitrary ingest node, and there is no cluster
  mechanism to broadcast per-stream filter state to all ingest nodes. It would
  also turn `MatchesStream` from a pure DAO-free predicate into a DAO-touching
  one.

## Consequences

- Subject filtering lives in the delivery path, not the routing predicate. A
  future reader will find it in `runPushLoop` / the poll-response handler, not
  next to `MatchesStream` — this ADR is why.
- `MatchesStream` and `HandleEvent` are untouched; an event still enters every
  matching stream's pending buffer regardless of subject filtering.
- PUSH filter consistency rides the existing per-stream lease + wake-up
  machinery; POLL reads the filter from Mongo per poll request (polls are cold
  and batched, so no cache or cross-node notification is needed).
- Operational events (`Operational=true`) carry no Subject and always pass the
  filter, consistent with their existing bypass of `MatchesStream`.
