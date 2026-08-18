<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 31. SSTP inbound honours its direction's RouteMode

Date: 2026-08-18

## Status

Accepted (GH #261)

## Context

An SSTP pair carries a `mode` per direction. `SstpModeToRouteMode` maps the
inbound one onto `SstpInbound.RouteMode`, and `docs/SSTP.md` stated that "a pair
can FORWARD outbound while PUBLISH-ing inbound".

The router never read it. `HandleEvent` resolved an SSTP-ingested SET via
`GetStreamStateBySID`, flagged `sstpInbound = true`, and then returned
unconditionally:

```go
if sstpInbound {
    return nil
}
```

That guard sat *before* the `RouteModeImport` check and before the aud /
explicit-route fan-out, so every SET entering goSignals over SSTP was treated as
`IMPORT` regardless of the mode configured on the pair. Both ingest paths reach
it: the responder side (`runner_sstp_server.go`) and the initiator's
response-SET side (`sstp_outbound.go`).

The comment cited PRD #154 Q5.1 ("consumed locally … not fanned out"), which
predates per-direction `mode`. The visible cost is that a two-hop topology —
`A --sstp--> goSignals --sstp--> B`, aud-routed — silently drops hop 2. The
workaround was RFC 8935 push for the inbound leg, which forfeits SSTP's
single-request bidirectional exchange and multi-SET batching.

## Decision

**D1 — Inbound routing is governed by the inbound direction's `RouteMode`.**
The guard now consults it: `IMPORT` returns as before; `FORWARD` and `PUBLISH`
fall through to the same fan-out an RFC 8935 push receiver uses. `streamState`
at that point is the rx-side view built by `sstpInboundCounterRecord`, whose
`StreamConfiguration` *is* the pair's `SstpInbound`, so `GetRouteMode()` already
returns the inbound mode — no new lookup is needed.

**D2 — The forward-vs-re-sign choice is NOT made on the inbound path.** It is
made per outbound stream at delivery time, from that stream's own route mode,
which is how the push path already works. The inbound mode decides only
*whether* the SET is routed. This keeps one signing decision point rather than
two that could disagree.

**D3 — The check cannot reuse `IsReceiver()`.** That helper matches
`ReceivePush` / `ReceivePoll` only, and an SSTP inbound's delivery method is
`ReceiveSstp`, so the pre-existing `IsReceiver() && RouteModeImport` line does
not fire for SSTP. The SSTP branch is therefore explicit rather than folded into
that condition. Widening `IsReceiver()` was rejected: it is used elsewhere to
mean "RFC8935/8936 receive-side", and changing it would move behaviour outside
this issue.

**D4 — A blank inbound `RouteMode` is treated as `IMPORT`, not as
`SstpModeToRouteMode`'s `PUBLISH` default.** The bootstrap always stores an
explicit mode, so a blank value means a record written before the field existed.
Every such record behaved as import-only under the old guard, and honouring the
`PUBLISH` default would silently start fanning out their events on upgrade —
a data-flow change no operator asked for. New pairs are unaffected.

**D5 — A SET is never routed back out the pair it arrived on.**
`routeEventToSstpPairsLocked` takes an `excludePairId`. The originating pair's
outbound direction frequently matches the event on `aud`, so without this the
fan-out would return the SET to the peer that just sent it. Initiator pairs are
keyed by `PairId`; responder pairs are keyed by tx SID, so that loop compares
`pair.PairId` rather than its map key.

This is a *pair*-level exclusion, not a general loop suppressor. A longer cycle
across distinct pairs (A→B→A) is still possible and is out of scope here; SSTP
has no hop count or path record to detect it with.

## Consequences

### Positive

- Two-hop SSTP topologies work, so `independentid/i2gosignals-ai#2` no longer
  needs the RFC 8935 push workaround for its inbound leg.
- `docs/SSTP.md`'s per-direction claim becomes true rather than aspirational.
- Inbound SSTP and inbound push now behave the same way for the same mode,
  which is one rule to learn instead of two.

### Negative

- A pair whose inbound mode is `FORWARD`/`PUBLISH` starts routing events that
  were previously dropped. That is the fix, but for anyone who configured a
  non-`IMPORT` inbound mode and adapted to it not working, event volume on
  downstream streams changes at upgrade.
- The exclusion is one pair deep (D5), so a multi-pair routing cycle remains
  possible to configure. Detecting it needs loop-prevention state that does not
  exist yet.
- `HandleEvent` now carries a second piece of SSTP-specific branching. The
  routing decision and the echo exclusion are separated by the whole fan-out
  block, coupled through the `sstpInboundRouted` local.

## Related

- [0030](0030-wire-shaped-set-bson-persistence.md) — the other GH-issue fix in
  this release line; unrelated mechanism.
- `docs/SSTP.md` — pair model, bootstrap, per-direction mode semantics.
