<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 20. Pair delete: local proceeds, cascade_peer opt-in, 207 partial

Date: 2026-06-07

## Status

Accepted

## Context

ADR 0018 settled the SSTP pair as one bidirectional `StreamStateRecord` per node;
ADR 0019 settled how that record is created and how a single command can
provision both nodes of a pair via the peer cascade. This ADR settles the other
end of the lifecycle: how a pair is **deleted**, and what happens to the *other*
node when one side is torn down.

An SSTP pair spans two independently-operated nodes. The peer may be a different
deployment, in a different domain, run by a different team. At delete time the
peer can be: reachable and cooperative, reachable but rejecting (revoked
credential, already deleted), or simply down. A naive "strict cascade" — delete
the peer first, then delete locally, fail the whole operation if the peer call
fails — couples local cleanup to peer reachability. That is exactly backwards for
an operator: the most common reason to delete a pair is that the peer is *already*
gone or misbehaving, and a dead peer must never be able to pin a stale local row
in place. Equally, always firing a peer call is surprising — an operator
decommissioning their own node should not silently reach across to mutate a
peer they may no longer own.

The same tension governs UPDATE (this slice, #162): the patchable-fields
whitelist deliberately keeps `Role`, an already-set `EndpointUrl`/`PeerPairId`,
and all IDs immutable so a live pair can never be accidentally repointed at a
different peer. Delete is the only sanctioned way to break a pair's peer binding,
which is why the delete contract has to be unambiguous.

## Decision

**Local cleanup always proceeds and never blocks on peer reachability.** Peer
cleanup is a **courtesy** action, **opt-in** via a new `?cascade_peer=true` query
parameter, and its failure is reported but never fails the local delete.

`StreamService.DeleteSstpPair(ctx, sid, cascadePeer, peerServer)` returns an
`SstpDeleteOutcome` carrying per-side results:

- It resolves `sid` to its pair record (tx-side SID == `PairId`, or rx-side SID
  == `SstpInbound.Id`) and deletes the **local** row first via the existing
  `DeleteStream`. If the local delete fails, the operation fails — there is
  nothing to be courteous about.
- Without `cascade_peer=true` (or with no resolvable peer `Server`), **no peer
  call is made**. `LocalDeleted=true`, `PeerAttempted=false` → the handler
  answers **200**.
- With `cascade_peer=true` and a resolvable peer `Server`, a courtesy `DELETE` is
  sent to the peer's SSF stream-configuration endpoint for the peer's `PairId`
  (`SstpMethod.PeerPairId`), using the stored `Server` credentials — the same
  foreign-server credential path the create cascade (ADR 0019) reuses.
  - Peer accepts → `PeerDeleted=true`, not a partial failure → **200**.
  - Peer fails, declines, or is unreachable → the error is captured in
    `PeerError`, `PeerDeleted=false`. The local row is **already gone**.
    `outcome.PartialFailure()` is true → the handler answers **207 Multi-Status**
    with the per-side outcome in the body.

The peer target is `SstpMethod.PeerPairId`; if it was never learned (a
local-only half), cascade is treated as a peer failure with a clear reason rather
than a silent no-op — the operator asked for cascade and deserves to know it
could not happen.

The HTTP wiring (query-param parsing, status-code mapping, peer `Server`
resolution) belongs to the routes/middleware slice (#163); this slice owns the
service contract and the `SstpDeleteOutcome`/`PartialFailure()` seam the handler
maps onto 200/207.

## Consequences

### Positive

- **Cleanup is never blocked by a dead peer.** The single most common delete
  scenario — peer already gone — always succeeds locally.
- **No surprise cross-node mutation.** Peer cleanup happens only when the operator
  explicitly opts in, matching the principle that touching a foreign node is a
  deliberate, credentialed act (ADR 0009).
- **Partial failure is observable, not swallowed.** 207 with per-side outcomes
  tells the operator exactly what to reconcile by hand, instead of a green 200
  that hides an orphaned peer row or a red 500 that hides a completed local
  delete.
- **Symmetric with UPDATE's immutability stance.** Repointing a pair is forbidden
  on UPDATE; delete is the one sanctioned teardown, with a clear local-vs-peer
  contract.

### Negative

- A successful `cascade_peer` delete plus a failed one are both "the local row is
  gone" — the operator must read the outcome body to tell them apart. Mitigated by
  distinct status codes (200 vs 207) and the explicit `PeerError`.
- After a 207 the peer may hold an orphaned half until its own operator deletes
  it. This is the accepted cost of not blocking local cleanup; the alternative
  (strict cascade) reintroduces the dead-peer pin we are explicitly rejecting.
- `cascade_peer` relies on a still-valid stored `Server` credential; a revoked
  credential surfaces as a 207, not a hard error. Acceptable — the local delete
  still succeeded and the operator is told peer cleanup did not.

## Related

- PRD #154 — SSTP as a third delivery method (Q37, Q48).
- Issue #162 — pair UPDATE/DELETE: patchable-fields whitelist, per-direction
  status, `cascade_peer` (this ADR).
- ADR 0018 — bidirectional `StreamStateRecord`; the tx/rx SID resolution this
  delete uses.
- ADR 0019 — create bootstrap + peer cascade; the foreign-server credential path
  reused for courtesy peer delete.
- ADR 0009 — foreign-server provisioning requires admin; why cross-node action is
  opt-in.
- `internal/services/stream_service_sstp.go` (`DeleteSstpPair`,
  `SstpDeleteOutcome`), draft-hunt-secevent-sstp-00.
