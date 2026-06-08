package services

import (
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SSF §9.3 HYBRID upstream-relay decision (PRD #97 issue #100). The pure
// counterpart to subject_grace.go: given the entry's state before the change,
// the planGraceChange result, and the receiver's add-vs-stop request, decide
// whether the upstream relay should fire now, be deferred to the
// push-transmitter lease owner's sweep, or be skipped entirely.
//
// The invariant we are preserving: the upstream subscription must track the
// *enforced* downstream-interest state, not the receiver's instantaneous
// request. A receiver Remove that lands a pending entry defers the upstream
// remove until enforceAt — the upstream keeps feeding events through the
// grace window, so the §9.3 protection is hollow only if we let the relay
// fire too early. A receiver Add that revives a pending entry is a no-op
// upstream because the upstream remove was never sent.

// RelayDecision tells the caller what to do with the HYBRID upstream relay
// for a downstream subject change. See planHybridRelay for the inputs.
type RelayDecision int

const (
    // RelayDecisionNone means no upstream relay is required: a re-Add of a
    // pending entry (upstream subscription still active), an idempotent
    // re-stop (no change), or a no-op against an already-enforced entry.
    RelayDecisionNone RelayDecision = iota
    // RelayDecisionImmediate means the caller should fire the upstream
    // relay synchronously — the pre-#100 behavior for fresh adds, and the
    // grace-zero fallback for every mutation.
    RelayDecisionImmediate
    // RelayDecisionDeferred means a stop-delivery change with grace > 0
    // landed a pending entry. The upstream relay is held back; the
    // push-transmitter lease owner's sweep will fire it at enforceAt by
    // calling SubjectRelayService.RelayHybrid for every entry whose
    // EnforceAt has elapsed.
    RelayDecisionDeferred
)

// planHybridRelay returns the upstream-relay action the caller should take
// for a HYBRID downstream subject change, given the entry state before the
// change, the planGraceChange storage mutation, the receiver's intent (add
// vs stop), and the resolved grace window.
//
// graceSeconds is the per-stream override or the server-wide default; a
// non-positive value falls back to the pre-#100 immediate-relay behavior,
// so a server that has not opted into §9.3 sees no change to its HYBRID
// relay timing.
func planHybridRelay(before *model.SubjectFilterEntry, change graceChange, add bool, graceSeconds int) RelayDecision {
    if graceSeconds <= 0 {
        // Pre-#100 behavior: relay whenever a mutation happens, otherwise
        // do nothing. RelayHybrid still suppresses redundant relays via
        // its interested-set check.
        if change.upsert == nil && !change.remove {
            return RelayDecisionNone
        }
        return RelayDecisionImmediate
    }

    if add {
        // Re-Add of a pending entry revives it (planStart upserts with
        // EnforceAt cleared). The upstream remove was deferred and never
        // sent, so the upstream subscription is still active — no relay.
        if before != nil && !before.EnforceAt.IsZero() {
            return RelayDecisionNone
        }
        // Idempotent re-Add of an already-active entry — planGraceChange
        // returned no mutation, so there's nothing to relay either.
        if change.upsert == nil && !change.remove {
            return RelayDecisionNone
        }
        // Fresh Add: the upstream may need a 0→1 transition relay. The
        // RelayHybrid call still consults siblings, so a redundant relay
        // is suppressed there.
        return RelayDecisionImmediate
    }

    // Stop-delivery with grace > 0. planStop only ever returns an upsert
    // that stamps EnforceAt (never a remove). If the planned upsert
    // carries a pending deadline, defer the upstream relay to the sweep.
    if change.upsert != nil && !change.upsert.EnforceAt.IsZero() {
        return RelayDecisionDeferred
    }
    // Idempotent re-stop or no-op (e.g. a Remove on NONE with no entry,
    // or a re-stop of an already-pending or already-enforced entry).
    return RelayDecisionNone
}
