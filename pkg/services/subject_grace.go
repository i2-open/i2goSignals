package services

import (
    "time"

    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SSF §9.3 removal-grace evaluation. The component is pure: every decision is a
// function of (baseline, entry, now) — no DAO, no clock side effects, no
// package-level state — so the clock-boundary behavior is verified cheaply and
// exhaustively (PRD #97 issue #99). The SubjectFilterService composes these
// helpers; the delivery-time predicate calls entryDelivers; AddSubject/
// RemoveSubject call stampEnforceAt and the planChange helper to decide
// whether a change is a deferred stop or an immediate revive.

// stampEnforceAt returns the §9.3 deadline for a stop-delivery operation:
// now + graceSeconds, or zero when graceSeconds is non-positive (no grace —
// the operation takes effect immediately).
func stampEnforceAt(now time.Time, graceSeconds int) time.Time {
    if graceSeconds <= 0 {
        return time.Time{}
    }
    return now.Add(time.Duration(graceSeconds) * time.Second)
}

// entryPending reports whether entry is in its §9.3 grace window — a
// delivery-stopping change has been recorded but has not yet taken effect at
// now. A zero EnforceAt is never pending.
func entryPending(entry *model.SubjectFilterEntry, now time.Time) bool {
    return entry != nil && !entry.EnforceAt.IsZero() && entry.EnforceAt.After(now)
}

// entryDelivers reports whether the stream's subject filter should deliver an
// event for the subject the entry represents at time now. The rule gates the
// §9.3 effect, not the SSF verb: while pending, an entry keeps delivery in the
// pre-stop state regardless of baseline. The truth table by (baseline, entry):
//
//   NONE                ALL
//   ────────────────    ────────────────
//   nil       → drop    nil       → deliver
//   active    → deliver active    → drop
//   pending   → deliver pending   → deliver   (§9.3 window — still delivering)
//   elapsed   → drop    elapsed   → drop      (lazy-purge: stop is enforced)
//
// "active" = EnforceAt zero; "pending" = EnforceAt in the future at now;
// "elapsed" = EnforceAt at-or-before now.
func entryDelivers(baseline string, entry *model.SubjectFilterEntry, now time.Time) bool {
    if entry == nil {
        return baseline == model.DefaultSubjectsAll
    }
    if entry.EnforceAt.IsZero() {
        // Fully active: the entry's baseline-opposing meaning is in force.
        return baseline == model.DefaultSubjectsNone
    }
    if entry.EnforceAt.After(now) {
        // Pending §9.3 window — keep the pre-stop delivery decision, which
        // is "delivering" regardless of baseline.
        return true
    }
    // Elapsed: the stop has taken effect — drop under either baseline. (For
    // NONE the inclusion is logically gone; for ALL the exclusion is in force.)
    return false
}

// graceChange captures the §9.3 mutation that applySubjectChange should
// perform for a given (baseline, existing entry, start-or-stop) decision. It
// keeps the entry-lifecycle policy — upsert / stamp / lazy-purge, never a
// mid-grace hard delete — in one tested place.
type graceChange struct {
    // upsert is the entry to write when non-nil. EnforceAt may be zero
    // (active/revive) or set (pending stop).
    upsert *model.SubjectFilterEntry
    // remove is true when the entry should be deleted outright (the
    // start-delivery path on an ALL baseline, or a grace=0 stop on NONE).
    remove bool
}

// planGraceChange returns the storage mutation for a stop-or-start decision.
//
// add reports the receiver's request: true = start delivery, false = stop. The
// existing entry (or nil) is consulted for idempotency: a re-stop during the
// grace window does not extend the deadline. graceSeconds may be 0 (no §9.3
// grace) or > 0; when 0, stop-delivery falls back to the pre-#99 immediate
// behavior so a server that does not opt into §9.3 sees no entry-lifecycle
// change.
func planGraceChange(baseline string, existing *model.SubjectFilterEntry, template model.SubjectFilterEntry, add bool, graceSeconds int, now time.Time) graceChange {
    if add {
        return planStart(baseline, existing, template)
    }
    return planStop(baseline, existing, template, graceSeconds, now)
}

// planStart handles a start-delivery request. The grace window does not apply
// to a delivery-starting change — it always takes effect immediately. On
// NONE the entry is upserted active (also revives a pending-removal entry,
// clearing EnforceAt without duplicating the row). On ALL the entry is
// removed outright (cancels a pending-stop exclusion, drops an active one).
func planStart(baseline string, existing *model.SubjectFilterEntry, template model.SubjectFilterEntry) graceChange {
    if baseline == model.DefaultSubjectsNone {
        // EnforceAt is explicitly cleared so a re-Add during the grace
        // window revives the pending entry rather than duplicating it.
        template.EnforceAt = time.Time{}
        return graceChange{upsert: &template}
    }
    // ALL baseline (and any unknown): start-delivery drops any exclusion.
    if existing == nil {
        return graceChange{}
    }
    return graceChange{remove: true}
}

// planStop handles a stop-delivery request. With grace > 0 the entry is
// upserted with EnforceAt = now + grace; a re-stop on an already-pending
// entry is idempotent (the deadline is not extended). With grace == 0 the
// operation falls back to the pre-#99 immediate behavior so an operator who
// has not opted into §9.3 sees no change.
func planStop(baseline string, existing *model.SubjectFilterEntry, template model.SubjectFilterEntry, graceSeconds int, now time.Time) graceChange {
    if graceSeconds <= 0 {
        // Pre-#99 immediate behavior.
        if baseline == model.DefaultSubjectsNone {
            // Drop the inclusion (no-op when absent).
            if existing == nil {
                return graceChange{}
            }
            return graceChange{remove: true}
        }
        // ALL: insert an active exclusion.
        template.EnforceAt = time.Time{}
        return graceChange{upsert: &template}
    }

    // Grace > 0: §9.3 deferral.
    if existing != nil && entryPending(existing, now) {
        // A re-stop during the grace window does not extend the deadline.
        return graceChange{}
    }
    if baseline == model.DefaultSubjectsNone && existing == nil {
        // Stopping delivery of a subject that was never delivering is a no-op.
        return graceChange{}
    }
    if baseline == model.DefaultSubjectsAll && existing != nil && existing.EnforceAt.IsZero() {
        // Already actively excluded — idempotent.
        return graceChange{}
    }
    template.EnforceAt = stampEnforceAt(now, graceSeconds)
    return graceChange{upsert: &template}
}
