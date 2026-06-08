package services

import (
    "testing"
    "time"

    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Pure unit tests for the SSF §9.3 grace-evaluation component (PRD #97 issue
// #99). These exercise the stamp/clear/revive logic, the clock-boundary
// predicate, and the gate-the-effect symmetry exhaustively — fast, no DAO, no
// goroutines, no real clock.

var graceNow = time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

// TestStampEnforceAt_AddsGraceWindow verifies a stop-delivery stamp pushes the
// deadline grace seconds into the future when grace is positive.
func TestStampEnforceAt_AddsGraceWindow(t *testing.T) {
    got := stampEnforceAt(graceNow, 30)
    want := graceNow.Add(30 * time.Second)
    if !got.Equal(want) {
        t.Fatalf("stampEnforceAt: want %v, got %v", want, got)
    }
}

// TestStampEnforceAt_ZeroAndNegativeGraceReturnZero verifies the "no grace"
// signal — a zero-value time the predicate treats as "fully active /
// enforced". The negative arm is defensive; SubjectRemovalGraceDefaultSeconds
// already clamps to zero.
func TestStampEnforceAt_ZeroAndNegativeGraceReturnZero(t *testing.T) {
    for _, g := range []int{0, -1, -3600} {
        if got := stampEnforceAt(graceNow, g); !got.IsZero() {
            t.Fatalf("stampEnforceAt(grace=%d): want zero, got %v", g, got)
        }
    }
}

// TestEntryPending_TrueOnlyInTheWindow verifies the §9.3 window predicate.
func TestEntryPending_TrueOnlyInTheWindow(t *testing.T) {
    tests := []struct {
        name string
        e    *model.SubjectFilterEntry
        want bool
    }{
        {"nil entry", nil, false},
        {"zero EnforceAt (fully active)", &model.SubjectFilterEntry{}, false},
        {"EnforceAt in the future (pending)", &model.SubjectFilterEntry{EnforceAt: graceNow.Add(10 * time.Second)}, true},
        {"EnforceAt at now (boundary, enforced)", &model.SubjectFilterEntry{EnforceAt: graceNow}, false},
        {"EnforceAt in the past (elapsed)", &model.SubjectFilterEntry{EnforceAt: graceNow.Add(-time.Second)}, false},
    }
    for _, tc := range tests {
        if got := entryPending(tc.e, graceNow); got != tc.want {
            t.Errorf("%s: want %v, got %v", tc.name, tc.want, got)
        }
    }
}

// TestEntryDelivers_TruthTable verifies the predicate exhaustively across
// (baseline × entry-state), so the "gate the effect, not the verb" symmetry
// is pinned: while pending, every baseline keeps the pre-stop delivery
// decision.
func TestEntryDelivers_TruthTable(t *testing.T) {
    active := &model.SubjectFilterEntry{}
    pending := &model.SubjectFilterEntry{EnforceAt: graceNow.Add(10 * time.Second)}
    elapsed := &model.SubjectFilterEntry{EnforceAt: graceNow.Add(-time.Second)}

    tests := []struct {
        name     string
        baseline string
        entry    *model.SubjectFilterEntry
        want     bool
    }{
        {"NONE + nil → drop", model.DefaultSubjectsNone, nil, false},
        {"NONE + active inclusion → deliver", model.DefaultSubjectsNone, active, true},
        {"NONE + pending removal → deliver (§9.3)", model.DefaultSubjectsNone, pending, true},
        {"NONE + elapsed removal → drop", model.DefaultSubjectsNone, elapsed, false},
        {"ALL + nil → deliver", model.DefaultSubjectsAll, nil, true},
        {"ALL + active exclusion → drop", model.DefaultSubjectsAll, active, false},
        {"ALL + pending exclusion → deliver (§9.3)", model.DefaultSubjectsAll, pending, true},
        {"ALL + elapsed exclusion → drop", model.DefaultSubjectsAll, elapsed, false},
    }
    for _, tc := range tests {
        if got := entryDelivers(tc.baseline, tc.entry, graceNow); got != tc.want {
            t.Errorf("%s: want %v, got %v", tc.name, tc.want, got)
        }
    }
}

// TestEntryDelivers_BoundaryAtEnforceAt verifies the clock-boundary semantics:
// at exactly now == enforceAt the stop is treated as enforced (the entry has
// "elapsed"), not still-pending. This bounds the worst-case extra delivery
// duration at the grace window.
func TestEntryDelivers_BoundaryAtEnforceAt(t *testing.T) {
    boundary := &model.SubjectFilterEntry{EnforceAt: graceNow}
    if entryDelivers(model.DefaultSubjectsNone, boundary, graceNow) {
        t.Fatal("NONE at enforceAt boundary must NOT deliver (entry is enforced, not pending)")
    }
    if entryDelivers(model.DefaultSubjectsAll, boundary, graceNow) {
        t.Fatal("ALL at enforceAt boundary must NOT deliver (exclusion has taken effect)")
    }
}

// TestPlanGraceChange_StopWithGraceUpserts verifies that a stop-delivery
// request with grace > 0 produces an upsert with EnforceAt = now + grace,
// independent of baseline.
func TestPlanGraceChange_StopWithGraceUpserts(t *testing.T) {
    template := model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}

    for _, baseline := range []string{model.DefaultSubjectsNone, model.DefaultSubjectsAll} {
        var existing *model.SubjectFilterEntry
        if baseline == model.DefaultSubjectsNone {
            // NONE-stop only enters the grace flow if an inclusion exists.
            existing = &model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}
        }
        change := planGraceChange(baseline, existing, template, false /*add*/, 30, graceNow)
        if change.upsert == nil {
            t.Fatalf("baseline=%s: stop with grace>0 must upsert", baseline)
        }
        if change.remove {
            t.Fatalf("baseline=%s: stop with grace>0 must not remove", baseline)
        }
        wantAt := graceNow.Add(30 * time.Second)
        if !change.upsert.EnforceAt.Equal(wantAt) {
            t.Fatalf("baseline=%s: EnforceAt want %v, got %v", baseline, wantAt, change.upsert.EnforceAt)
        }
    }
}

// TestPlanGraceChange_StopWithGraceIsIdempotent verifies that a re-stop on an
// already-pending entry does not extend the deadline — it is a no-op.
func TestPlanGraceChange_StopWithGraceIsIdempotent(t *testing.T) {
    pending := &model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1", EnforceAt: graceNow.Add(20 * time.Second)}
    template := model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}

    change := planGraceChange(model.DefaultSubjectsNone, pending, template, false, 30, graceNow)
    if change.upsert != nil || change.remove {
        t.Fatalf("re-stop on a pending entry must be a no-op, got upsert=%v remove=%v", change.upsert, change.remove)
    }
}

// TestPlanGraceChange_StartOnNoneRevivesAndClearsEnforceAt verifies the §9.3
// revive rule: a start-delivery during the grace window upserts the entry
// with EnforceAt cleared, so the pending stop is cancelled with no
// delivery gap and no duplicate row.
func TestPlanGraceChange_StartOnNoneRevivesAndClearsEnforceAt(t *testing.T) {
    pending := &model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1", EnforceAt: graceNow.Add(20 * time.Second)}
    template := model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1", EnforceAt: graceNow.Add(99 * time.Second) /* stale value should be cleared */}

    change := planGraceChange(model.DefaultSubjectsNone, pending, template, true /*add*/, 30, graceNow)
    if change.upsert == nil {
        t.Fatal("start-delivery on NONE must upsert (revive or create)")
    }
    if !change.upsert.EnforceAt.IsZero() {
        t.Fatalf("revive must clear EnforceAt, got %v", change.upsert.EnforceAt)
    }
}

// TestPlanGraceChange_StartOnAllRemovesExclusion verifies the symmetric ALL
// start rule: a start-delivery drops the exclusion (whether active or
// pending), cancelling any in-flight grace.
func TestPlanGraceChange_StartOnAllRemovesExclusion(t *testing.T) {
    exclusion := &model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1", EnforceAt: graceNow.Add(20 * time.Second)}
    template := model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}

    change := planGraceChange(model.DefaultSubjectsAll, exclusion, template, true, 30, graceNow)
    if !change.remove {
        t.Fatal("start-delivery on ALL must remove the exclusion")
    }
    if change.upsert != nil {
        t.Fatal("start-delivery on ALL must not upsert")
    }
}

// TestPlanGraceChange_StopWithZeroGraceFallsBackImmediate verifies that an
// operator who has not opted into §9.3 (grace=0) sees the pre-#99 behavior
// exactly — NONE drops, ALL inserts an active exclusion — with no EnforceAt
// stamped on storage.
func TestPlanGraceChange_StopWithZeroGraceFallsBackImmediate(t *testing.T) {
    inclusion := &model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}
    template := model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}

    none := planGraceChange(model.DefaultSubjectsNone, inclusion, template, false, 0, graceNow)
    if !none.remove {
        t.Fatal("NONE + grace=0 + existing inclusion: must remove immediately")
    }

    all := planGraceChange(model.DefaultSubjectsAll, nil, template, false, 0, graceNow)
    if all.upsert == nil {
        t.Fatal("ALL + grace=0: must upsert an active exclusion")
    }
    if !all.upsert.EnforceAt.IsZero() {
        t.Fatalf("ALL + grace=0: EnforceAt must be zero, got %v", all.upsert.EnforceAt)
    }
}

// TestPlanGraceChange_StopOnAlreadyEnforcedAllIsNoop verifies that re-stopping
// a subject already actively excluded on ALL is a no-op, even with grace>0.
func TestPlanGraceChange_StopOnAlreadyEnforcedAllIsNoop(t *testing.T) {
    active := &model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}
    template := model.SubjectFilterEntry{StreamId: "s1", CanonicalKey: "k1"}

    change := planGraceChange(model.DefaultSubjectsAll, active, template, false, 30, graceNow)
    if change.upsert != nil || change.remove {
        t.Fatalf("re-stop on actively-excluded ALL entry must be a no-op, got upsert=%v remove=%v", change.upsert, change.remove)
    }
}
