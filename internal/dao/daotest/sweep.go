package daotest

import (
	"context"
	"fmt"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Sweep parity cases (i2goSignals #360). Expiry instants sit in the future of
// the wall clock and the sweep is handed a later "now", so a store-side TTL
// monitor never races the sweep for the same references.

func insertAt(t *testing.T, d interfaces.EventDAO, sortTime time.Time, jtis ...string) {
	t.Helper()
	for _, jti := range jtis {
		rec := record(jti)
		rec.SortTime = sortTime
		if err := d.Insert(context.Background(), rec); err != nil {
			t.Fatalf("Insert %s: %v", jti, err)
		}
	}
}

func sweep(t *testing.T, d interfaces.EventDAO, now, cutoff time.Time, maxBodies int) interfaces.SweepResult {
	t.Helper()
	res, err := d.SweepExpired(context.Background(), now, cutoff, maxBodies)
	if err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	return res
}

func deliverRef(t *testing.T, d interfaces.EventDAO, sid, jti string, expireAt *time.Time) {
	t.Helper()
	if err := d.AddPending(context.Background(), interfaces.PendingRef{Jti: jti, AckJti: jti}, sid); err != nil {
		t.Fatalf("AddPending %s: %v", jti, err)
	}
	if n := ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{jti}, AckDate: time.Now(), ExpireAt: expireAt}); n != 1 {
		t.Fatalf("Ack %s acked %d, want 1", jti, n)
	}
}

func bodyExists(t *testing.T, d interfaces.EventDAO, jti string) bool {
	t.Helper()
	rec, err := d.FindByJTI(context.Background(), jti)
	return err == nil && rec != nil
}

// sweepRemovesExpiredReferences: step 1 removes exactly the references whose
// expireAt <= now; a reference with no expireAt is kept forever.
func sweepRemovesExpiredReferences(t *testing.T, d interfaces.EventDAO) {
	sid := ids.NewObjectID()
	base := time.Now()
	insert(t, d, "a", "b", "c")
	soon, later := ms(base.Add(time.Hour)), ms(base.Add(3*time.Hour))
	deliverRef(t, d, sid, "a", &soon)
	deliverRef(t, d, sid, "b", &later)
	deliverRef(t, d, sid, "c", nil)

	res := sweep(t, d, base.Add(2*time.Hour), time.Time{}, 100)
	if res.References != 1 || res.Bodies != 0 {
		t.Fatalf("sweep = %+v, want 1 reference, 0 bodies", res)
	}
	got := delivered(t, d, sid)
	if _, ok := got["a"]; ok {
		t.Errorf("expired reference a survived")
	}
	for _, jti := range []string{"b", "c"} {
		if _, ok := got[jti]; !ok {
			t.Errorf("reference %s removed before expiry", jti)
		}
	}
}

// sweepDeletesOnlyUnreferencedBodies: step 2 deletes a body older than the
// cutoff only when no reference in either state points at it, and never a
// body newer than the cutoff.
func sweepDeletesOnlyUnreferencedBodies(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	insertAt(t, d, old, "orphan", "pend", "deliv")
	insertAt(t, d, now, "young-orphan")
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "pend", AckJti: "pend"}, sid); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	deliverRef(t, d, sid, "deliv", nil)

	res := sweep(t, d, now, now.Add(-24*time.Hour), 100)
	if res.Bodies != 1 {
		t.Fatalf("sweep = %+v, want 1 body", res)
	}
	if bodyExists(t, d, "orphan") {
		t.Errorf("unreferenced old body survived")
	}
	for _, jti := range []string{"pend", "deliv", "young-orphan"} {
		if !bodyExists(t, d, jti) {
			t.Errorf("body %s wrongly swept", jti)
		}
	}
}

// sweepCopyFollowsInboundReference: a stored outbound copy (OriginalJti set)
// is keyed by its inbound JTI, so it survives while that JTI is referenced
// and goes with it once the reference expires.
func sweepCopyFollowsInboundReference(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	insertAt(t, d, old, "in-1")
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "in-1", AckJti: "out-1"}, sid); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	copyRec := record("out-1")
	copyRec.OriginalJti = "in-1"
	copyRec.SortTime = old
	expire := ms(now.Add(time.Hour))
	if n := ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{"out-1"}, AckDate: now, ExpireAt: &expire, Copies: []*model.EventRecord{copyRec}}); n != 1 {
		t.Fatalf("acked %d, want 1", n)
	}
	cutoff := now.Add(-24 * time.Hour)

	if res := sweep(t, d, now, cutoff, 100); res.Bodies != 0 || res.References != 0 {
		t.Fatalf("sweep while referenced = %+v, want nothing removed", res)
	}
	if !bodyExists(t, d, "in-1") || !bodyExists(t, d, "out-1") {
		t.Fatalf("inbound body or its copy swept while referenced")
	}

	res := sweep(t, d, now.Add(2*time.Hour), cutoff, 100)
	if res.References != 1 || res.Bodies != 2 {
		t.Fatalf("sweep after expiry = %+v, want 1 reference, 2 bodies", res)
	}
	if bodyExists(t, d, "in-1") || bodyExists(t, d, "out-1") {
		t.Errorf("inbound body or its copy survived its last reference")
	}
}

// sweepBoundedAndResumesAcrossTies: each pass examines at most maxBodies
// bodies, and repeated passes reach every body even when many share one
// sortTime (iat has second precision) and some of them stay referenced.
func sweepBoundedAndResumesAcrossTies(t *testing.T, d interfaces.EventDAO) {
	sid := ids.NewObjectID()
	now := time.Now()
	tie := ms(now.Add(-48 * time.Hour)).Truncate(time.Second)
	var orphans []string
	for i := 0; i < 5; i++ {
		orphans = append(orphans, fmt.Sprintf("o%d", i))
	}
	insertAt(t, d, tie, orphans...)
	insertAt(t, d, tie, "r0", "r1")
	deliverRef(t, d, sid, "r0", nil)
	deliverRef(t, d, sid, "r1", nil)
	cutoff := now.Add(-24 * time.Hour)

	var total int64
	for pass := 0; pass < 4; pass++ {
		res := sweep(t, d, now, cutoff, 3)
		if res.Bodies > 3 {
			t.Fatalf("pass %d deleted %d bodies, want at most 3", pass, res.Bodies)
		}
		total += res.Bodies
	}
	if total != int64(len(orphans)) {
		t.Fatalf("deleted %d bodies over 4 passes, want %d", total, len(orphans))
	}
	for _, jti := range orphans {
		if bodyExists(t, d, jti) {
			t.Errorf("orphan %s never swept", jti)
		}
	}
	for _, jti := range []string{"r0", "r1"} {
		if !bodyExists(t, d, jti) {
			t.Errorf("referenced body %s swept", jti)
		}
	}
}
