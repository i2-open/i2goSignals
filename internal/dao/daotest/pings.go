package daotest

import (
	"context"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Ping-purge parity cases (ADR 0048, i2goSignals #388). They run in the
// Deliveries table, so both adapters are held to them.

// pingRecord is a stored SSF Verification Event received at receivedAt.
func pingRecord(jti string, receivedAt time.Time) *model.EventRecord {
	ev := goSet.SecurityEventToken{Events: map[string]interface{}{events.VerificationEventUri: map[string]interface{}{}}}
	ev.ID = jti
	return &model.EventRecord{Jti: jti, Event: ev, Types: []string{events.VerificationEventUri},
		Original: `{"jti":"` + jti + `"}`, SortTime: receivedAt, ReceivedAt: receivedAt}
}

// dataRecord is a non-ping event received at receivedAt.
func dataRecord(jti string, receivedAt time.Time) *model.EventRecord {
	rec := record(jti)
	rec.Types = []string{"urn:test"}
	rec.SortTime, rec.ReceivedAt = receivedAt, receivedAt
	return rec
}

func insertRec(t *testing.T, d interfaces.EventDAO, rec *model.EventRecord) {
	t.Helper()
	if err := d.Insert(context.Background(), rec); err != nil {
		t.Fatalf("Insert %s: %v", rec.Jti, err)
	}
}

func addPending(t *testing.T, d interfaces.EventDAO, sid string, ref interfaces.PendingRef) {
	t.Helper()
	if err := d.AddPending(context.Background(), ref, sid); err != nil {
		t.Fatalf("AddPending %s/%s: %v", ref.Jti, sid, err)
	}
}

func hasBody(t *testing.T, d interfaces.EventDAO, jti string) bool {
	t.Helper()
	rec, err := d.FindByJTI(context.Background(), jti)
	return err == nil && rec != nil
}

func purgePings(t *testing.T, d interfaces.EventDAO, from, to time.Time) interfaces.PingPurgeResult {
	t.Helper()
	res, err := d.PurgePingWindow(context.Background(), from, to)
	if err != nil {
		t.Fatalf("PurgePingWindow: %v", err)
	}
	return res
}

// pingPurgeDeletesOnlyDeliveredOldPings: a delivered ping older than the
// cutoff goes with its body; a younger ping stays; a ping pending on one
// stream and delivered on another keeps its body and pending row; a ping never
// queued goes; a data event of the same age is untouched.
func pingPurgeDeletesOnlyDeliveredOldPings(t *testing.T, d interfaces.EventDAO) {
	now := ms(time.Now())
	old, cutoff, young := now.Add(-48*time.Hour), now.Add(-24*time.Hour), now.Add(-time.Hour)
	sidA, sidB := ids.NewObjectID(), ids.NewObjectID()

	insertRec(t, d, pingRecord("old-ping", old))
	addPending(t, d, sidA, interfaces.PendingRef{Jti: "old-ping", AckJti: "old-ping", EnqueuedAt: old, Ping: true})
	insertRec(t, d, pingRecord("young-ping", young))
	addPending(t, d, sidA, interfaces.PendingRef{Jti: "young-ping", AckJti: "young-ping", EnqueuedAt: young, Ping: true})
	insertRec(t, d, pingRecord("split-ping", old))
	addPending(t, d, sidA, interfaces.PendingRef{Jti: "split-ping", AckJti: "split-ping", EnqueuedAt: old, Ping: true})
	addPending(t, d, sidB, interfaces.PendingRef{Jti: "split-ping", AckJti: "split-ping", EnqueuedAt: old, Ping: true})
	insertRec(t, d, pingRecord("never-queued", old))
	insertRec(t, d, dataRecord("old-data", old))
	addPending(t, d, sidA, interfaces.PendingRef{Jti: "old-data", AckJti: "old-data", EnqueuedAt: old})
	ack(t, d, interfaces.AckBatch{StreamID: sidA, Jtis: []string{"old-ping", "young-ping", "split-ping", "old-data"}, AckDate: now})

	res := purgePings(t, d, old.Add(-time.Hour), cutoff)
	if res.Deliveries != 2 || res.Bodies != 2 {
		t.Errorf("PurgePingWindow = %+v, want 2 deliveries (old-ping, split-ping on A) and 2 bodies (old-ping, never-queued)", res)
	}
	for jti, want := range map[string]bool{"old-ping": false, "young-ping": true, "split-ping": true, "never-queued": false, "old-data": true} {
		if got := hasBody(t, d, jti); got != want {
			t.Errorf("body %s stored = %v, want %v", jti, got, want)
		}
	}
	gotA := delivered(t, d, sidA)
	for jti, want := range map[string]bool{"old-ping": false, "young-ping": true, "split-ping": false, "old-data": true} {
		if _, got := gotA[jti]; got != want {
			t.Errorf("delivered row %s on A = %v, want %v", jti, got, want)
		}
	}
	if _, ok := pendingRef(t, d, sidB, "split-ping"); !ok {
		t.Error("pending row split-ping on B was purged")
	}
}

// oldestPingStoredAt reports the oldest ping body's receivedAt, ignoring data
// events.
func oldestPingStoredAt(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	if _, ok, err := d.OldestPingStoredAt(ctx); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v, want none", ok, err)
	}
	now := ms(time.Now())
	insertRec(t, d, dataRecord("data", now.Add(-72*time.Hour)))
	if _, ok, err := d.OldestPingStoredAt(ctx); err != nil || ok {
		t.Fatalf("data only: ok=%v err=%v, want none", ok, err)
	}
	insertRec(t, d, pingRecord("p2", now.Add(-time.Hour)))
	insertRec(t, d, pingRecord("p1", now.Add(-48*time.Hour)))
	at, ok, err := d.OldestPingStoredAt(ctx)
	if err != nil || !ok || !at.Equal(now.Add(-48*time.Hour)) {
		t.Fatalf("OldestPingStoredAt = (%v, %v, %v), want %v", at, ok, err, now.Add(-48*time.Hour))
	}
}

// receivedAtStamped: every body write stamps receivedAt.
func receivedAtStamped(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	before := ms(time.Now()).Add(-time.Millisecond)
	if err := d.Insert(ctx, record("ins")); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if errs, err := d.InsertMany(ctx, []*model.EventRecord{record("many")}); err != nil || errs[0] != nil {
		t.Fatalf("InsertMany = (%v, %v)", errs, err)
	}
	if errs, err := d.InsertWithPending(ctx, []*model.EventRecord{record("iwp")}, map[string][]interfaces.PendingRef{sid: {{Jti: "iwp", AckJti: "iwp-out"}}}); err != nil || errs[0] != nil {
		t.Fatalf("InsertWithPending = (%v, %v)", errs, err)
	}
	copyRec := record("iwp-out")
	copyRec.OriginalJti = "iwp"
	ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{"iwp-out"}, AckDate: time.Now(), Copies: []*model.EventRecord{copyRec}})
	after := ms(time.Now()).Add(time.Millisecond)
	for _, jti := range []string{"ins", "many", "iwp", "iwp-out"} {
		rec, err := d.FindByJTI(ctx, jti)
		if err != nil || rec == nil {
			t.Fatalf("FindByJTI %s = (%v, %v)", jti, rec, err)
		}
		if rec.ReceivedAt.Before(before) || rec.ReceivedAt.After(after) {
			t.Errorf("%s receivedAt = %v, want within [%v, %v]", jti, rec.ReceivedAt, before, after)
		}
	}
}

// pingMarkerEveryWritePath: each delivery write path marks a ping's row, so the
// purge deletes it once delivered, and leaves a data event's row unmarked.
func pingMarkerEveryWritePath(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	old := ms(time.Now().Add(-48 * time.Hour))
	paths := []struct {
		name  string
		write func(t *testing.T, sid string, rec *model.EventRecord, ping bool)
	}{
		{"AddPending", func(t *testing.T, sid string, rec *model.EventRecord, ping bool) {
			insertRec(t, d, rec)
			addPending(t, d, sid, interfaces.PendingRef{Jti: rec.Jti, AckJti: rec.Jti, Ping: ping})
		}},
		{"AddPendingMany", func(t *testing.T, sid string, rec *model.EventRecord, ping bool) {
			insertRec(t, d, rec)
			if err := d.AddPendingMany(ctx, []interfaces.PendingRef{{Jti: rec.Jti, AckJti: rec.Jti, Ping: ping}}, sid); err != nil {
				t.Fatalf("AddPendingMany: %v", err)
			}
		}},
		{"InsertWithPending", func(t *testing.T, sid string, rec *model.EventRecord, _ bool) {
			// The DAO derives the marker from the records it holds.
			errs, err := d.InsertWithPending(ctx, []*model.EventRecord{rec}, map[string][]interfaces.PendingRef{sid: {{Jti: rec.Jti, AckJti: rec.Jti}}})
			if err != nil || errs[0] != nil {
				t.Fatalf("InsertWithPending = (%v, %v)", errs, err)
			}
		}},
		{"EnsurePending", func(t *testing.T, sid string, rec *model.EventRecord, _ bool) {
			// The DAO reads the body's types.
			insertRec(t, d, rec)
			if _, err := d.EnsurePending(ctx, rec.Jti, map[string]string{sid: rec.Jti}); err != nil {
				t.Fatalf("EnsurePending: %v", err)
			}
		}},
	}
	for _, p := range paths {
		sid := ids.NewObjectID()
		ping, data := "ping-"+p.name, "data-"+p.name
		p.write(t, sid, pingRecord(ping, old), true)
		p.write(t, sid, dataRecord(data, old), false)
		ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{ping, data}, AckDate: time.Now()})
		purgePings(t, d, old.Add(-time.Hour), time.Now().Add(time.Second))
		got := delivered(t, d, sid)
		if _, ok := got[ping]; ok {
			t.Errorf("%s: delivered ping row kept: not marked", p.name)
		}
		if _, ok := got[data]; !ok {
			t.Errorf("%s: delivered data row purged", p.name)
		}
	}
}

// PreUpgradeSeeder is implemented, in an adapter's test files, by a DAO that
// can store a body the way a release before ADR 0048 did: with no receivedAt,
// stored at storedAt by the adapter's own stored-at fallback (the ObjectId
// `_id` time in Mongo, SortTime in memory). storedAt must be whole seconds.
// The pre-upgrade cases (#389) skip on a DAO that does not implement it.
type PreUpgradeSeeder interface {
	SeedPreUpgradeBody(t *testing.T, rec *model.EventRecord, storedAt time.Time)
}

func preUpgradeSeeder(t *testing.T, d interfaces.EventDAO) PreUpgradeSeeder {
	t.Helper()
	s, ok := d.(PreUpgradeSeeder)
	if !ok {
		t.Skipf("%T cannot seed pre-upgrade bodies", d)
	}
	return s
}

// preUpgradePingPurgedByStoredAt (#389): a ping body with no receivedAt is
// purged by its stored-at fallback once older than the cutoff; a younger one
// stays; one still pending on a stream stays with its pending row; a
// pre-upgrade data body of the same age is untouched.
func preUpgradePingPurgedByStoredAt(t *testing.T, d interfaces.EventDAO) {
	seed := preUpgradeSeeder(t, d)
	now := time.Now().UTC().Truncate(time.Second)
	old, cutoff, young := now.Add(-48*time.Hour), now.Add(-24*time.Hour), now.Add(-time.Hour)
	sid := ids.NewObjectID()

	pre := func(rec *model.EventRecord) *model.EventRecord {
		rec.ReceivedAt = time.Time{}
		return rec
	}
	seed.SeedPreUpgradeBody(t, pre(pingRecord("pre-old", old)), old)
	seed.SeedPreUpgradeBody(t, pre(pingRecord("pre-young", young)), young)
	seed.SeedPreUpgradeBody(t, pre(pingRecord("pre-pending", old)), old)
	addPending(t, d, sid, interfaces.PendingRef{Jti: "pre-pending", AckJti: "pre-pending", EnqueuedAt: old})
	seed.SeedPreUpgradeBody(t, pre(dataRecord("pre-data", old)), old)

	res := purgePings(t, d, old.Add(-time.Hour), cutoff)
	if res.Bodies != 1 {
		t.Errorf("PurgePingWindow = %+v, want 1 body (pre-old)", res)
	}
	for jti, want := range map[string]bool{"pre-old": false, "pre-young": true, "pre-pending": true, "pre-data": true} {
		if got := hasBody(t, d, jti); got != want {
			t.Errorf("body %s stored = %v, want %v", jti, got, want)
		}
	}
	if _, ok := pendingRef(t, d, sid, "pre-pending"); !ok {
		t.Error("pending row pre-pending was purged")
	}
	// The window just before is empty: nothing older than the oldest body.
	if res := purgePings(t, d, old.Add(-2*time.Hour), old.Add(-time.Hour)); res.Bodies != 0 {
		t.Errorf("empty window purged %+v", res)
	}
}

// oldestPingStoredAtPreUpgrade (#389): the oldest ping is the minimum over
// stamped bodies' receivedAt and pre-upgrade bodies' stored-at fallback.
func oldestPingStoredAtPreUpgrade(t *testing.T, d interfaces.EventDAO) {
	seed := preUpgradeSeeder(t, d)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	insertRec(t, d, pingRecord("stamped", now.Add(-time.Hour)))
	seed.SeedPreUpgradeBody(t, dataRecord("pre-data", now.Add(-96*time.Hour)), now.Add(-96*time.Hour))
	pre := pingRecord("pre", now.Add(-48*time.Hour))
	pre.ReceivedAt = time.Time{}
	seed.SeedPreUpgradeBody(t, pre, now.Add(-48*time.Hour))
	at, ok, err := d.OldestPingStoredAt(ctx)
	if err != nil || !ok || !at.Equal(now.Add(-48*time.Hour)) {
		t.Fatalf("OldestPingStoredAt = (%v, %v, %v), want the pre-upgrade %v", at, ok, err, now.Add(-48*time.Hour))
	}
	insertRec(t, d, pingRecord("stamped-older", now.Add(-72*time.Hour)))
	at, ok, err = d.OldestPingStoredAt(ctx)
	if err != nil || !ok || !at.Equal(now.Add(-72*time.Hour)) {
		t.Fatalf("OldestPingStoredAt = (%v, %v, %v), want the stamped %v", at, ok, err, now.Add(-72*time.Hour))
	}
}
