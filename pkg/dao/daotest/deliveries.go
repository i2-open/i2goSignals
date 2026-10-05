// Package daotest holds store-parity cases that every EventDAO adapter must
// pass. Each adapter's tests call the suite with a constructor for a fresh,
// empty store, so the memory and MongoDB adapters are held to one contract.
package daotest

import (
	"context"
	"sync"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Deliveries runs the deliveries-collection parity cases (i2goSignals #359)
// against the store newDAO returns. newDAO must return an empty store; it is
// called once per case.
func Deliveries(t *testing.T, newDAO func(t *testing.T) interfaces.EventDAO) {
	cases := []struct {
		name string
		fn   func(t *testing.T, d interfaces.EventDAO)
	}{
		{"PendingPageAscendingWithAckJti", pendingPageAscendingWithAckJti},
		{"AckMatchesAckJtiNotJti", ackMatchesAckJtiNotJti},
		{"AckExactlyOnceAcrossConcurrentCallers", ackExactlyOnce},
		{"AckStoresExpireAtAndCopies", ackStoresExpireAtAndCopies},
		{"AddPendingRequeuesDelivered", addPendingRequeuesDelivered},
		{"EnsurePendingKeepsAckJti", ensurePendingKeepsAckJti},
		{"ResetPendingAckJtiTouchesPendingOnly", resetPendingAckJtiPendingOnly},
		{"CreatedAtRules", createdAtRules},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.fn(t, newDAO(t)) })
	}
}

// ms truncates to the millisecond precision every store keeps.
func ms(tm time.Time) time.Time { return tm.UTC().Truncate(time.Millisecond) }

func record(jti string) *model.EventRecord {
	ev := goSet.SecurityEventToken{Events: map[string]interface{}{"urn:test": map[string]interface{}{}}}
	ev.ID = jti
	return &model.EventRecord{Jti: jti, Event: ev, Original: `{"jti":"` + jti + `"}`, SortTime: time.Now()}
}

func insert(t *testing.T, d interfaces.EventDAO, jtis ...string) {
	t.Helper()
	for _, jti := range jtis {
		if err := d.Insert(context.Background(), record(jti)); err != nil {
			t.Fatalf("Insert %s: %v", jti, err)
		}
	}
}

func page(t *testing.T, d interfaces.EventDAO, sid string, limit int32) interfaces.PendingPage {
	t.Helper()
	p, err := d.GetPendingForStream(context.Background(), sid, limit)
	if err != nil {
		t.Fatalf("GetPendingForStream: %v", err)
	}
	return p
}

func pendingRef(t *testing.T, d interfaces.EventDAO, sid, jti string) (interfaces.PendingRef, bool) {
	t.Helper()
	for _, r := range page(t, d, sid, 1000).Refs {
		if r.Jti == jti {
			return r, true
		}
	}
	return interfaces.PendingRef{}, false
}

func delivered(t *testing.T, d interfaces.EventDAO, sid string) map[string]interfaces.DeliveredEvent {
	t.Helper()
	list, err := d.ListDeliveredForStream(context.Background(), sid)
	if err != nil {
		t.Fatalf("ListDeliveredForStream: %v", err)
	}
	out := make(map[string]interfaces.DeliveredEvent, len(list))
	for _, e := range list {
		out[e.Jti] = e
	}
	return out
}

func ack(t *testing.T, d interfaces.EventDAO, b interfaces.AckBatch) int64 {
	t.Helper()
	n, err := d.Ack(context.Background(), b)
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	return n
}

func pendingReadsAscending(t *testing.T, refs []interfaces.PendingRef) {
	t.Helper()
	for i := 1; i < len(refs); i++ {
		if refs[i-1].Jti >= refs[i].Jti {
			t.Fatalf("refs not in ascending jti order: %+v", refs)
		}
	}
}

func pendingPageAscendingWithAckJti(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	t0 := ms(time.Now().Add(-time.Hour))
	insert(t, d, "c", "a", "b")
	refs := []interfaces.PendingRef{
		{Jti: "c", AckJti: "x-c", EnqueuedAt: t0},
		{Jti: "a", AckJti: "x-a", EnqueuedAt: t0.Add(2 * time.Second)},
		{Jti: "b", AckJti: "x-b", EnqueuedAt: t0.Add(time.Second)},
	}
	if err := d.AddPendingMany(ctx, refs, sid); err != nil {
		t.Fatalf("AddPendingMany: %v", err)
	}
	p := page(t, d, sid, 2)
	if p.Total != 3 || len(p.Refs) != 2 {
		t.Fatalf("page = %+v, want 2 refs of total 3", p)
	}
	pendingReadsAscending(t, p.Refs)
	if p.Refs[0].Jti != "a" || p.Refs[0].AckJti != "x-a" || p.Refs[1].Jti != "b" || p.Refs[1].AckJti != "x-b" {
		t.Fatalf("refs = %+v, want a/x-a then b/x-b", p.Refs)
	}
	if !p.Refs[0].EnqueuedAt.Equal(t0.Add(2 * time.Second)) {
		t.Errorf("a EnqueuedAt = %v, want its createdAt %v", p.Refs[0].EnqueuedAt, t0.Add(2*time.Second))
	}
	if !p.OldestBeyond.Equal(t0) {
		t.Errorf("OldestBeyond = %v, want createdAt of c %v", p.OldestBeyond, t0)
	}
	if full := page(t, d, sid, 10); len(full.Refs) != 3 || !full.OldestBeyond.IsZero() {
		t.Errorf("full page = %+v, want 3 refs and zero OldestBeyond", full)
	}
}

func ackMatchesAckJtiNotJti(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	other := ids.NewObjectID()
	insert(t, d, "in-1", "in-2")
	if err := d.AddPendingMany(ctx, []interfaces.PendingRef{{Jti: "in-1", AckJti: "out-1"}, {Jti: "in-2", AckJti: "out-2"}}, sid); err != nil {
		t.Fatalf("AddPendingMany: %v", err)
	}
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "in-1", AckJti: "out-1"}, other); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	ackDate := ms(time.Now())
	if n := ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{"in-1", "in-2"}, AckDate: ackDate}); n != 0 {
		t.Fatalf("ack by inbound jti acked %d, want 0", n)
	}
	if n := ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{"out-1", "missing"}, AckDate: ackDate}); n != 1 {
		t.Fatalf("ack by ackJti acked %d, want 1", n)
	}
	got := delivered(t, d, sid)
	if e, ok := got["in-1"]; !ok || len(got) != 1 || !e.AckDate.Equal(ackDate) || e.AckJti != "out-1" {
		t.Fatalf("delivered = %+v, want only in-1 (ackJti out-1) at %v", got, ackDate)
	}
	if p := page(t, d, sid, 10); len(p.Refs) != 1 || p.Refs[0].Jti != "in-2" {
		t.Errorf("stream pending = %+v, want [in-2]", p.Refs)
	}
	if p := page(t, d, other, 10); len(p.Refs) != 1 {
		t.Errorf("other stream pending = %+v, must be untouched", p.Refs)
	}
}

func ackExactlyOnce(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	const n = 50
	jtis := make([]string, n)
	refs := make([]interfaces.PendingRef, n)
	for i := range jtis {
		jtis[i] = ids.NewObjectID()
		refs[i] = interfaces.PendingRef{Jti: jtis[i], AckJti: jtis[i]}
	}
	insert(t, d, jtis...)
	if err := d.AddPendingMany(ctx, refs, sid); err != nil {
		t.Fatalf("AddPendingMany: %v", err)
	}
	var wg sync.WaitGroup
	counts := make([]int64, 2)
	errs := make([]error, 2)
	for w := range counts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counts[w], errs[w] = d.Ack(ctx, interfaces.AckBatch{StreamID: sid, Jtis: jtis, AckDate: time.Now()})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Ack: %v", err)
		}
	}
	if counts[0]+counts[1] != n {
		t.Fatalf("acked %d + %d, want exactly %d in total", counts[0], counts[1], n)
	}
	if got := delivered(t, d, sid); len(got) != n {
		t.Errorf("delivered = %d, want %d", len(got), n)
	}
}

func ackStoresExpireAtAndCopies(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	insert(t, d, "in-1", "dup-copy")
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "in-1", AckJti: "out-1"}, sid); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	expire := ms(time.Now().Add(24 * time.Hour))
	copyRec := record("out-1")
	copyRec.OriginalJti = "in-1"
	// dup-copy already exists: its duplicate-key error must not stop the ack.
	n := ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{"out-1"}, AckDate: time.Now(), ExpireAt: &expire, Copies: []*model.EventRecord{record("dup-copy"), copyRec}})
	if n != 1 {
		t.Fatalf("acked %d, want 1", n)
	}
	e, ok := delivered(t, d, sid)["in-1"]
	if !ok || e.ExpireAt == nil || !e.ExpireAt.Equal(expire) {
		t.Fatalf("delivered in-1 = %+v, want expireAt %v", e, expire)
	}
	got, err := d.FindByJTI(ctx, "out-1")
	if err != nil || got == nil || got.OriginalJti != "in-1" {
		t.Fatalf("copy out-1 = (%+v, %v), want stored with OriginalJti in-1", got, err)
	}
}

func addPendingRequeuesDelivered(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	insert(t, d, "j")
	expire := ms(time.Now().Add(time.Hour))
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "j", AckJti: "j"}, sid); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{"j"}, AckDate: time.Now(), ExpireAt: &expire})
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "j", AckJti: "j2"}, sid); err != nil {
		t.Fatalf("re-queue AddPending: %v", err)
	}
	r, ok := pendingRef(t, d, sid, "j")
	if !ok || r.AckJti != "j2" {
		t.Fatalf("re-queued ref = %+v (found %v), want pending with ackJti j2", r, ok)
	}
	if got := delivered(t, d, sid); len(got) != 0 {
		t.Errorf("delivered after re-queue = %+v, want none", got)
	}
	if n, _ := d.CountRetainedForStream(ctx, sid); n != 0 {
		t.Errorf("retained after re-queue = %d, want 0", n)
	}
}

func ensurePendingKeepsAckJti(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	fresh := ids.NewObjectID()
	insert(t, d, "j")
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "j", AckJti: "orig"}, sid); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	queued, err := d.EnsurePending(ctx, "j", map[string]string{sid: "new", fresh: "fresh-ack"})
	if err != nil {
		t.Fatalf("EnsurePending: %v", err)
	}
	if len(queued) != 1 || queued[0] != fresh {
		t.Fatalf("queued = %v, want [%s]", queued, fresh)
	}
	if r, ok := pendingRef(t, d, sid, "j"); !ok || r.AckJti != "orig" {
		t.Errorf("existing ref = %+v, want ackJti orig kept", r)
	}
	if r, ok := pendingRef(t, d, fresh, "j"); !ok || r.AckJti != "fresh-ack" {
		t.Errorf("new ref = %+v, want ackJti fresh-ack", r)
	}
}

func resetPendingAckJtiPendingOnly(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	insert(t, d, "p1", "p2", "d1")
	refs := []interfaces.PendingRef{{Jti: "p1", AckJti: "o-p1"}, {Jti: "p2", AckJti: "p2"}, {Jti: "d1", AckJti: "o-d1"}}
	if err := d.AddPendingMany(ctx, refs, sid); err != nil {
		t.Fatalf("AddPendingMany: %v", err)
	}
	ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{"o-d1"}, AckDate: time.Now()})
	n, err := d.ResetPendingAckJti(ctx, sid)
	if err != nil || n != 1 {
		t.Fatalf("ResetPendingAckJti = (%d, %v), want (1, nil)", n, err)
	}
	for _, r := range page(t, d, sid, 10).Refs {
		if r.AckJti != r.Jti {
			t.Errorf("pending %s ackJti = %s, want reset to its jti", r.Jti, r.AckJti)
		}
	}
	if e := delivered(t, d, sid)["d1"]; e.AckJti != "o-d1" {
		t.Errorf("delivered d1 ackJti = %q, want o-d1 untouched", e.AckJti)
	}
}

func createdAtRules(t *testing.T, d interfaces.EventDAO) {
	ctx := context.Background()
	sid := ids.NewObjectID()
	t0 := ms(time.Now().Add(-time.Hour))
	t1 := t0.Add(10 * time.Minute)

	// Set on insert (InsertWithPending), unchanged by a duplicate SET.
	errs, err := d.InsertWithPending(ctx, []*model.EventRecord{record("ing")}, map[string][]interfaces.PendingRef{sid: {{Jti: "ing", AckJti: "ing", EnqueuedAt: t0}}})
	if err != nil || errs[0] != nil {
		t.Fatalf("InsertWithPending = (%v, %v)", errs, err)
	}
	errs, err = d.InsertWithPending(ctx, []*model.EventRecord{record("ing")}, map[string][]interfaces.PendingRef{sid: {{Jti: "ing", AckJti: "ing", EnqueuedAt: t1}}})
	if err != nil || errs[0] == nil {
		t.Fatalf("duplicate InsertWithPending = (%v, %v), want a per-record duplicate", errs, err)
	}
	if r, _ := pendingRef(t, d, sid, "ing"); !r.EnqueuedAt.Equal(t0) {
		t.Errorf("after duplicate SET createdAt = %v, want %v", r.EnqueuedAt, t0)
	}

	// Unchanged when AddPending / AddPendingMany meets an already-pending row
	// and by EnsurePending.
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "ing", AckJti: "ing", EnqueuedAt: t1}, sid); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if err := d.AddPendingMany(ctx, []interfaces.PendingRef{{Jti: "ing", AckJti: "ing", EnqueuedAt: t1}}, sid); err != nil {
		t.Fatalf("AddPendingMany: %v", err)
	}
	if _, err := d.EnsurePending(ctx, "ing", map[string]string{sid: "ing"}); err != nil {
		t.Fatalf("EnsurePending: %v", err)
	}
	if r, _ := pendingRef(t, d, sid, "ing"); !r.EnqueuedAt.Equal(t0) {
		t.Errorf("already-pending createdAt = %v, want %v kept", r.EnqueuedAt, t0)
	}

	// Re-set when a delivered row returns to pending.
	ack(t, d, interfaces.AckBatch{StreamID: sid, Jtis: []string{"ing"}, AckDate: time.Now()})
	if err := d.AddPendingMany(ctx, []interfaces.PendingRef{{Jti: "ing", AckJti: "ing", EnqueuedAt: t1}}, sid); err != nil {
		t.Fatalf("re-queue AddPendingMany: %v", err)
	}
	if r, _ := pendingRef(t, d, sid, "ing"); !r.EnqueuedAt.Equal(t1) {
		t.Errorf("re-queued createdAt = %v, want %v", r.EnqueuedAt, t1)
	}
}
