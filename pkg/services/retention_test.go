package services

import (
	"context"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func days(n int) *int { return &n }

func streamWithWindow(win *int) model.StreamStateRecord {
	return model.StreamStateRecord{Id: bson.NewObjectID(), RetentionWindowDays: win}
}

func seedBody(t *testing.T, dao *memory.EventDAOMemory, jti string) {
	t.Helper()
	ev := &goSet.SecurityEventToken{Events: map[string]interface{}{"t": "e"}}
	ev.ID = jti
	if err := dao.Insert(context.Background(), &model.EventRecord{Jti: jti, Event: *ev, SortTime: time.Now()}); err != nil {
		t.Fatalf("seed %s: %v", jti, err)
	}
}

func deliver(t *testing.T, dao *memory.EventDAOMemory, jti, streamID string, ack time.Time) {
	t.Helper()
	if err := dao.MarkDelivered(context.Background(), &interfaces.DeliverableEvent{Jti: jti, StreamId: streamID}, ack); err != nil {
		t.Fatalf("deliver %s/%s: %v", jti, streamID, err)
	}
}

// TestPurgeExpired_Dormant asserts keep-forever (nil window) never purges,
// however old the ack is — the engine ships DORMANT (ADR 0055 decision 3).
func TestPurgeExpired_Dormant(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewEventDAO()
	eng := NewRetentionEngine(dao)

	stream := streamWithWindow(nil) // keep-forever
	seedBody(t, dao, "j1")
	deliver(t, dao, "j1", stream.Id.Hex(), time.Now().Add(-365*24*time.Hour))

	purged, err := eng.PurgeExpired(ctx, time.Now(), []model.StreamStateRecord{stream}, DefaultEffectiveWindow)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 0 {
		t.Fatalf("dormant engine purged %d bodies", purged)
	}
	if n, _ := dao.CountRetainedForStream(ctx, stream.Id.Hex()); n != 1 {
		t.Fatalf("dormant engine dropped a delivered entry, count=%d", n)
	}
	if rec, _ := dao.FindByJTI(ctx, "j1"); rec == nil {
		t.Fatalf("dormant engine deleted a body")
	}
}

// TestPurgeExpired_FinitePurgesPostAck asserts a post-ack event older than the
// finite window is purged, while a fresh one and a pending one survive.
func TestPurgeExpired_FinitePurgesPostAck(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewEventDAO()
	eng := NewRetentionEngine(dao)

	stream := streamWithWindow(days(7))
	sid := stream.Id.Hex()
	now := time.Now()

	seedBody(t, dao, "old")   // acked 10 days ago -> expired
	seedBody(t, dao, "fresh") // acked 1 day ago -> retained
	seedBody(t, dao, "pend")  // pending -> never purged
	deliver(t, dao, "old", sid, now.Add(-10*24*time.Hour))
	deliver(t, dao, "fresh", sid, now.Add(-1*24*time.Hour))
	if err := dao.AddPending(ctx, "pend", sid); err != nil {
		t.Fatalf("add pending: %v", err)
	}

	purged, err := eng.PurgeExpired(ctx, now, []model.StreamStateRecord{stream}, DefaultEffectiveWindow)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 purged body, got %d", purged)
	}
	if rec, _ := dao.FindByJTI(ctx, "old"); rec != nil {
		t.Fatalf("expired body should be gone")
	}
	if rec, _ := dao.FindByJTI(ctx, "fresh"); rec == nil {
		t.Fatalf("fresh body wrongly purged")
	}
	if rec, _ := dao.FindByJTI(ctx, "pend"); rec == nil {
		t.Fatalf("pending body wrongly purged")
	}
	// Pending entry itself is untouched.
	jtis, total, _ := dao.GetPendingForStream(ctx, sid, 10)
	if total != 1 || len(jtis) != 1 || jtis[0] != "pend" {
		t.Fatalf("pending entry disturbed: %v total=%d", jtis, total)
	}
}

// TestPurgeExpired_RefcountAcrossStreams asserts a body fanned out to two streams
// with different windows survives to the MAX window (refcount 0 gate).
func TestPurgeExpired_RefcountAcrossStreams(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewEventDAO()
	eng := NewRetentionEngine(dao)

	short := streamWithWindow(days(1))
	long := streamWithWindow(days(10))
	streams := []model.StreamStateRecord{short, long}

	t0 := time.Now().Add(-100 * 24 * time.Hour) // fixed ack anchor in the past
	seedBody(t, dao, "shared")
	deliver(t, dao, "shared", short.Id.Hex(), t0)
	deliver(t, dao, "shared", long.Id.Hex(), t0)

	// Pass 1 at t0+2d: only the short window has elapsed. Body must survive.
	purged, err := eng.PurgeExpired(ctx, t0.Add(2*24*time.Hour), streams, DefaultEffectiveWindow)
	if err != nil {
		t.Fatalf("pass1: %v", err)
	}
	if purged != 0 {
		t.Fatalf("pass1 purged %d; body must survive to the max window", purged)
	}
	if rec, _ := dao.FindByJTI(ctx, "shared"); rec == nil {
		t.Fatalf("body deleted while long-window stream still references it")
	}
	if n, _ := dao.CountRetainedForStream(ctx, short.Id.Hex()); n != 0 {
		t.Fatalf("short-window delivered entry should be dropped, count=%d", n)
	}
	if n, _ := dao.CountRetainedForStream(ctx, long.Id.Hex()); n != 1 {
		t.Fatalf("long-window delivered entry should remain, count=%d", n)
	}

	// Pass 2 at t0+11d: the long window has now elapsed too. Body deleted.
	purged, err = eng.PurgeExpired(ctx, t0.Add(11*24*time.Hour), streams, DefaultEffectiveWindow)
	if err != nil {
		t.Fatalf("pass2: %v", err)
	}
	if purged != 1 {
		t.Fatalf("pass2 should delete the now-unreferenced body, purged=%d", purged)
	}
	if rec, _ := dao.FindByJTI(ctx, "shared"); rec != nil {
		t.Fatalf("body should be gone once both windows expired")
	}
}

type captureSink struct{ samples []OccupancySample }

func (c *captureSink) ObserveOccupancy(s OccupancySample) { c.samples = append(c.samples, s) }

// TestSampleOccupancy_EmitsPerStreamRetained asserts the sampler emits the pinned
// tuple with post-ack-retained counts and a stable idempotency key.
func TestSampleOccupancy_EmitsPerStreamRetained(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewEventDAO()
	eng := NewRetentionEngine(dao)

	s1 := streamWithWindow(nil)
	s2 := streamWithWindow(nil)
	now := time.Now()
	seedBody(t, dao, "a")
	seedBody(t, dao, "b")
	seedBody(t, dao, "c")
	deliver(t, dao, "a", s1.Id.Hex(), now)
	deliver(t, dao, "b", s1.Id.Hex(), now)
	deliver(t, dao, "c", s2.Id.Hex(), now)
	// A pending event must NOT count toward retained.
	if err := dao.AddPending(ctx, "a", s2.Id.Hex()); err != nil {
		t.Fatalf("add pending: %v", err)
	}

	sink := &captureSink{}
	sampleTime := time.Date(2026, 7, 4, 15, 4, 5, 0, time.UTC)
	if err := eng.SampleOccupancy(ctx, sampleTime, "urn:server:test", []model.StreamStateRecord{s1, s2}, sink); err != nil {
		t.Fatalf("sample: %v", err)
	}
	if len(sink.samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(sink.samples))
	}
	byStream := map[string]OccupancySample{}
	for _, s := range sink.samples {
		byStream[s.StreamURN] = s
		if s.ServerURN != "urn:server:test" {
			t.Fatalf("wrong server urn: %q", s.ServerURN)
		}
		if s.SampleDate != "2026-07-04" {
			t.Fatalf("wrong sample date: %q", s.SampleDate)
		}
	}
	if got := byStream[s1.Id.Hex()].RetainedCount; got != 2 {
		t.Fatalf("s1 retained = %d, want 2", got)
	}
	if got := byStream[s2.Id.Hex()].RetainedCount; got != 1 {
		t.Fatalf("s2 retained = %d, want 1 (pending excluded)", got)
	}
}

// TestSampleOccupancy_NilSinkNoop asserts a nil sink is inert (no sink registered).
func TestSampleOccupancy_NilSinkNoop(t *testing.T) {
	dao := memory.NewEventDAO()
	eng := NewRetentionEngine(dao)
	if err := eng.SampleOccupancy(context.Background(), time.Now(), "urn:s", []model.StreamStateRecord{streamWithWindow(nil)}, nil); err != nil {
		t.Fatalf("nil sink should be a no-op, got %v", err)
	}
}
