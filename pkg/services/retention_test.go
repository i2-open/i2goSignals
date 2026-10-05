package services

import (
	"context"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func days(n int) *int { return &n }

func streamWithWindow(win *int) model.StreamStateRecord {
	return model.StreamStateRecord{Id: model.NewRecordId(), RetentionWindowDays: win}
}

func seedBody(t *testing.T, dao *memory.EventDAOMemory, jti string, sortTime time.Time) {
	t.Helper()
	ev := &goSet.SecurityEventToken{Events: map[string]interface{}{"t": "e"}}
	ev.ID = jti
	if err := dao.Insert(context.Background(), &model.EventRecord{Jti: jti, Event: *ev, SortTime: sortTime}); err != nil {
		t.Fatalf("seed %s: %v", jti, err)
	}
}

// deliver queues jti for streamID and acknowledges it at ack, stamping
// expireAt = ack + win days as the router does at acknowledgement (#360). A nil
// win writes no expireAt (keep forever).
func deliver(t *testing.T, dao *memory.EventDAOMemory, jti, streamID string, ack time.Time, win *int) {
	t.Helper()
	ctx := context.Background()
	if err := dao.AddPending(ctx, refOf(jti), streamID); err != nil {
		t.Fatalf("queue %s/%s: %v", jti, streamID, err)
	}
	batch := interfaces.AckBatch{StreamID: streamID, Jtis: []string{jti}, AckDate: ack}
	if win != nil {
		expireAt := ack.Add(time.Duration(*win) * 24 * time.Hour)
		batch.ExpireAt = &expireAt
	}
	if _, err := dao.Ack(ctx, batch); err != nil {
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
	old := time.Now().Add(-365 * 24 * time.Hour)
	seedBody(t, dao, "j1", old)
	deliver(t, dao, "j1", stream.Id.Hex(), old, nil)

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

// TestPurgeExpired_FinitePurgesPostAck asserts a reference whose expireAt has
// passed is dropped and its body (older than the window) purged, while a fresh
// one and a pending one survive.
func TestPurgeExpired_FinitePurgesPostAck(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewEventDAO()
	eng := NewRetentionEngine(dao)

	win := days(7)
	stream := streamWithWindow(win)
	sid := stream.Id.Hex()
	now := time.Now()

	seedBody(t, dao, "old", now.Add(-11*24*time.Hour))  // acked 10 days ago -> expired
	seedBody(t, dao, "fresh", now.Add(-2*24*time.Hour)) // acked 1 day ago -> retained
	seedBody(t, dao, "pend", now.Add(-11*24*time.Hour)) // pending -> never purged
	deliver(t, dao, "old", sid, now.Add(-10*24*time.Hour), win)
	deliver(t, dao, "fresh", sid, now.Add(-1*24*time.Hour), win)
	if err := dao.AddPending(ctx, refOf("pend"), sid); err != nil {
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
	if n, _ := dao.CountRetainedForStream(ctx, sid); n != 1 {
		t.Fatalf("expected only the fresh delivered entry to remain, count=%d", n)
	}
	// Pending entry itself is untouched.
	jtis, total, _ := pageJtis(dao.GetPendingForStream(ctx, sid, 10))
	if total != 1 || len(jtis) != 1 || jtis[0] != "pend" {
		t.Fatalf("pending entry disturbed: %v total=%d", jtis, total)
	}
}

// TestPurgeExpired_RefcountAcrossStreams asserts a body fanned out to two streams
// with different windows survives until the last reference expires.
func TestPurgeExpired_RefcountAcrossStreams(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewEventDAO()
	eng := NewRetentionEngine(dao)

	short := streamWithWindow(days(1))
	long := streamWithWindow(days(10))
	streams := []model.StreamStateRecord{short, long}

	t0 := time.Now().Add(-100 * 24 * time.Hour) // fixed ack anchor in the past
	seedBody(t, dao, "shared", t0.Add(-time.Hour))
	deliver(t, dao, "shared", short.Id.Hex(), t0, short.RetentionWindowDays)
	deliver(t, dao, "shared", long.Id.Hex(), t0, long.RetentionWindowDays)

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

// TestPurgeExpired_WindowFixedAtAck asserts a reference acknowledged while the
// stream was keep-forever carries no expireAt and is never expired by a later
// finite window (#360: the window is fixed at acknowledgement).
func TestPurgeExpired_WindowFixedAtAck(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewEventDAO()
	eng := NewRetentionEngine(dao)

	stream := streamWithWindow(nil)
	old := time.Now().Add(-30 * 24 * time.Hour)
	seedBody(t, dao, "kept", old)
	deliver(t, dao, "kept", stream.Id.Hex(), old, nil)

	stream.RetentionWindowDays = days(1) // policy turns finite after the ack
	purged, err := eng.PurgeExpired(ctx, time.Now(), []model.StreamStateRecord{stream}, DefaultEffectiveWindow)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 0 {
		t.Fatalf("a keep-forever ack was purged by a later policy, purged=%d", purged)
	}
	if n, _ := dao.CountRetainedForStream(ctx, stream.Id.Hex()); n != 1 {
		t.Fatalf("keep-forever reference dropped, count=%d", n)
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
	seedBody(t, dao, "a", now)
	seedBody(t, dao, "b", now)
	seedBody(t, dao, "c", now)
	deliver(t, dao, "a", s1.Id.Hex(), now, nil)
	deliver(t, dao, "b", s1.Id.Hex(), now, nil)
	deliver(t, dao, "c", s2.Id.Hex(), now, nil)
	// A pending event must NOT count toward retained.
	if err := dao.AddPending(ctx, refOf("a"), s2.Id.Hex()); err != nil {
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

// TestSummarizeRetention_ClassifiesLikePurge asserts the summary uses exactly
// the purge engine's rule: nil, zero and negative windows are all keep-forever,
// only a positive window is windowed. The startup log must never claim a stream
// will expire events that PurgeExpired would skip.
func TestSummarizeRetention_ClassifiesLikePurge(t *testing.T) {
	streams := []model.StreamStateRecord{
		streamWithWindow(nil),      // unset -> keep-forever
		streamWithWindow(days(0)),  // non-positive -> keep-forever
		streamWithWindow(days(-1)), // non-positive -> keep-forever
		streamWithWindow(days(30)), // finite window
	}

	got := SummarizeRetention(streams, DefaultEffectiveWindow)

	want := RetentionPosture{Streams: 4, KeepForever: 3, Windowed: 1}
	if got != want {
		t.Fatalf("posture = %+v, want %+v", got, want)
	}
}

// TestSummarizeRetention_EmptyAndNil covers the fresh-server case: no streams
// yet, and a nil resolver falling back to the community default. Neither may
// panic — this runs on the startup path.
func TestSummarizeRetention_EmptyAndNil(t *testing.T) {
	if got := SummarizeRetention(nil, nil); (got != RetentionPosture{}) {
		t.Fatalf("nil streams: posture = %+v, want zero value", got)
	}

	// A nil resolver must default to DefaultEffectiveWindow, not keep-forever
	// for everything, so the summary tracks whatever the purge pass would do.
	got := SummarizeRetention([]model.StreamStateRecord{streamWithWindow(days(7))}, nil)
	want := RetentionPosture{Streams: 1, KeepForever: 0, Windowed: 1}
	if got != want {
		t.Fatalf("nil window func: posture = %+v, want %+v", got, want)
	}
}

// TestSummarizeRetention_HonorsCustomResolver proves the summary is resolver-
// driven, not field-driven: an enterprise-style resolver that supplies a default
// window turns a stream with no per-stream override into a windowed stream.
func TestSummarizeRetention_HonorsCustomResolver(t *testing.T) {
	withBundleDefault := func(stream *model.StreamStateRecord) *int {
		if stream.RetentionWindowDays != nil {
			return stream.RetentionWindowDays
		}
		return days(90)
	}

	got := SummarizeRetention([]model.StreamStateRecord{
		streamWithWindow(nil),
		streamWithWindow(days(30)),
	}, withBundleDefault)

	want := RetentionPosture{Streams: 2, KeepForever: 0, Windowed: 2}
	if got != want {
		t.Fatalf("posture = %+v, want %+v", got, want)
	}
}
