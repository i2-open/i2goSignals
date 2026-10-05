package eventRouter

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/wal"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func ringFed(d *RouterDeps) { d.WALRingFed = true }

func overlayEntry(stream string, jtis ...string) *walEntry {
	e := &walEntry{Sid: "in", Targets: []walTarget{{Mode: "POLL", Key: stream, DocID: stream, Sid: stream, Jtis: jtis}}}
	for _, jti := range jtis {
		e.Records = append(e.Records, &model.EventRecord{Jti: jti, Sid: "in", Original: "body-" + jti})
	}
	return e
}

func storeWithPending(t *testing.T, s *walSetup, stream string, jtis ...string) {
	t.Helper()
	recs := make([]*model.EventRecord, 0, len(jtis))
	for _, jti := range jtis {
		recs = append(recs, &model.EventRecord{Jti: jti, Sid: "in", Original: "stored-" + jti})
	}
	_, err := s.p.EventDAO.InsertWithPending(context.Background(), recs, pendingRefsOf(map[string][]string{stream: jtis}))
	require.NoError(t, err)
}

// The read-through merges undrained and stored pending SETs in jti order,
// without duplicates, cut to the limit, and hides SETs whose ack is held.
func TestWalReadThrough_PendingMergeAckAndClear(t *testing.T) {
	m := useWalMetrics(t)
	p := openMemPersistence(t)
	s := &walSetup{p: p}
	rt := newWalReadThrough(p.EventDAO, m)
	ctx := context.Background()

	storeWithPending(t, s, "s1", "b", "d")
	e := overlayEntry("s1", "a", "c", "d")
	rt.overlay.add(e)

	jtis, total, err := pageJtis(rt.GetPendingForStream(ctx, "s1", 0))
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c", "d"}, jtis)
	assert.EqualValues(t, 4, total)
	jtis, _, err = pageJtis(rt.GetPendingForStream(ctx, "s1", 2))
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, jtis)

	acked, err := rt.Ack(ctx, interfaces.AckBatch{StreamID: "s1", Jtis: []string{"a", "b"}, AckDate: time.Now()})
	require.NoError(t, err)
	assert.EqualValues(t, 2, acked, "held and stored acks are both counted")
	jtis, _, err = pageJtis(rt.GetPendingForStream(ctx, "s1", 2))
	require.NoError(t, err)
	assert.Equal(t, []string{"c", "d"}, jtis, "a held ack hides the SET and a full page stays full")

	n, err := rt.ClearPendingForStream(ctx, "s1")
	require.NoError(t, err)
	assert.EqualValues(t, 3, n, "the stored d plus the undrained c and d")
	jtis, _, err = pageJtis(rt.GetPendingForStream(ctx, "s1", 0))
	require.NoError(t, err)
	assert.Empty(t, jtis)

	// The drain stores the entry, then applies the held ack and clears.
	storeWithPending(t, s, "s1", "a", "c", "d")
	require.NoError(t, rt.applyHeld(ctx, []*walEntry{e}))
	rt.overlay.remove(e)
	base, _, err := pageJtis(p.EventDAO.GetPendingForStream(ctx, "s1", 0))
	require.NoError(t, err)
	assert.Empty(t, base, "held acks and clears reached the store")
	delivered, err := p.EventDAO.ListDeliveredForStream(ctx, "s1")
	require.NoError(t, err)
	var got []string
	for _, d := range delivered {
		got = append(got, d.Jti)
	}
	assert.ElementsMatch(t, []string{"a", "b"}, got)
	assert.Empty(t, rt.overlay.pending)
	assert.Empty(t, rt.overlay.records)
}

// Undrained bodies come from the overlay, the rest from the store, in the
// requested order, and each overlay hit is counted.
func TestWalReadThrough_FindByJTIs(t *testing.T) {
	m := useWalMetrics(t)
	p := openMemPersistence(t)
	s := &walSetup{p: p}
	rt := newWalReadThrough(p.EventDAO, m)
	ctx := context.Background()
	storeWithPending(t, s, "s1", "b")
	rt.overlay.add(overlayEntry("s1", "a", "c"))

	recs, err := rt.FindByJTIs(ctx, []string{"c", "b", "missing", "a"})
	require.NoError(t, err)
	require.Len(t, recs, 3)
	assert.Equal(t, []string{"c", "b", "a"}, []string{recs[0].Jti, recs[1].Jti, recs[2].Jti})
	assert.Equal(t, "body-c", recs[0].Original)
	assert.Equal(t, "stored-b", recs[1].Original)
	assert.InDelta(t, 2, testutil.ToFloat64(m.ringFedServed), 0.0001)

	rec, err := rt.FindByJTI(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, "body-a", rec.Original)
	rec.Original = "mutated"
	again, _ := rt.FindByJTI(ctx, "a")
	assert.Equal(t, "body-a", again.Original, "callers get a copy")
	assert.InDelta(t, 4, testutil.ToFloat64(m.ringFedServed), 0.0001)
}

// Without I2SIG_STORE_WAL_RING_FED the read-through is not wired.
func TestLocalWal_RingFedOffByDefault(t *testing.T) {
	p := openMemPersistence(t)
	s := newWalRouter(t, p, t.TempDir(), nil)
	assert.Nil(t, s.router.walRT)
}

// A router rebuilt on the same EventService replaces the read-through
// rather than stacking a second one on the first.
func TestLocalWal_RingFedRebuildDoesNotStack(t *testing.T) {
	p := openMemPersistence(t)
	es := services.NewEventService(p.EventDAO)
	build := func() *router {
		log, err := wal.Open(t.TempDir())
		require.NoError(t, err)
		r := NewRouter(RouterDeps{StreamService: p.StreamService, KeyService: p.KeyService, EventService: es, Coordinator: p.Coordinator, WAL: log, WALRingFed: true}, "node-wal-test").(*router)
		return r
	}
	r1 := build()
	require.NotNil(t, r1.walRT)
	r1.Shutdown()
	r2 := build()
	t.Cleanup(r2.Shutdown)
	require.NotNil(t, r2.walRT)
	_, stacked := r2.walRT.EventDAO.(*walReadThrough)
	assert.False(t, stacked)
}

// Poll: a SET is served while the drain is held, its ack is held until the
// drain stores it, and it is never offered again.
func TestLocalWal_RingFedPollServesBeforeDrain(t *testing.T) {
	m := useWalMetrics(t)
	p := openMemPersistence(t)
	gate := make(chan struct{})
	s := newWalRouterWith(t, p, t.TempDir(), &gatedEventDAO{EventDAO: p.EventDAO, gate: gate}, ringFed)
	require.NotNil(t, s.router.walRT)

	require.NoError(t, s.router.HandleEvent(newRiscToken("rf-poll-1", dupTestIssuer, s.audience), "x", s.streamID))
	assert.False(t, s.stored("rf-poll-1"))

	sets, _, status := s.router.PollStreamHandler(s.streamID, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	require.Equal(t, 200, status)
	assert.Equal(t, []string{"rf-poll-1"}, keysOf(sets), "served from the WAL before the drain")
	assert.False(t, s.stored("rf-poll-1"), "still not in the store")
	assert.GreaterOrEqual(t, testutil.ToFloat64(m.ringFedServed), 1.0)

	sets, _, status = s.router.PollStreamHandler(s.streamID, model.PollParameters{MaxEvents: 10, ReturnImmediately: true, Acks: []string{"rf-poll-1"}})
	require.Equal(t, 200, status)
	assert.Empty(t, sets)

	close(gate)
	s.waitDrained(t)
	assert.True(t, s.stored("rf-poll-1"))
	assert.Empty(t, s.pending(t), "the held ack reached the store with the SET")
	delivered, err := p.EventDAO.ListDeliveredForStream(context.Background(), s.streamID)
	require.NoError(t, err)
	require.Len(t, delivered, 1)
	assert.Equal(t, "rf-poll-1", delivered[0].Jti)

	sets, _, _ = s.router.PollStreamHandler(s.streamID, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	assert.Empty(t, sets, "an acked SET is not redelivered after the drain")
}

// Push: the runner pushes a SET while the drain is held, exactly once.
func TestLocalWal_RingFedPushServesBeforeDrain(t *testing.T) {
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "0")
	p := openMemPersistence(t)
	gate := make(chan struct{})
	rx := newHoldingReceiver()
	rx.release()
	s := newWalRouterWith(t, p, t.TempDir(), &gatedEventDAO{EventDAO: p.EventDAO, gate: gate}, func(d *RouterDeps) {
		d.PushDelivery = rx
		d.WALRingFed = true
	})
	h := &filterPushHarness{router: s.router, streamService: p.StreamService, keyService: p.KeyService, eventService: p.EventService}
	push := h.createPushStream(t, "NONE")
	pushID := push.StreamConfiguration.Id
	s.router.UpdateStreamState(push.DeepCopy())
	waitLeaseOwner(t, p.Coordinator, cluster.PushTransmitterResource(pushID), "node-wal-test")

	require.NoError(t, s.router.HandleEvent(newRiscToken("rf-push-1", dupTestIssuer, s.audience), "x", s.streamID))
	rx.waitEntered(t)
	assert.False(t, s.stored("rf-push-1"), "pushed before the drain stored it")

	close(gate)
	s.waitDrained(t)
	assert.True(t, s.stored("rf-push-1"))
	require.Eventually(t, func() bool {
		jtis, _, _ := pageJtis(p.EventDAO.GetPendingForStream(context.Background(), pushID, 0))
		return len(jtis) == 0
	}, 5*time.Second, 5*time.Millisecond, "the held push ack reached the store")
	pushes := rx.settle(t)
	assert.Len(t, deliveriesByJti(pushes)["rf-push-1"], 1, "pushed exactly once")
}

// After a crash, the next run serves the replayed entries before the replay
// stores them, and a restarted runner gets every unacked SET again.
func TestLocalWal_RingFedServesReplayedEntries(t *testing.T) {
	p := openMemPersistence(t)
	dir := t.TempDir()
	s1 := newWalRouterWith(t, p, dir, &gatedEventDAO{EventDAO: p.EventDAO, gate: make(chan struct{})}, ringFed)
	jtis := []string{"rf-crash-1", "rf-crash-2"}
	for _, jti := range jtis {
		require.NoError(t, s1.router.HandleEvent(newRiscToken(jti, dupTestIssuer, s1.audience), jti, s1.streamID))
	}
	crashLocalWal(s1.router)

	gate := make(chan struct{})
	s2 := newWalRouterWith(t, p, dir, &gatedEventDAO{EventDAO: p.EventDAO, gate: gate}, ringFed)
	// The replayed entries target s1's stream (s2's setup made another one).
	s2.router.UpdateStreamState(s1.stream)
	sets, _, status := s2.router.PollStreamHandler(s1.streamID, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	require.Equal(t, 200, status)
	assert.ElementsMatch(t, jtis, keysOf(sets), "replayed SETs are served before the replay stores them")
	for _, jti := range jtis {
		assert.False(t, s2.stored(jti))
	}
	close(gate)
	s2.waitDrained(t)
	for _, jti := range jtis {
		assert.True(t, s2.stored(jti))
	}
}

// ringFedLatency is the time from the WAL ack to the first push while each
// store write takes storeDelay.
func ringFedLatency(t *testing.T, ringFedOn bool, storeDelay time.Duration) time.Duration {
	t.Helper()
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "0")
	p := openMemPersistence(t)
	gate := make(chan struct{})
	rx := newHoldingReceiver()
	rx.release()
	s := newWalRouterWith(t, p, t.TempDir(), &gatedEventDAO{EventDAO: p.EventDAO, gate: gate}, func(d *RouterDeps) {
		d.PushDelivery = rx
		d.WALRingFed = ringFedOn
	})
	h := &filterPushHarness{router: s.router, streamService: p.StreamService, keyService: p.KeyService, eventService: p.EventService}
	push := h.createPushStream(t, "NONE")
	s.router.UpdateStreamState(push.DeepCopy())
	waitLeaseOwner(t, p.Coordinator, cluster.PushTransmitterResource(push.StreamConfiguration.Id), "node-wal-test")

	go func() { time.Sleep(storeDelay); close(gate) }()
	start := time.Now()
	require.NoError(t, s.router.HandleEvent(newRiscToken("rf-lat", dupTestIssuer, s.audience), "x", s.streamID))
	rx.waitEntered(t)
	return time.Since(start)
}

// Delivery latency with a slow drain (#342 AC: before/after). Without
// ring-feeding the push waits for the store write; with it, it does not.
func TestLocalWal_RingFedDeliveryLatency(t *testing.T) {
	const storeDelay = 300 * time.Millisecond
	var before, after time.Duration
	t.Run("drain-fed", func(t *testing.T) { before = ringFedLatency(t, false, storeDelay) })
	t.Run("ring-fed", func(t *testing.T) { after = ringFedLatency(t, true, storeDelay) })
	t.Logf("WAL-ack to push latency with a %v store write: drain-fed %v, ring-fed %v", storeDelay, before, after)
	assert.GreaterOrEqual(t, before, storeDelay, "drain-fed delivery waits for the store")
	assert.Less(t, after, storeDelay, "ring-fed delivery does not wait for the store")
}
