package eventRouter

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/wal"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

// useWalMetrics swaps in a private WAL metric set for the test.
func useWalMetrics(t *testing.T) *walMetrics {
	t.Helper()
	m := newWalMetrics()
	prev := walMetricsDefault
	walMetricsDefault = m
	t.Cleanup(func() { walMetricsDefault = prev })
	return m
}

// captureWalLogs routes the logger to a buffer for the test.
func captureWalLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	logger.Init(logger.Options{Level: "info", Format: "json", Writer: buf})
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// records returns the captured JSON log lines whose msg contains substr.
func (s *syncBuffer) records(substr string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(s.b.Bytes(), []byte("\n")) {
		var rec map[string]any
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		if msg, _ := rec["msg"].(string); bytes.Contains([]byte(msg), []byte(substr)) {
			out = append(out, rec)
		}
	}
	return out
}

// walClock drives the graceful-stop drain deadline.
type walClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *walClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *walClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// useWalClock makes routers built after it use clock and sleep.
func useWalClock(t *testing.T, clock *walClock, sleep func(context.Context, time.Duration) bool) {
	t.Helper()
	prevNow, prevSleep := walNow, walSleep
	walNow = clock.now
	if sleep != nil {
		walSleep = sleep
	}
	t.Cleanup(func() { walNow, walSleep = prevNow, prevSleep })
}

// releaseWatcher wraps a coordinator and runs onRelease before each release.
type releaseWatcher struct {
	cluster.ClusterCoordinator
	onRelease func(resource string)
}

func (w *releaseWatcher) ReleaseLeaseIfOwned(resource, nodeId string) error {
	if w.onRelease != nil {
		w.onRelease(resource)
	}
	return w.ClusterCoordinator.ReleaseLeaseIfOwned(resource, nodeId)
}

// walPushSetup is a local-WAL router that also runs one push stream, whose
// runner holds its lease until the router stops.
type walPushSetup struct {
	*walSetup
	coord    cluster.ClusterCoordinator
	resource string
}

func newWalPushSetup(t *testing.T, dao *gatedEventDAO, onRelease func(resource string)) *walPushSetup {
	t.Helper()
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "0")
	p := openMemPersistence(t)
	if dao != nil {
		dao.EventDAO = p.EventDAO
	}
	rx := newHoldingReceiver()
	t.Cleanup(rx.release)
	coord := &releaseWatcher{ClusterCoordinator: p.Coordinator, onRelease: onRelease}
	s := newWalRouterWith(t, p, t.TempDir(), dao, func(d *RouterDeps) {
		d.PushDelivery = rx
		d.Coordinator = coord
	})
	h := &filterPushHarness{router: s.router, streamService: p.StreamService, keyService: p.KeyService, eventService: p.EventService}
	push := h.createPushStream(t, "NONE")
	resource := cluster.PushTransmitterResource(push.StreamConfiguration.Id)
	s.router.UpdateStreamState(push.DeepCopy())
	waitLeaseOwner(t, p.Coordinator, resource, "node-wal-test")
	return &walPushSetup{walSetup: s, coord: p.Coordinator, resource: resource}
}

func (s *walPushSetup) leaseOwner(t *testing.T) string {
	t.Helper()
	owner, _, _, err := s.coord.GetLeaseOwner(s.resource)
	require.NoError(t, err)
	return owner
}

// US 22: graceful stop drains the WAL to the store while every stream lease
// is still held, and releases the leases only after the drain.
func TestLocalWal_ShutdownDrainsBeforeLeaseRelease(t *testing.T) {
	m := useWalMetrics(t)
	dao := &gatedEventDAO{}
	var s *walPushSetup
	var storedAtRelease, released atomic.Bool
	var sleeps atomic.Int32
	clock := &walClock{t: time.Now()}
	useWalClock(t, clock, func(ctx context.Context, d time.Duration) bool {
		// Mid-drain: the lease is still ours and nothing has been released.
		assert.Equal(t, "node-wal-test", s.leaseOwner(t), "the lease is held while the WAL is not empty")
		assert.False(t, released.Load())
		clock.advance(d)
		if sleeps.Add(1) == 3 {
			dao.failures.Store(0) // the store comes back
		}
		return ctx.Err() == nil
	})
	s = newWalPushSetup(t, dao, func(resource string) {
		// s is nil for the startup migration lease, released inside NewRouter.
		if s != nil && resource == s.resource {
			released.Store(true)
			storedAtRelease.Store(s.stored("wal-stop"))
		}
	})
	// The store is down: the background drain keeps failing.
	dao.failures.Store(1 << 20)
	require.NoError(t, s.router.HandleEvent(newRiscToken("wal-stop", dupTestIssuer, s.audience), "x", s.streamID))
	require.Equal(t, 1, s.log.Depth())

	s.router.Shutdown()

	assert.GreaterOrEqual(t, int(sleeps.Load()), 3, "the shutdown drain retried the store")
	assert.True(t, s.stored("wal-stop"), "the WAL drained to the store at shutdown")
	// The runner exits, and releases its lease, once Shutdown has cancelled it.
	require.Eventually(t, func() bool { return released.Load() && s.leaseOwner(t) == "" }, 10*time.Second, 5*time.Millisecond,
		"the runner releases its lease after the drain")
	assert.True(t, storedAtRelease.Load(), "the SET was in the store before the lease was released")
	assert.InDelta(t, 0, testutil.ToFloat64(m.depth), 0.0001)

	// Ingest is closed once shutdown began.
	err := s.router.HandleEvent(newRiscToken("wal-late", dupTestIssuer, s.audience), "x", s.streamID)
	assert.ErrorIs(t, err, ErrStoreUnavailable)
}

// US 22: when the store stays down past the drain timeout, shutdown gives up,
// logs the residual depth at ERROR, and leaves the WAL intact on disk.
func TestLocalWal_ShutdownDrainTimeoutLeavesResidue(t *testing.T) {
	t.Setenv(wal.EnvDrainTimeout, "30s")
	logs := captureWalLogs(t)
	p := openMemPersistence(t)
	dao := &gatedEventDAO{EventDAO: p.EventDAO}
	dao.failures.Store(1 << 20)
	dir := t.TempDir()
	clock := &walClock{t: time.Now()}
	useWalClock(t, clock, func(ctx context.Context, d time.Duration) bool {
		clock.advance(10 * time.Second)
		return ctx.Err() == nil
	})
	s := newWalRouter(t, p, dir, dao)
	require.NoError(t, s.router.HandleEvent(newRiscToken("wal-stuck", dupTestIssuer, s.audience), "x", s.streamID))
	started := time.Now()
	s.router.Shutdown()
	assert.Less(t, time.Since(started), 10*time.Second, "the fake clock, not wall time, ran out the deadline")
	assert.False(t, s.stored("wal-stuck"))

	timedOut := logs.records("drain timed out")
	require.Len(t, timedOut, 1)
	assert.Equal(t, "ERROR", timedOut[0]["level"])
	assert.EqualValues(t, 1, timedOut[0]["depth"])

	reopened, err := wal.Open(dir)
	require.NoError(t, err)
	defer func() { _ = reopened.Close() }()
	assert.Equal(t, 1, reopened.Depth(), "the residue stays on disk for the next start")
}

// crashLocalWal stops the drain and closes the log without draining, as a
// crash would leave it.
func crashLocalWal(r *router) {
	lw := r.wal
	lw.shutdown.Do(func() {
		lw.cancel()
		close(lw.stop)
		<-lw.done
		_ = lw.log.Close()
	})
}

// US 23: entries a crashed run left in the WAL are replayed to the store,
// exactly once, before the next run accepts ingest.
func TestLocalWal_CrashReplayGatesIngest(t *testing.T) {
	m := useWalMetrics(t)
	p := openMemPersistence(t)
	dir := t.TempDir()
	s1 := newWalRouter(t, p, dir, &gatedEventDAO{EventDAO: p.EventDAO, gate: make(chan struct{})})
	jtis := []string{"wal-crash-1", "wal-crash-2", "wal-crash-3"}
	for _, jti := range jtis {
		require.NoError(t, s1.router.HandleEvent(newRiscToken(jti, dupTestIssuer, s1.audience), jti, s1.streamID))
	}
	require.Equal(t, 3, s1.log.Depth())
	crashLocalWal(s1.router)

	gate := make(chan struct{})
	dao2 := &gatedEventDAO{EventDAO: p.EventDAO, gate: gate}
	s2 := newWalRouter(t, p, dir, dao2)
	assert.True(t, s2.router.wal.replaying.Load())
	assert.InDelta(t, 3, testutil.ToFloat64(m.depth), 0.0001, "depth is published at start")

	err := s2.router.HandleEvent(newRiscToken("wal-new", dupTestIssuer, s2.audience), "n", s2.streamID)
	require.ErrorIs(t, err, ErrStoreUnavailable, "ingest waits for the replay")
	assert.Equal(t, 3, s2.log.Depth(), "a refused SET is not appended")

	close(gate)
	s2.waitDrained(t)
	require.Eventually(t, func() bool { return !s2.router.wal.replaying.Load() }, 5*time.Second, 5*time.Millisecond)
	for _, jti := range jtis {
		assert.True(t, s2.stored(jti), jti)
	}
	assert.ElementsMatch(t, jtis, s1.pending(t), "each replayed SET is planned exactly once")
	assert.InDelta(t, 3, testutil.ToFloat64(m.replayed), 0.0001)
	assert.InDelta(t, 3, testutil.ToFloat64(m.drained), 0.0001)

	require.NoError(t, s2.router.HandleEvent(newRiscToken("wal-new", dupTestIssuer, s2.audience), "n", s2.streamID),
		"ingest resumes once the replay is done")
	s2.waitDrained(t)
	assert.True(t, s2.stored("wal-new"))
	assert.InDelta(t, 3, testutil.ToFloat64(m.replayed), 0.0001, "a fresh SET is not counted as replayed")
	assert.InDelta(t, 4, testutil.ToFloat64(m.drained), 0.0001)
}

// US 24: depth, lag, drained and drain-duration metrics track the WAL.
func TestLocalWal_Metrics(t *testing.T) {
	m := useWalMetrics(t)
	reg := prometheus.NewRegistry()
	for _, c := range m.collectors() {
		require.NoError(t, reg.Register(c))
	}
	p := openMemPersistence(t)
	gate := make(chan struct{})
	s := newWalRouter(t, p, t.TempDir(), &gatedEventDAO{EventDAO: p.EventDAO, gate: gate})

	require.NoError(t, s.router.HandleEvent(newRiscToken("wal-m1", dupTestIssuer, s.audience), "x", s.streamID))
	require.NoError(t, s.router.HandleEvent(newRiscToken("wal-m2", dupTestIssuer, s.audience), "y", s.streamID))
	assert.InDelta(t, 2, testutil.ToFloat64(m.depth), 0.0001, "depth counts undrained entries")

	close(gate)
	s.waitDrained(t)
	require.Eventually(t, func() bool { return testutil.ToFloat64(m.drained) == 2 }, 5*time.Second, 5*time.Millisecond)
	assert.InDelta(t, 0, testutil.ToFloat64(m.depth), 0.0001)
	assert.InDelta(t, 0, testutil.ToFloat64(m.drainLag), 0.0001, "no lag once empty")
	assert.InDelta(t, 0, testutil.ToFloat64(m.replayed), 0.0001)

	families, err := reg.Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
		if f.GetName() == "goSignals_wal_drain_duration_seconds" {
			assert.GreaterOrEqual(t, f.GetMetric()[0].GetHistogram().GetSampleCount(), uint64(1))
		}
	}
	for _, n := range []string{"goSignals_wal_depth", "goSignals_wal_drain_lag_seconds", "goSignals_wal_drained_total", "goSignals_wal_replayed_total", "goSignals_wal_drain_duration_seconds"} {
		assert.True(t, names[n], n)
	}
}

// The drain-lag gauge reports the age of the oldest undrained entry.
func TestLocalWal_DrainLagReportsOldestEntry(t *testing.T) {
	m := useWalMetrics(t)
	p := openMemPersistence(t)
	dao := &gatedEventDAO{EventDAO: p.EventDAO}
	dao.failures.Store(1 << 20)
	clock := &walClock{t: time.Now()}
	useWalClock(t, clock, nil)
	s := newWalRouter(t, p, t.TempDir(), dao)
	require.NoError(t, s.router.HandleEvent(newRiscToken("wal-lag", dupTestIssuer, s.audience), "x", s.streamID))
	clock.advance(42 * time.Second)
	s.router.refreshWalGauges(s.router.wal)
	assert.InDelta(t, 42, testutil.ToFloat64(m.drainLag), 0.5)
	dao.failures.Store(0)
	s.waitDrained(t)
}
