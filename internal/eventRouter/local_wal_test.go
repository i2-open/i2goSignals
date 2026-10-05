package eventRouter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/wal"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// gatedEventDAO wraps an EventDAO so a test can hold or fail InsertWithPending.
type gatedEventDAO struct {
	interfaces.EventDAO
	gate     chan struct{} // when non-nil, InsertWithPending waits for it to close
	failures atomic.Int32  // remaining calls to fail
	calls    atomic.Int32
}

var errInjectedStore = errors.New("injected store outage")

func (g *gatedEventDAO) InsertWithPending(ctx context.Context, recs []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	g.calls.Add(1)
	if g.gate != nil {
		select {
		case <-g.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if g.failures.Load() > 0 {
		g.failures.Add(-1)
		return nil, errInjectedStore
	}
	return g.EventDAO.InsertWithPending(ctx, recs, pending)
}

type walSetup struct {
	p         *dbProviders.Persistence
	router    *router
	dao       *gatedEventDAO
	log       wal.Log
	walDir    string
	stream    *model.StreamStateRecord
	streamID  string
	audience  string
	inCounter *prometheus.CounterVec
}

func openMemPersistence(t *testing.T) *dbProviders.Persistence {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	p, err := dbProviders.OpenPersistence("memorydb:", "local_wal_test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Storage.Close() })
	return p
}

// newWalRouter builds a local-durability router over p whose store writes go
// through a gatedEventDAO, and registers one poll stream the test SETs match.
func newWalRouter(t *testing.T, p *dbProviders.Persistence, walDir string, dao *gatedEventDAO) *walSetup {
	t.Helper()
	return newWalRouterWith(t, p, walDir, dao, nil)
}

// newWalRouterWith is newWalRouter with the router's deps passed through
// adjust before the router is built (nil leaves them as they are).
func newWalRouterWith(t *testing.T, p *dbProviders.Persistence, walDir string, dao *gatedEventDAO, adjust func(*RouterDeps)) *walSetup {
	t.Helper()
	log, err := wal.Open(walDir)
	require.NoError(t, err)
	if dao == nil {
		dao = &gatedEventDAO{EventDAO: p.EventDAO}
	}
	deps := RouterDeps{
		StreamService: p.StreamService,
		KeyService:    p.KeyService,
		EventService:  services.NewEventService(dao),
		Coordinator:   p.Coordinator,
		ServesClaims:  true,
		WAL:           log,
	}
	if adjust != nil {
		adjust(&deps)
	}
	r := NewRouter(deps, "node-wal-test").(*router)
	t.Cleanup(r.Shutdown)

	inCounter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_wal_events_in_total", Help: "test"}, []string{"type", "iss", "tfr", "stream_id"})
	outCounter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_wal_events_out_total", Help: "test"}, []string{"type", "iss", "tfr", "stream_id"})
	r.SetEventCounter(inCounter, outCounter)

	s := &walSetup{p: p, router: r, dao: dao, log: log, walDir: walDir, audience: "https://receiver.example.com", inCounter: inCounter}
	s.stream = ensureWalPollStream(t, p, s.audience)
	s.streamID = s.stream.StreamConfiguration.Id
	r.UpdateStreamState(s.stream)
	return s
}

func ensureWalPollStream(t *testing.T, p *dbProviders.Persistence, audience string) *model.StreamStateRecord {
	t.Helper()
	return ensurePollStreamDurability(t, p, audience, model.DurabilityLocal)
}

// ensurePollStreamDurability registers a poll stream for audience carrying the
// given per-stream durability (issue #343).
func ensurePollStreamDurability(t *testing.T, p *dbProviders.Persistence, audience string, durability model.DurabilityMode) *model.StreamStateRecord {
	t.Helper()
	h := &testHarness{streamService: p.StreamService, keyService: p.KeyService}
	projectId := projectIdFromHarness(t, h)
	if _, err := p.KeyService.CreateKeyPair(context.Background(), dupTestIssuer, "sig", projectId); err != nil {
		t.Logf("key pair: %v", err)
	}
	cfg := model.StreamConfiguration{
		Iss:             dupTestIssuer,
		Aud:             []string{audience},
		EventsRequested: []string{typeAcctDisabled},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll, EndpointUrl: "https://transmitter.example.com/events"},
		},
	}
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := p.StreamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg, Durability: durability}, projectId, nil)
	require.NoError(t, err)
	state, err := p.StreamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	return state
}

func (s *walSetup) pending(t *testing.T) []string {
	t.Helper()
	jtis, _ := s.p.EventService.GetEventIds(context.Background(), s.streamID, model.PollParameters{MaxEvents: 100, ReturnImmediately: true})
	return interfaces.RefJtis(jtis)
}

func (s *walSetup) stored(jti string) bool {
	return s.p.EventService.GetEventRecord(context.Background(), jti) != nil
}

func (s *walSetup) waitDrained(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { return s.log.Depth() == 0 }, 5*time.Second, 5*time.Millisecond, "WAL must drain")
}

func TestLocalWal_AckedBeforeStoreThenDrained(t *testing.T) {
	p := openMemPersistence(t)
	gate := make(chan struct{})
	s := newWalRouter(t, p, t.TempDir(), &gatedEventDAO{EventDAO: p.EventDAO, gate: gate})

	require.NoError(t, s.router.HandleEvent(newRiscToken("wal-1", dupTestIssuer, s.audience), `{"raw":1}`, s.streamID),
		"local mode acks once the SET is in the WAL")
	assert.Equal(t, 1, s.log.Depth())
	assert.False(t, s.stored("wal-1"), "the store write has not happened yet")
	assert.InDelta(t, 0.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001, "ingress is metered when stored, not at WAL ack")

	close(gate)
	s.waitDrained(t)
	assert.True(t, s.stored("wal-1"))
	assert.Equal(t, []string{"wal-1"}, s.pending(t), "the planned marker is written with the body")
	assert.Eventually(t, func() bool { return inCounterValue(t, s.inCounter, s.streamID) == 1 }, time.Second, 5*time.Millisecond)
	rec := s.p.EventService.GetEventRecord(context.Background(), "wal-1")
	assert.Equal(t, `{"raw":1}`, rec.Original)
	assert.Equal(t, s.streamID, rec.Sid)
	assert.Contains(t, rec.Types, typeAcctDisabled)
}

func TestLocalWal_BatchAndBufferedDuplicates(t *testing.T) {
	p := openMemPersistence(t)
	gate := make(chan struct{})
	s := newWalRouter(t, p, t.TempDir(), &gatedEventDAO{EventDAO: p.EventDAO, gate: gate})

	a := newRiscToken("wal-a", dupTestIssuer, s.audience)
	b := newRiscToken("wal-b", dupTestIssuer, s.audience)
	errs := s.router.HandleEvents([]*goSet.SecurityEventToken{a, b, a}, []string{"a", "b", "a"}, s.streamID)
	for _, err := range errs {
		require.NoError(t, err)
	}
	// A re-send while still buffered is acked as a duplicate, not appended again.
	require.NoError(t, s.router.HandleEvent(a, "a", s.streamID))
	assert.Equal(t, 1, s.log.Depth(), "one entry for the batch; buffered repeats are not appended")

	close(gate)
	s.waitDrained(t)
	assert.ElementsMatch(t, []string{"wal-a", "wal-b"}, s.pending(t))
}

func TestLocalWal_StoreFailureRetriedWithoutLoss(t *testing.T) {
	p := openMemPersistence(t)
	dao := &gatedEventDAO{EventDAO: p.EventDAO}
	dao.failures.Store(3)
	s := newWalRouter(t, p, t.TempDir(), dao)

	require.NoError(t, s.router.HandleEvent(newRiscToken("wal-retry", dupTestIssuer, s.audience), "r", s.streamID),
		"a store outage does not fail a local-mode ack")
	s.waitDrained(t)
	assert.GreaterOrEqual(t, int(dao.calls.Load()), 4, "the drain retried the store write")
	assert.True(t, s.stored("wal-retry"))
	assert.Equal(t, []string{"wal-retry"}, s.pending(t))
	assert.InDelta(t, 1.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001)
}

func TestLocalWal_DuplicateInStoreCountsAsDrained(t *testing.T) {
	p := openMemPersistence(t)
	s := newWalRouter(t, p, t.TempDir(), nil)
	tok := newRiscToken("wal-dup", dupTestIssuer, s.audience)
	recs := services.NewIngestRecords([]*goSet.SecurityEventToken{tok}, s.streamID, []string{"first"})
	pending := map[string][]string{s.stream.Id.Hex(): {"wal-dup"}}
	_, errs := p.EventService.AddEventsWithPending(context.Background(), recs, s.streamID, pendingRefsOf(pending))
	require.NoError(t, errs[0])

	require.NoError(t, s.router.HandleEvent(tok, "second", s.streamID))
	s.waitDrained(t)
	assert.Equal(t, "first", p.EventService.GetEventRecord(context.Background(), "wal-dup").Original, "the stored copy wins")
	assert.Equal(t, []string{"wal-dup"}, s.pending(t), "a duplicate gets no second marker")
	assert.InDelta(t, 0.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001, "a duplicate is not metered")
}

// TestLocalWal_DuplicateWithoutMarkerIsRequeued: a body that reached the store
// without its pending marker (the ADR 0043 residual, #331) is re-queued when
// its retry drains through the WAL, so the SET is still delivered exactly once.
func TestLocalWal_DuplicateWithoutMarkerIsRequeued(t *testing.T) {
	p := openMemPersistence(t)
	s := newWalRouter(t, p, t.TempDir(), nil)
	tok := newRiscToken("wal-orphan", dupTestIssuer, s.audience)
	recs := services.NewIngestRecords([]*goSet.SecurityEventToken{tok}, s.streamID, []string{"first"})
	_, errs := p.EventService.AddEventsWithPending(context.Background(), recs, s.streamID, nil)
	require.NoError(t, errs[0])
	require.Empty(t, s.pending(t), "precondition: body stored, marker missing")

	require.NoError(t, s.router.HandleEvent(tok, "second", s.streamID))
	s.waitDrained(t)
	assert.Equal(t, []string{"wal-orphan"}, s.pending(t), "the retry re-queues the orphaned body exactly once")
	assert.InDelta(t, 0.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001, "a duplicate is still not metered as ingress")

	// A further retry finds the marker in place and changes nothing.
	require.NoError(t, s.router.HandleEvent(tok, "third", s.streamID))
	s.waitDrained(t)
	assert.Equal(t, []string{"wal-orphan"}, s.pending(t))
}

func TestLocalWal_AppendFailureIsStoreUnavailable(t *testing.T) {
	p := openMemPersistence(t)
	s := newWalRouter(t, p, t.TempDir(), nil)
	require.NoError(t, s.log.Close())

	err := s.router.HandleEvent(newRiscToken("wal-closed", dupTestIssuer, s.audience), "x", s.streamID)
	require.ErrorIs(t, err, ErrStoreUnavailable, "a SET that is not in the WAL must not be acked")
	// The JTI reservation is released, so a later retry is not swallowed.
	s.router.wal.mu.Lock()
	_, held := s.router.wal.buffered["wal-closed"]
	s.router.wal.mu.Unlock()
	assert.False(t, held)
}

// An acked SET still in the WAL when the router stops is drained by the next
// router over the same log.
func TestLocalWal_UndrainedEntriesDrainOnRestart(t *testing.T) {
	// The store stays gated, so the graceful-stop drain runs out of time.
	t.Setenv(wal.EnvDrainTimeout, "100ms")
	p := openMemPersistence(t)
	dir := t.TempDir()
	gate := make(chan struct{})
	s := newWalRouter(t, p, dir, &gatedEventDAO{EventDAO: p.EventDAO, gate: gate})
	require.NoError(t, s.router.HandleEvent(newRiscToken("wal-restart", dupTestIssuer, s.audience), "x", s.streamID))
	s.router.Shutdown()
	assert.False(t, s.stored("wal-restart"))

	s2 := newWalRouter(t, p, dir, nil)
	s2.waitDrained(t)
	assert.True(t, s2.stored("wal-restart"))
}

func TestLocalWal_ConcurrentIngest(t *testing.T) {
	p := openMemPersistence(t)
	s := newWalRouter(t, p, t.TempDir(), nil)
	var wg sync.WaitGroup
	for c := 0; c < 8; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				jti := "wal-c-" + string(rune('a'+c)) + "-" + time.Now().Format("150405.000000000") + "-" + string(rune('A'+i))
				assert.NoError(t, s.router.HandleEvent(newRiscToken(jti, dupTestIssuer, s.audience), "x", s.streamID))
			}
		}(c)
	}
	wg.Wait()
	s.waitDrained(t)
	assert.Len(t, s.pending(t), 100, "GetEventIds caps at MaxEvents")
	assert.InDelta(t, 200.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001, "every SET stored and metered once")
}

// US 34: a SET ingested through the WAL and drained is purged by the
// RetentionEngine exactly like a directly ingested one.
func TestLocalWal_DrainedSetIsPurgedByRetention_Memory(t *testing.T) {
	assertWalRetention(t, openMemPersistence(t))
}

func TestLocalWal_DrainedSetIsPurgedByRetention_Mongo(t *testing.T) {
	t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))
	t.Setenv("I2SIG_STORE_MONGO_FALLBACK_MEM", "FALSE")
	url := os.Getenv("MONGO_URL")
	if url == "" {
		url = benchMongoURL()
	}
	p, err := dbProviders.OpenPersistence(url, "local_wal_retention_test")
	if err != nil {
		t.Skipf("mongo unreachable (%v); set MONGO_URL or start the dev stack", err)
	}
	if err := p.Storage.Check(); err != nil {
		_ = p.Storage.Close()
		t.Skipf("mongo unreachable (%v); set MONGO_URL or start the dev stack", err)
	}
	t.Cleanup(func() {
		_ = p.Storage.ResetDb(false)
		_ = p.Storage.Close()
	})
	assertWalRetention(t, p)
}

func assertWalRetention(t *testing.T, p *dbProviders.Persistence) {
	t.Helper()
	s := newWalRouter(t, p, t.TempDir(), nil)
	ctx := context.Background()
	jti := "wal-retention-" + time.Now().Format("150405.000000000")

	require.NoError(t, s.router.HandleEvent(newRiscToken(jti, dupTestIssuer, s.audience), "raw", s.streamID))
	s.waitDrained(t)
	require.True(t, s.stored(jti))
	// Acknowledge as the router does with a 1-day window: expireAt is fixed
	// at acknowledgement (#360).
	window := 1
	ackDate := time.Now()
	expireAt := ackDate.Add(time.Duration(window) * 24 * time.Hour)
	_, err := p.EventService.AckBatch(ctx, interfaces.AckBatch{StreamID: s.streamID, Jtis: []string{s.stream.AckJti(jti)}, AckDate: ackDate, ExpireAt: &expireAt})
	require.NoError(t, err)

	count, err := p.EventDAO.CountRetainedForStream(ctx, s.streamID)
	require.NoError(t, err)
	require.Equal(t, int64(1), count)

	streams := []model.StreamStateRecord{{Id: s.stream.Id, RetentionWindowDays: &window}}
	purged, err := services.NewRetentionEngine(p.EventDAO).PurgeExpired(ctx, time.Now().Add(48*time.Hour), streams, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, purged, "a WAL-drained SET is purged like any other")
	count, err = p.EventDAO.CountRetainedForStream(ctx, s.streamID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// TestLocalWal_PerStreamDurabilitySelectsIngestPath is the issue #343 seam: on
// a local-mode router a durability=local stream is acked from the WAL, while a
// majority or unset stream keeps the ADR 0038 direct store write.
func TestLocalWal_PerStreamDurabilitySelectsIngestPath(t *testing.T) {
	p := openMemPersistence(t)
	s := newWalRouter(t, p, t.TempDir(), nil)

	for _, mode := range []model.DurabilityMode{model.DurabilityMajority, model.DurabilityUnset} {
		aud := "https://majority-" + string(mode) + ".example.com"
		st := ensurePollStreamDurability(t, p, aud, mode)
		s.router.UpdateStreamState(st)
		jti := "dur-majority-" + string(mode)
		require.NoError(t, s.router.HandleEvent(newRiscToken(jti, dupTestIssuer, aud), `{"raw":2}`, st.StreamConfiguration.Id))
		assert.Equal(t, 0, s.log.Depth(), "durability %q must not use the WAL", mode)
		assert.True(t, s.stored(jti), "durability %q is stored before the ack", mode)
	}

	// With the store failing, a local stream still acks: the SET is in the WAL.
	s.dao.failures.Store(1 << 20)
	require.NoError(t, s.router.HandleEvent(newRiscToken("dur-local", dupTestIssuer, s.audience), `{"raw":1}`, s.streamID))
	assert.Equal(t, 1, s.log.Depth(), "a local stream is acked into the WAL")
	assert.False(t, s.stored("dur-local"))
	s.dao.failures.Store(0)
	s.waitDrained(t)
	assert.True(t, s.stored("dur-local"))
}

// TestLocalWal_LocalStreamOnMajorityDeploymentUsesStore: a durability=local
// stream on a router without a WAL runs at majority (stored before the ack).
func TestLocalWal_LocalStreamOnMajorityDeploymentUsesStore(t *testing.T) {
	p := openMemPersistence(t)
	r := NewRouter(RouterDeps{
		StreamService: p.StreamService,
		KeyService:    p.KeyService,
		EventService:  p.EventService,
		Coordinator:   p.Coordinator,
		ServesClaims:  true,
	}, "node-majority-test").(*router)
	t.Cleanup(r.Shutdown)
	aud := "https://receiver.example.com"
	st := ensureWalPollStream(t, p, aud)
	r.UpdateStreamState(st)

	require.NoError(t, r.HandleEvent(newRiscToken("dur-ignored", dupTestIssuer, aud), `{"raw":3}`, st.StreamConfiguration.Id))
	assert.NotNil(t, p.EventService.GetEventRecord(context.Background(), "dur-ignored"), "stored before the ack")
	_, warned := r.durabilityWarned.Load(st.StreamConfiguration.Id)
	assert.True(t, warned, "the ignored local setting is WARNed once")
}

// TestLocalWal_SuspendLocalIngestFallsBackToStore: once the server suspends
// local ingest (#343, a peer joined without ring-fed), a durability=local
// stream is acked at majority: nothing new enters the WAL, the SET is stored
// before the ack, the WARN fires once, and the gauge reads 1. A second
// SuspendLocalIngest is a no-op.
func TestLocalWal_SuspendLocalIngestFallsBackToStore(t *testing.T) {
	p := openMemPersistence(t)
	s := newWalRouter(t, p, t.TempDir(), nil)
	require.Equal(t, float64(0), testutil.ToFloat64(s.router.wal.metrics.suspended))

	require.NoError(t, s.router.HandleEvent(newRiscToken("pre-suspend", dupTestIssuer, s.audience), `{"raw":1}`, s.streamID))
	require.Equal(t, 1, s.log.Depth(), "before suspension a local stream is acked into the WAL")
	s.waitDrained(t)

	s.router.SuspendLocalIngest()
	s.router.SuspendLocalIngest()
	assert.Equal(t, float64(1), testutil.ToFloat64(s.router.wal.metrics.suspended))

	require.NoError(t, s.router.HandleEvent(newRiscToken("post-suspend", dupTestIssuer, s.audience), `{"raw":2}`, s.streamID))
	assert.Equal(t, 0, s.log.Depth(), "after suspension the WAL is not used")
	assert.True(t, s.stored("post-suspend"), "stored before the ack")
	_, warned := s.router.durabilityWarned.Load("suspended:" + s.streamID)
	assert.True(t, warned, "the suspension is WARNed once per stream")

	// With the store down, a local stream now fails like a majority one.
	s.dao.failures.Store(1)
	err := s.router.HandleEvent(newRiscToken("post-suspend-down", dupTestIssuer, s.audience), `{"raw":3}`, s.streamID)
	require.ErrorIs(t, err, ErrStoreUnavailable)
	assert.Equal(t, 0, s.log.Depth())
}
