package eventRouter

import (
	"context"
	"errors"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedFence is a coordinator whose every lease carries token. Any lease call
// other than GetLeaseOwner panics on the nil embedded interface, which proves
// an ack path makes none.
type fixedFence struct {
	cluster.ClusterCoordinator
	token int64
}

func (f fixedFence) GetLeaseOwner(string) (string, time.Time, int64, error) {
	return "node-a", time.Now().Add(time.Minute), f.token, nil
}

func windowDays(n int) *int { return &n }

// ackRouter is a bare router over a memory store holding one push stream sid
// with the given per-stream retention window, and one pending reference j1.
func ackRouter(t *testing.T, window services.EffectiveWindowFunc, days *int) (*router, *memory.EventDAOMemory, string) {
	t.Helper()
	dao := memory.NewEventDAO()
	r, sid := ackRouterOn(t, dao, window, days)
	return r, dao, sid
}

// ackRouterOn is ackRouter over the given store.
func ackRouterOn(t *testing.T, dao interfaces.EventDAO, window services.EffectiveWindowFunc, days *int) (*router, string) {
	t.Helper()
	sid := model.NewRecordId().Hex()
	require.NoError(t, dao.AddPending(context.Background(), interfaces.PendingRef{Jti: "j1", AckJti: "j1"}, sid))
	r := &router{
		eventService:      services.NewEventService(dao),
		pushStreams:       map[string]model.StreamStateRecord{sid: {RetentionWindowDays: days}},
		pollStreams:       map[string]model.StreamStateRecord{},
		sstpClientStreams: map[string]model.StreamStateRecord{},
		sstpServerStreams: map[string]model.StreamStateRecord{},
		retentionWindow:   window,
	}
	// The stream's DeliveryQueue holds j1 as ingest would (#363): the queue
	// acks it under the acknowledgement JTI written with the row.
	r.queueFor(sid).accept(context.Background(), []interfaces.PendingRef{{Jti: "j1", AckJti: "j1"}})
	return r, sid
}

func deliveredExpireAt(t *testing.T, dao interfaces.EventDAO, sid string) (*time.Time, bool) {
	t.Helper()
	list, err := dao.ListDeliveredForStream(context.Background(), sid)
	require.NoError(t, err)
	for _, e := range list {
		if e.Jti == "j1" {
			return e.ExpireAt, true
		}
	}
	return nil, false
}

// A finite window resolved from the stream record the router holds is written
// as expireAt = ackDate + window at acknowledgement (#360, seam S1).
func TestAckEvents_FiniteWindowWritesExpireAt(t *testing.T) {
	assertFiniteWindowWritesExpireAt(t, memory.NewEventDAO())
}

// Parity: the Mongo store writes the same expireAt, resolved from the stream
// setting by the router, as the memory store (#360).
func TestAckEvents_FiniteWindowWritesExpireAt_Mongo(t *testing.T) {
	t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))
	t.Setenv("I2SIG_STORE_MONGO_FALLBACK_MEM", "FALSE")
	url := os.Getenv("MONGO_URL")
	if url == "" {
		url = benchMongoURL()
	}
	p, err := dbProviders.OpenPersistence(url, "ack_expire_parity_test")
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
	assertFiniteWindowWritesExpireAt(t, p.EventDAO)
}

func assertFiniteWindowWritesExpireAt(t *testing.T, dao interfaces.EventDAO) {
	t.Helper()
	r, sid := ackRouterOn(t, dao, services.DefaultEffectiveWindow, windowDays(3))
	before := time.Now()
	require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid))
	after := time.Now()

	expireAt, ok := deliveredExpireAt(t, dao, sid)
	require.True(t, ok, "j1 delivered")
	require.NotNil(t, expireAt)
	window := 3 * 24 * time.Hour
	assert.False(t, expireAt.Before(before.Add(window).Truncate(time.Millisecond)), "expireAt %v before ack+window", expireAt)
	assert.False(t, expireAt.After(after.Add(window)), "expireAt %v after ack+window", expireAt)
}

// No resolver (community), a nil window and a non-positive window all keep
// the reference forever: no expireAt is written.
func TestAckEvents_KeepForeverWritesNoExpireAt(t *testing.T) {
	cases := map[string]struct {
		window services.EffectiveWindowFunc
		days   *int
	}{
		"no resolver":  {nil, windowDays(3)},
		"nil window":   {services.DefaultEffectiveWindow, nil},
		"zero window":  {services.DefaultEffectiveWindow, windowDays(0)},
		"negative":     {services.DefaultEffectiveWindow, windowDays(-1)},
		"nil override": {func(*model.StreamStateRecord) *int { return nil }, windowDays(3)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r, dao, sid := ackRouter(t, c.window, c.days)
			require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid))
			expireAt, ok := deliveredExpireAt(t, dao, sid)
			require.True(t, ok, "j1 delivered")
			assert.Nil(t, expireAt)
		})
	}
}

// An ack for a stream the router does not hold writes no expireAt.
func TestAckEvents_UnknownStreamWritesNoExpireAt(t *testing.T) {
	r, dao, sid := ackRouter(t, services.DefaultEffectiveWindow, windowDays(3))
	r.pushStreams = map[string]model.StreamStateRecord{}
	require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid))
	expireAt, ok := deliveredExpireAt(t, dao, sid)
	require.True(t, ok)
	assert.Nil(t, expireAt)
}

// The expireAt path is guarded by the lease manager (#364): with no recorded
// tenure on the stream's lease the ack writes nothing and returns
// errNotLeaseOwner, without a coordinator call; once a renewal records the
// tenure the same ack is written with its expireAt.
func TestAckEvents_ExpireAtPathRequiresTenure(t *testing.T) {
	r, dao, sid := ackRouter(t, services.DefaultEffectiveWindow, windowDays(3))
	r.coordinator = fixedFence{token: 7}
	r.leases = newLeaseManager(r.coordinator)

	err := r.ackEvents(context.Background(), []string{"j1"}, sid)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errNotLeaseOwner))
	_, ok := deliveredExpireAt(t, dao, sid)
	assert.False(t, ok, "an ack without tenure must not write")

	r.leases.note(cluster.PushTransmitterResource(sid), time.Now(), true, time.Now().Add(time.Minute), time.Minute)
	require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid))
	expireAt, ok := deliveredExpireAt(t, dao, sid)
	require.True(t, ok)
	assert.NotNil(t, expireAt)
}

// A batch skipped for lease tenure is not counted: it is retried after the
// next renewal, and counting both attempts would report one batch as two
// against a single write.
func TestAckEvents_SkippedBatchIsNotCounted(t *testing.T) {
	r, _, sid := ackRouter(t, services.DefaultEffectiveWindow, windowDays(3))
	r.coordinator = fixedFence{token: 7}
	r.leases = newLeaseManager(r.coordinator)

	batches := testutil.ToFloat64(ackBatchesTotal)
	writes := testutil.ToFloat64(ackWritesTotal)
	require.ErrorIs(t, r.ackEvents(context.Background(), []string{"j1"}, sid), errNotLeaseOwner)
	assert.Equal(t, batches, testutil.ToFloat64(ackBatchesTotal), "a skipped batch is not counted")

	r.leases.note(cluster.PushTransmitterResource(sid), time.Now(), true, time.Now().Add(time.Minute), time.Minute)
	require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid))
	assert.Equal(t, batches+1, testutil.ToFloat64(ackBatchesTotal), "the retried batch counts once")
	assert.Equal(t, writes+1, testutil.ToFloat64(ackWritesTotal))
}
