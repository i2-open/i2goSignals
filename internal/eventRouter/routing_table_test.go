package eventRouter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unwrapCoordinator returns the coordinator a router was built with, beneath
// the trackedCoordinator that counts reads under the router lock.
func unwrapCoordinator(c cluster.ClusterCoordinator) cluster.ClusterCoordinator {
	if tc, ok := c.(*trackedCoordinator); ok {
		return tc.Unwrap()
	}
	return c
}

// routeFor returns the snapshot entry of the given mode and key, or nil.
func routeFor(r *router, mode, key string) *routeEntry {
	rt := r.routing()
	for i := range rt.entries {
		if rt.entries[i].mode == mode && rt.entries[i].key == key {
			return &rt.entries[i]
		}
	}
	return nil
}

// addPollStream creates and loads one more poll-transmit stream for the
// audience, with the same shape as setupDedupRouterPollStream's.
func addPollStream(t *testing.T, h *testHarness, audience string) string {
	t.Helper()
	projectId := projectIdFromHarness(t, h)
	cfg := model.StreamConfiguration{
		Iss:             dupTestIssuer,
		Aud:             []string{audience},
		EventsRequested: []string{typeAcctDisabled},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method:      model.DeliveryPoll,
				EndpointUrl: "https://transmitter.example.com/events",
			},
		},
	}
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := h.streamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
	require.NoError(t, err)
	state, err := h.streamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	h.router.UpdateStreamState(state)
	return created.Id
}

// TestRoutingTable_RebuiltOnStreamAddStatusChangeAndRemove: the snapshot
// follows the stream maps. Adding a stream publishes an entry naming its lease
// resource, a status change is visible in the entry's record, and removing the
// stream drops the entry.
func TestRoutingTable_RebuiltOnStreamAddStatusChangeAndRemove(t *testing.T) {
	h := newTestRouter(t)
	state := mustCreateTestStream(t, h, projectIdFromHarness(t, h))
	sid := state.StreamConfiguration.Id

	before := h.router.routing()
	h.router.UpdateStreamState(state)
	e := routeFor(h.router, routeModePush, sid)
	require.NotNil(t, e, "adding a push stream publishes a snapshot entry")
	assert.Equal(t, cluster.PushTransmitterResource(sid), e.resource)
	assert.Equal(t, model.StreamStateEnabled, e.stream.Status)
	assert.NotSame(t, before, h.router.routing(), "a write publishes a new snapshot")

	paused := *state
	paused.SetStatus(model.StreamStatePause, "test pause")
	h.router.UpdateStreamState(&paused)
	e = routeFor(h.router, routeModePush, sid)
	require.NotNil(t, e)
	assert.Equal(t, model.StreamStatePause, e.stream.Status, "a status change is rebuilt into the snapshot")

	h.router.RemoveStream(sid)
	assert.Nil(t, routeFor(h.router, routeModePush, sid), "removing the stream drops its entry")
}

// TestRoutingTable_EntriesNameEachKindsLeaseResource: every routed kind
// (push, poll, sstp-client, sstp-server) carries its own lease resource, and
// streamLeaseResource names all five kinds, the inbound poll receiver too.
func TestRoutingTable_EntriesNameEachKindsLeaseResource(t *testing.T) {
	r := newTestRouter(t).router
	r.mu.Lock()
	r.pushStreams["push-1"] = model.StreamStateRecord{}
	r.pollStreams["poll-1"] = model.StreamStateRecord{}
	r.sstpClientStreams["pair-1"] = model.StreamStateRecord{}
	r.sstpServerStreams["tx-1"] = model.StreamStateRecord{}
	r.rebuildRoutingLocked()
	r.mu.Unlock()

	cases := []struct{ mode, key, want string }{
		{routeModePush, "push-1", "push-transmitter:push-1"},
		{routeModePoll, "poll-1", "poll-transmitter:poll-1"},
		{routeModeSstpClient, "pair-1", "sstp-client:pair-1"},
		{routeModeSstpServer, "tx-1", "sstp-server:tx-1"},
	}
	for _, c := range cases {
		e := routeFor(r, c.mode, c.key)
		require.NotNil(t, e, c.mode)
		assert.Equal(t, c.want, e.resource, c.mode)
	}

	assert.Equal(t, cluster.PushTransmitterResource("s"), streamLeaseResource(routeModePush, "s"))
	assert.Equal(t, cluster.PollTransmitterResource("s"), streamLeaseResource(routeModePoll, "s"))
	assert.Equal(t, cluster.SstpClientResource("s"), streamLeaseResource(routeModeSstpClient, "s"))
	assert.Equal(t, cluster.SstpServerResource("s"), streamLeaseResource(routeModeSstpServer, "s"))
	assert.Equal(t, cluster.PollReceiverResource("s"), streamLeaseResource(model.ReceivePoll, "s"))
	assert.Equal(t, "poll-transmitter:s", cluster.PollTransmitterResource("s"))
	assert.Equal(t, "sstp-server:s", cluster.SstpServerResource("s"))
}

// trackingEventDAO counts every EventDAO call made while the caller holds a
// fan-out router lock region, through the router's lockTracker.
type trackingEventDAO struct {
	interfaces.EventDAO
	locks atomic.Pointer[lockTracker]
}

func (d *trackingEventDAO) note() {
	if l := d.locks.Load(); l != nil {
		l.noteRead()
	}
}

func (d *trackingEventDAO) Insert(ctx context.Context, record *model.EventRecord) error {
	d.note()
	return d.EventDAO.Insert(ctx, record)
}
func (d *trackingEventDAO) InsertMany(ctx context.Context, records []*model.EventRecord) ([]error, error) {
	d.note()
	return d.EventDAO.InsertMany(ctx, records)
}
func (d *trackingEventDAO) InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	d.note()
	return d.EventDAO.InsertWithPending(ctx, records, pending)
}
func (d *trackingEventDAO) FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error) {
	d.note()
	return d.EventDAO.FindByJTI(ctx, jti)
}
func (d *trackingEventDAO) FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error) {
	d.note()
	return d.EventDAO.FindByJTIs(ctx, jtis)
}
func (d *trackingEventDAO) FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.EventRecord) bool) ([]*model.EventRecord, error) {
	d.note()
	return d.EventDAO.FindByTimeRange(ctx, from, to, filter)
}
func (d *trackingEventDAO) AddPending(ctx context.Context, ref interfaces.PendingRef, streamID string) error {
	d.note()
	return d.EventDAO.AddPending(ctx, ref, streamID)
}
func (d *trackingEventDAO) AddPendingMany(ctx context.Context, refs []interfaces.PendingRef, streamID string) error {
	d.note()
	return d.EventDAO.AddPendingMany(ctx, refs, streamID)
}
func (d *trackingEventDAO) EnsurePending(ctx context.Context, jti string, ackJtis map[string]string) ([]string, error) {
	d.note()
	return d.EventDAO.EnsurePending(ctx, jti, ackJtis)
}
func (d *trackingEventDAO) GetPendingForStream(ctx context.Context, streamID string, limit int32) (interfaces.PendingPage, error) {
	d.note()
	return d.EventDAO.GetPendingForStream(ctx, streamID, limit)
}
func (d *trackingEventDAO) RemovePendingMany(ctx context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	d.note()
	return d.EventDAO.RemovePendingMany(ctx, jtis, streamID)
}
func (d *trackingEventDAO) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	d.note()
	return d.EventDAO.ClearPendingForStream(ctx, streamID)
}
func (d *trackingEventDAO) Ack(ctx context.Context, batch interfaces.AckBatch) (int64, error) {
	d.note()
	return d.EventDAO.Ack(ctx, batch)
}
func (d *trackingEventDAO) ResetPendingAckJti(ctx context.Context, streamID string) (int64, error) {
	d.note()
	return d.EventDAO.ResetPendingAckJti(ctx, streamID)
}
func (d *trackingEventDAO) SweepExpired(ctx context.Context, now time.Time, bodyCutoff time.Time, maxBodies int) (interfaces.SweepResult, error) {
	d.note()
	return d.EventDAO.SweepExpired(ctx, now, bodyCutoff, maxBodies)
}
func (d *trackingEventDAO) MigrateLegacyDeliveries(ctx context.Context, expireAt func(streamID string, ackDate time.Time) *time.Time) (interfaces.MigrationResult, error) {
	d.note()
	return d.EventDAO.MigrateLegacyDeliveries(ctx, expireAt)
}
func (d *trackingEventDAO) ListDeliveredForStream(ctx context.Context, streamID string) ([]interfaces.DeliveredEvent, error) {
	d.note()
	return d.EventDAO.ListDeliveredForStream(ctx, streamID)
}
func (d *trackingEventDAO) RemoveDelivered(ctx context.Context, jti string, streamID string) error {
	d.note()
	return d.EventDAO.RemoveDelivered(ctx, jti, streamID)
}
func (d *trackingEventDAO) DeleteBodyIfUnreferenced(ctx context.Context, jti string) (bool, error) {
	d.note()
	return d.EventDAO.DeleteBodyIfUnreferenced(ctx, jti)
}
func (d *trackingEventDAO) CountRetainedForStream(ctx context.Context, streamID string) (int64, error) {
	d.note()
	return d.EventDAO.CountRetainedForStream(ctx, streamID)
}
func (d *trackingEventDAO) WatchPending(ctx context.Context, callback func(ref interfaces.PendingRef, streamID string)) error {
	d.note()
	return d.EventDAO.WatchPending(ctx, callback)
}

// newTrackedRouter builds a router whose EventDAO reports to the router's
// lockTracker, and counts the reads it reports.
func newTrackedRouter(t *testing.T) (*testHarness, *atomic.Int64) {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "routing_table_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})
	dao := &trackingEventDAO{}
	persistence.EventService.WrapEventDAO(func(inner interfaces.EventDAO) interfaces.EventDAO {
		dao.EventDAO = inner
		return dao
	})
	r := NewRouter(RouterDeps{
		StreamService: persistence.StreamService,
		KeyService:    persistence.KeyService,
		EventService:  persistence.EventService,
		Coordinator:   persistence.Coordinator,
		ServesClaims:  true,
	}, "node-test").(*router)
	t.Cleanup(r.Shutdown)
	reads := &atomic.Int64{}
	r.locks.fanout.onRead = func() { reads.Add(1) }
	dao.locks.Store(&r.locks)
	return &testHarness{router: r, streamService: persistence.StreamService, keyService: persistence.KeyService}, reads
}

// TestHandleEvent_NoStoreOrCoordinatorReadUnderRouterLock: a SET fanned out to
// two poll streams and an SSTP-client pair, whose owner needs a coordinator
// read, makes no store or coordinator call while the router lock is held. The
// negative control shows a coordinator call inside a fan-out lock region is
// counted.
func TestHandleEvent_NoStoreOrCoordinatorReadUnderRouterLock(t *testing.T) {
	h, reads := newTrackedRouter(t)
	r := h.router
	audience := "https://receiver.example.com"
	_, err := h.keyService.CreateKeyPair(context.Background(), dupTestIssuer, "sig", projectIdFromHarness(t, h))
	require.NoError(t, err)
	inbound := addPollStream(t, h, audience)
	second := addPollStream(t, h, audience)

	pairId := "pair-no-read"
	pair := sstpClientPairForMatch("sstp-tx-no-read", pairId)
	r.mu.Lock()
	r.sstpClientStreams[pairId] = *pair
	r.rebuildRoutingLocked()
	r.mu.Unlock()

	counterBefore := testutil.ToFloat64(readsUnderLockCounter)
	require.NoError(t, r.HandleEvent(newRiscToken("no-read-under-lock", dupTestIssuer, audience), `{}`, inbound))
	require.Eventually(t, func() bool { return pollBufferCount(h, second) == 1 }, 2*time.Second, 5*time.Millisecond)
	assert.Zero(t, reads.Load(), "no store or coordinator read while the router lock is held")
	assert.Equal(t, counterBefore, testutil.ToFloat64(readsUnderLockCounter))

	// Negative control: the same coordinator read inside a fan-out region counts.
	r.fanoutRLock()
	_, _, _, _ = r.coordinator.GetLeaseOwner(cluster.SstpClientResource(pairId))
	r.fanoutRUnlock()
	assert.Equal(t, int64(1), reads.Load(), "a read under the fan-out lock is counted")
	assert.Equal(t, counterBefore+1, testutil.ToFloat64(readsUnderLockCounter))
}

// TestHandleEvent_SetMatchingTwoPollStreamsReachesEachOnce: one SET matching
// two poll streams is queued once on each.
func TestHandleEvent_SetMatchingTwoPollStreamsReachesEachOnce(t *testing.T) {
	s := setupDedupRouterPollStream(t)
	second := addPollStream(t, s.h, s.audience)

	require.NoError(t, s.h.router.HandleEvent(newRiscToken("two-poll", dupTestIssuer, s.audience), `{}`, s.streamID))
	require.Eventually(t, func() bool {
		return s.pollBufferCh() == 1 && pollBufferCount(s.h, second) == 1
	}, 2*time.Second, 5*time.Millisecond, "the SET reaches each poll stream")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, s.pollBufferCh(), "queued once on the first poll stream")
	assert.Equal(t, 1, pollBufferCount(s.h, second), "queued once on the second poll stream")
}

// TestResolveOwners_PushAndSstpClientOwnersOnTarget: owners are resolved onto
// the targets before any lock is taken, so the wake reads only t.owner.
func TestResolveOwners_PushAndSstpClientOwnersOnTarget(t *testing.T) {
	r := newTestRouter(t).router
	coord := unwrapCoordinator(r.coordinator)
	ok, _, _, err := coord.TryAcquireOrRenewLease(cluster.PushTransmitterResource("push-o"), "node-push", time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	ok, _, _, err = coord.TryAcquireOrRenewLease(cluster.SstpClientResource("pair-o"), "node-sstp", time.Minute)
	require.NoError(t, err)
	require.True(t, ok)

	push := &fanoutTarget{mode: routeModePush, key: "push-o", sid: "push-o"}
	sstp := &fanoutTarget{mode: routeModeSstpClient, key: "pair-o", sid: "tx-o"}
	poll := &fanoutTarget{mode: routeModePoll, key: "poll-o", sid: "poll-o"}
	r.resolveOwners([]*fanoutTarget{push, sstp, poll})

	assert.Equal(t, "node-push", push.owner)
	assert.Equal(t, "node-sstp", sstp.owner)
	assert.Empty(t, poll.owner, "poll targets have no owner to resolve")
	assert.Equal(t, "node-sstp", r.leaseOwners.peek(cluster.SstpClientResource("pair-o")),
		"the sstp-client owner is noted for the post-commit remote wake")
}
