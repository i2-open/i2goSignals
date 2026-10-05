package eventRouter

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// migrateDAO stands in for the store's MigrateLegacyDeliveries (#361): it
// counts calls, optionally takes `took` of (fake) time and returns err.
type migrateDAO struct {
	interfaces.EventDAO
	calls atomic.Int32
	took  time.Duration
	err   error
	// notReadyFor answers ErrStoreNotReady to the first notReadyFor calls.
	notReadyFor int32
}

func (d *migrateDAO) MigrateLegacyDeliveries(context.Context, func(string, time.Time) *time.Time) (interfaces.MigrationResult, error) {
	n := d.calls.Add(1)
	if n <= d.notReadyFor {
		return interfaces.MigrationResult{}, fmt.Errorf("%w: unbound", interfaces.ErrStoreNotReady)
	}
	if d.took > 0 {
		time.Sleep(d.took)
	}
	if d.err != nil {
		return interfaces.MigrationResult{}, d.err
	}
	return interfaces.MigrationResult{Pending: 2, Delivered: 3, Dropped: true}, nil
}

// leaseFree reports whether the migration lease is free, by taking and
// releasing it as a probe node.
func leaseFree(t *testing.T, coord cluster.ClusterCoordinator) bool {
	t.Helper()
	held, _, _, err := coord.TryAcquireOrRenewLease(migrationLeaseResource, "probe", time.Second)
	require.NoError(t, err)
	if held {
		require.NoError(t, coord.ReleaseLeaseIfOwned(migrationLeaseResource, "probe"))
	}
	return held
}

func TestMigrateLegacyDeliveries_NilCoordinatorRunsDirectly(t *testing.T) {
	dao := &migrateDAO{}
	res, err := migrateLegacyDeliveries(t.Context(), services.NewEventService(dao), nil, "node-a", nil)
	require.NoError(t, err)
	assert.Equal(t, interfaces.MigrationResult{Pending: 2, Delivered: 3, Dropped: true}, res)
	assert.EqualValues(t, 1, dao.calls.Load())
}

// A node refused the lease waits, retrying, and migrates once the holder
// releases it; the lease is released afterwards.
func TestMigrateLegacyDeliveries_WaitsForTheLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		coord := memory_provider.NewMemoryCoordinator()
		held, _, _, err := coord.TryAcquireOrRenewLease(migrationLeaseResource, "node-z", time.Hour)
		require.NoError(t, err)
		require.True(t, held)

		dao := &migrateDAO{}
		done := make(chan error, 1)
		go func() {
			_, err := migrateLegacyDeliveries(t.Context(), services.NewEventService(dao), coord, "node-b", nil)
			done <- err
		}()

		time.Sleep(10 * migrationLeaseRetry)
		synctest.Wait()
		assert.EqualValues(t, 0, dao.calls.Load(), "migrated while another node held the lease")
		select {
		case <-done:
			t.Fatal("returned while another node held the lease")
		default:
		}

		require.NoError(t, coord.ReleaseLeaseIfOwned(migrationLeaseResource, "node-z"))
		require.NoError(t, <-done)
		assert.EqualValues(t, 1, dao.calls.Load())
		assert.True(t, leaseFree(t, coord), "lease not released after the migration")
	})
}

// A wait honours context cancellation.
func TestMigrateLegacyDeliveries_WaitCancelled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		coord := memory_provider.NewMemoryCoordinator()
		_, _, _, err := coord.TryAcquireOrRenewLease(migrationLeaseResource, "node-z", time.Hour)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		dao := &migrateDAO{}
		_, err = migrateLegacyDeliveries(ctx, services.NewEventService(dao), coord, "node-b", nil)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.EqualValues(t, 0, dao.calls.Load())
	})
}

// The lease is released after a failed migration too.
func TestMigrateLegacyDeliveries_ReleasesTheLeaseOnFailure(t *testing.T) {
	coord := memory_provider.NewMemoryCoordinator()
	boom := errors.New("boom")
	_, err := migrateLegacyDeliveries(t.Context(), services.NewEventService(&migrateDAO{err: boom}), coord, "node-a", nil)
	assert.ErrorIs(t, err, boom)
	assert.True(t, leaseFree(t, coord), "lease not released after a failed migration")
}

// A migration longer than the lease TTL keeps the lease by renewing it.
func TestMigrateLegacyDeliveries_RenewsTheLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		coord := memory_provider.NewMemoryCoordinator()
		dao := &migrateDAO{took: 3 * migrationLeaseTTL}
		done := make(chan error, 1)
		go func() {
			_, err := migrateLegacyDeliveries(t.Context(), services.NewEventService(dao), coord, "node-a", nil)
			done <- err
		}()
		time.Sleep(2 * migrationLeaseTTL)
		synctest.Wait()
		held, _, _, err := coord.TryAcquireOrRenewLease(migrationLeaseResource, "node-b", migrationLeaseTTL)
		require.NoError(t, err)
		assert.False(t, held, "lease lapsed while the migration was running")
		require.NoError(t, <-done)
		assert.True(t, leaseFree(t, coord))
	})
}

// NewRouter panics when the migration fails, before it serves anything.
func TestNewRouter_PanicsWhenTheMigrationFails(t *testing.T) {
	p := openMemPersistence(t)
	es := services.NewEventService(&migrateDAO{EventDAO: p.EventDAO, err: errors.New("disk on fire")})
	assert.PanicsWithValue(t, "legacy deliveries migration failed: disk on fire", func() {
		r := NewRouter(RouterDeps{StreamService: p.StreamService, KeyService: p.KeyService, EventService: es, Coordinator: p.Coordinator}, "node-mig")
		r.Shutdown()
	})
	assert.True(t, leaseFree(t, p.Coordinator), "lease held after the failed migration")
}

// NewRouter runs the migration once at startup.
func TestNewRouter_RunsTheMigration(t *testing.T) {
	p := openMemPersistence(t)
	dao := &migrateDAO{EventDAO: p.EventDAO}
	r := NewRouter(RouterDeps{StreamService: p.StreamService, KeyService: p.KeyService, EventService: services.NewEventService(dao), Coordinator: p.Coordinator}, "node-mig")
	t.Cleanup(r.Shutdown)
	assert.EqualValues(t, 1, dao.calls.Load())
}

func TestMigrationExpireAt(t *testing.T) {
	seven := 7
	window := func(rec *model.StreamStateRecord) *int {
		if rec.StreamConfiguration.Id == "keep" {
			return nil
		}
		return &seven
	}
	states := map[string]model.StreamStateRecord{
		"s1":   {StreamConfiguration: model.StreamConfiguration{Id: "s1"}},
		"keep": {StreamConfiguration: model.StreamConfiguration{Id: "keep"}},
	}
	ack := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	f := migrationExpireAt(window, states)
	got := f("s1", ack)
	require.NotNil(t, got)
	assert.Equal(t, ack.Add(7*24*time.Hour), *got)
	assert.Nil(t, f("keep", ack), "no window keeps the row forever")
	assert.Nil(t, f("gone", ack), "a deleted stream keeps the row forever")
	assert.Nil(t, migrationExpireAt(nil, states)("s1", ack), "no window function")
}

// A store that is not connected yet does not wait for the lease: the call
// returns ErrStoreNotReady at once.
func TestMigrateLegacyDeliveries_StoreNotReady(t *testing.T) {
	coord := &notReadyCoordinator{ClusterCoordinator: memory_provider.NewMemoryCoordinator()}
	dao := &migrateDAO{}
	_, err := migrateLegacyDeliveries(t.Context(), services.NewEventService(dao), coord, "node-a", nil)
	assert.ErrorIs(t, err, interfaces.ErrStoreNotReady)
	assert.EqualValues(t, 0, dao.calls.Load())
}

// NewRouter does not wait for a store that is not connected yet (the
// provider reconnects in the background and the application must start): it
// returns at once and runs the migration in the background once the store is
// ready, starting delivery only after it (#361).
func TestNewRouter_StoreNotReadyMigratesInTheBackgroundBeforeDelivery(t *testing.T) {
	prev := migrationLeaseRetry
	migrationLeaseRetry = 5 * time.Millisecond
	t.Cleanup(func() { migrationLeaseRetry = prev })

	p := openMemPersistence(t)
	dao := &migrateDAO{EventDAO: p.EventDAO, notReadyFor: 3}
	r := NewRouter(RouterDeps{StreamService: p.StreamService, KeyService: p.KeyService, EventService: services.NewEventService(dao), Coordinator: p.Coordinator}, "node-mig").(*router)
	t.Cleanup(r.Shutdown)
	assert.Less(t, dao.calls.Load(), int32(4), "NewRouter waited for the store")
	assert.False(t, routerEnabled(r), "delivery started before the migration")

	require.Eventually(t, func() bool { return routerEnabled(r) }, 5*time.Second, time.Millisecond, "delivery never started")
	assert.EqualValues(t, 4, dao.calls.Load(), "delivery started before the migration ran on a ready store")
	assert.True(t, leaseFree(t, p.Coordinator), "lease held after the migration")
}

// Shutdown while the store is still not connected stops the background
// migration and never starts delivery.
func TestNewRouter_ShutdownBeforeTheStoreIsReadyStartsNothing(t *testing.T) {
	prev := migrationLeaseRetry
	migrationLeaseRetry = 5 * time.Millisecond
	t.Cleanup(func() { migrationLeaseRetry = prev })

	p := openMemPersistence(t)
	dao := &migrateDAO{EventDAO: p.EventDAO, notReadyFor: 1 << 30}
	r := NewRouter(RouterDeps{StreamService: p.StreamService, KeyService: p.KeyService, EventService: services.NewEventService(dao), Coordinator: p.Coordinator}, "node-mig").(*router)
	r.Shutdown()
	settled := dao.calls.Load()
	time.Sleep(10 * migrationLeaseRetry)
	assert.LessOrEqual(t, dao.calls.Load(), settled+1, "the migration retried after Shutdown")
	assert.False(t, routerEnabled(r), "delivery started after Shutdown")
}

func routerEnabled(r *router) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

// notReadyCoordinator is a coordinator whose store is not connected.
type notReadyCoordinator struct {
	cluster.ClusterCoordinator
}

func (notReadyCoordinator) TryAcquireOrRenewLease(string, string, time.Duration) (bool, int64, time.Time, error) {
	return false, 0, time.Time{}, fmt.Errorf("coordinator not initialized: %w", interfaces.ErrStoreNotReady)
}

// probeDAO answers ErrStoreNotReady to MigrateLegacyDeliveries until ready is
// set, and counts every deliveries read or write that arrives before the
// migration has completed (#361).
type probeDAO struct {
	interfaces.EventDAO
	ready    atomic.Bool
	migrated atomic.Bool
	early    atomic.Int32
	clears   atomic.Int32
}

func (d *probeDAO) touch() {
	if !d.migrated.Load() {
		d.early.Add(1)
	}
}

func (d *probeDAO) MigrateLegacyDeliveries(ctx context.Context, f func(string, time.Time) *time.Time) (interfaces.MigrationResult, error) {
	if !d.ready.Load() {
		return interfaces.MigrationResult{}, fmt.Errorf("%w: unbound", interfaces.ErrStoreNotReady)
	}
	res, err := d.EventDAO.MigrateLegacyDeliveries(ctx, f)
	d.migrated.Store(err == nil)
	return res, err
}

func (d *probeDAO) InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	d.touch()
	return d.EventDAO.InsertWithPending(ctx, records, pending)
}

func (d *probeDAO) AddPending(ctx context.Context, ref interfaces.PendingRef, streamID string) error {
	d.touch()
	return d.EventDAO.AddPending(ctx, ref, streamID)
}

func (d *probeDAO) AddPendingMany(ctx context.Context, refs []interfaces.PendingRef, streamID string) error {
	d.touch()
	return d.EventDAO.AddPendingMany(ctx, refs, streamID)
}

func (d *probeDAO) EnsurePending(ctx context.Context, jti string, ackJtis map[string]string) ([]string, error) {
	d.touch()
	return d.EventDAO.EnsurePending(ctx, jti, ackJtis)
}

func (d *probeDAO) GetPendingForStream(ctx context.Context, streamID string, limit int32) (interfaces.PendingPage, error) {
	d.touch()
	return d.EventDAO.GetPendingForStream(ctx, streamID, limit)
}

func (d *probeDAO) StoredAckJtis(ctx context.Context, streamID string, jtis []string) (map[string]string, error) {
	d.touch()
	return d.EventDAO.StoredAckJtis(ctx, streamID, jtis)
}

func (d *probeDAO) RemovePendingMany(ctx context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	d.touch()
	return d.EventDAO.RemovePendingMany(ctx, jtis, streamID)
}

func (d *probeDAO) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	d.touch()
	d.clears.Add(1)
	return d.EventDAO.ClearPendingForStream(ctx, streamID)
}

func (d *probeDAO) Ack(ctx context.Context, batch interfaces.AckBatch) (int64, error) {
	d.touch()
	return d.EventDAO.Ack(ctx, batch)
}

func (d *probeDAO) ResetPendingAckJti(ctx context.Context, streamID string) (int64, error) {
	d.touch()
	return d.EventDAO.ResetPendingAckJti(ctx, streamID)
}

// A stream created through the API while delivery waits for the store starts
// nothing that reads or writes deliveries until the legacy migration has
// completed (#361, seam S2); ingest is refused as a retryable store failure,
// a reset is carried out after the start, and the stream starts from the
// state map read once the migration is done.
func TestNewRouter_APIStreamWaitsForTheMigration(t *testing.T) {
	prev := migrationLeaseRetry
	migrationLeaseRetry = 5 * time.Millisecond
	t.Cleanup(func() { migrationLeaseRetry = prev })

	p := openMemPersistence(t)
	dao := &probeDAO{EventDAO: p.EventDAO}
	r := NewRouter(RouterDeps{StreamService: p.StreamService, KeyService: p.KeyService, EventService: services.NewEventService(dao), Coordinator: p.Coordinator, ServesClaims: true}, "node-mig").(*router)
	t.Cleanup(r.Shutdown)

	audience := "https://receiver.example.com"
	stream := ensureWalPollStream(t, p, audience)
	sid := stream.StreamConfiguration.Id
	r.UpdateStreamState(stream)
	r.ResetStream(sid)
	err := r.HandleEvent(newRiscToken("jti-early", dupTestIssuer, audience), "raw", sid)
	assert.ErrorIs(t, err, ErrStoreUnavailable, "ingest before the migration must be a retryable store failure")
	_, _, status := r.PollStreamHandler(t.Context(), sid, model.PollParameters{MaxEvents: 1, ReturnImmediately: true})
	assert.Equal(t, 503, status, "a poll before the migration must be told to retry")
	assert.False(t, r.DeliveryStarted())

	assert.Never(t, func() bool { return dao.early.Load() > 0 }, 100*time.Millisecond, time.Millisecond, "deliveries accessed before the migration")

	dao.ready.Store(true)
	require.Eventually(t, func() bool { return routerEnabled(r) }, 5*time.Second, time.Millisecond, "delivery never started")
	require.Eventually(t, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		_, ok := r.pollStreams[sid]
		return ok
	}, 5*time.Second, time.Millisecond, "the API-created stream never started")
	assert.True(t, r.DeliveryStarted())
	require.Eventually(t, func() bool { return dao.clears.Load() == 1 }, 5*time.Second, time.Millisecond, "the deferred reset never ran")
	assert.Zero(t, dao.early.Load(), "deliveries accessed before the migration")
}

// An SSTP exchange that arrives while delivery waits for the legacy
// migration is refused as a retryable store failure before it resolves the
// acceptor owner, seeds a queue or applies the peer's acks (#361): nothing
// reads or writes deliveries until the migration has completed.
func TestNewRouter_SstpExchangeWaitsForTheMigration(t *testing.T) {
	prev := migrationLeaseRetry
	migrationLeaseRetry = 5 * time.Millisecond
	t.Cleanup(func() { migrationLeaseRetry = prev })

	p := openMemPersistence(t)
	dao := &probeDAO{EventDAO: p.EventDAO}
	r := NewRouter(RouterDeps{StreamService: p.StreamService, KeyService: p.KeyService, EventService: services.NewEventService(dao), Coordinator: p.Coordinator, ServesClaims: true}, "node-mig").(*router)
	t.Cleanup(r.Shutdown)

	rec := sstpServerPairState("sstp-tx-mig", "sstp-rx-mig", "pair-mig")
	require.NoError(t, p.StreamService.PersistStreamStateRecord(t.Context(), rec))
	inbound := []SstpInboundSet{{Jti: "sstp-mig-in", Token: newRiscToken("sstp-mig-in", "https://peer.example.com", dupTestIssuer), Raw: "raw"}}
	resp, err := r.SstpServerHandler(t.Context(), rec, goSetSstp.Message{Ack: []string{"wire-ack-1"}, ReturnImmediately: goSetSstp.BoolPtr(true)}, inbound)
	assert.ErrorIs(t, err, ErrStoreUnavailable, "an SSTP exchange before the migration must be told to retry")
	assert.Empty(t, resp.Ack, "nothing may be acked before the migration")
	assert.Zero(t, dao.early.Load(), "deliveries accessed before the migration")
	assert.Zero(t, leaseHolderCount(t, p.Coordinator, cluster.SstpServerResource("sstp-tx-mig")), "acceptor owner resolved before the migration")
}

// leaseHolderCount is 1 when some node holds resource, else 0.
func leaseHolderCount(t *testing.T, coord cluster.ClusterCoordinator, resource string) int {
	t.Helper()
	held, _, _, err := coord.TryAcquireOrRenewLease(resource, "probe", time.Second)
	require.NoError(t, err)
	if held {
		require.NoError(t, coord.ReleaseLeaseIfOwned(resource, "probe"))
		return 0
	}
	return 1
}
