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
}

func (d *migrateDAO) MigrateLegacyDeliveries(context.Context, func(string, time.Time) *time.Time) (interfaces.MigrationResult, error) {
	d.calls.Add(1)
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

// A store that is not connected yet does not wait for the lease and does not
// stop NewRouter: the migration is deferred to the next start.
func TestMigrateLegacyDeliveries_StoreNotReady(t *testing.T) {
	coord := &notReadyCoordinator{ClusterCoordinator: memory_provider.NewMemoryCoordinator()}
	dao := &migrateDAO{}
	_, err := migrateLegacyDeliveries(t.Context(), services.NewEventService(dao), coord, "node-a", nil)
	assert.ErrorIs(t, err, interfaces.ErrStoreNotReady)
	assert.EqualValues(t, 0, dao.calls.Load())

	p := openMemPersistence(t)
	es := services.NewEventService(&migrateDAO{EventDAO: p.EventDAO, err: fmt.Errorf("%w: unbound", interfaces.ErrStoreNotReady)})
	assert.NotPanics(t, func() {
		r := NewRouter(RouterDeps{StreamService: p.StreamService, KeyService: p.KeyService, EventService: es, Coordinator: p.Coordinator}, "node-mig")
		r.Shutdown()
	})
}

// notReadyCoordinator is a coordinator whose store is not connected.
type notReadyCoordinator struct {
	cluster.ClusterCoordinator
}

func (notReadyCoordinator) TryAcquireOrRenewLease(string, string, time.Duration) (bool, int64, time.Time, error) {
	return false, 0, time.Time{}, fmt.Errorf("coordinator not initialized: %w", interfaces.ErrStoreNotReady)
}
