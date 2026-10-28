package eventRouter

import (
	"context"
	"errors"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// migrationLeaseResource is the coordinator lease the startup migration of
// the legacy delivery collections runs under (#361, seam S2). It is none of
// the stream lease kinds, so no runner or owner cache reads it.
const migrationLeaseResource = "migration:deliveries"

// Migration lease timings (seam S2). Variables so tests can shorten them.
var (
	migrationLeaseTTL     = 30 * time.Second
	migrationLeaseRenew   = 10 * time.Second
	migrationLeaseRetry   = 2 * time.Second
	migrationWaitLogEvery = 30 * time.Second
)

// migrationExpireAt returns the expireAt function MigrateLegacyDeliveries
// stamps on a migrated delivered row: ackDate + the stream's retention window
// from states, or nil (keep forever) when there is no window or the stream no
// longer exists.
func migrationExpireAt(window services.EffectiveWindowFunc, states map[string]model.StreamStateRecord) func(string, time.Time) *time.Time {
	return func(sid string, ackDate time.Time) *time.Time {
		rec, ok := states[sid]
		if !ok {
			return nil
		}
		return ackExpireAt(window, &rec, ackDate)
	}
}

// migrateUntilStoreReady runs migrateLegacyDeliveries and, while the store is
// not connected yet (background reconnect), retries every
// migrationLeaseRetry, logging at WARN every migrationWaitLogEvery. The
// router's background start (migrateThenStartDelivery) therefore starts no
// delivery goroutine until the migration has run on a connected store (#361).
// Any other error, or ctx ending, is returned.
func migrateUntilStoreReady(ctx context.Context, es *services.EventService, coord cluster.ClusterCoordinator, nodeId string, expireAt func(string, time.Time) *time.Time) (interfaces.MigrationResult, error) {
	var lastLog time.Time
	for {
		res, err := migrateLegacyDeliveries(ctx, es, coord, nodeId, expireAt)
		if !errors.Is(err, interfaces.ErrStoreNotReady) {
			return res, err
		}
		if now := time.Now(); now.Sub(lastLog) >= migrationWaitLogEvery {
			lastLog = now
			eventLogger.Warn("ROUTER: store not connected; waiting to run the legacy deliveries migration before starting delivery", "node", nodeId, "error", err)
		}
		if !SleepCtx(ctx, migrationLeaseRetry) {
			return interfaces.MigrationResult{}, ctx.Err()
		}
	}
}

// migrateLegacyDeliveries runs EventService.MigrateLegacyDeliveries. With a
// coordinator it holds the migration lease for the whole pass: a node refused
// the lease retries every migrationLeaseRetry (logging at INFO every
// migrationWaitLogEvery) and, once it gets the lease, runs the same call,
// which finds nothing to migrate or completes an interrupted pass. The lease
// is renewed while the migration runs and released before returning, also on
// failure. With a nil coordinator the migration runs directly. A store that is
// not connected yet returns an error wrapping interfaces.ErrStoreNotReady
// without waiting; migrateUntilStoreReady retries it.
func migrateLegacyDeliveries(ctx context.Context, es *services.EventService, coord cluster.ClusterCoordinator, nodeId string, expireAt func(string, time.Time) *time.Time) (interfaces.MigrationResult, error) {
	var res interfaces.MigrationResult
	err := underMigrationLease(ctx, coord, migrationLeaseResource, "deliveries", nodeId, func() error {
		var err error
		res, err = es.MigrateLegacyDeliveries(ctx, expireAt)
		return err
	})
	return res, err
}

// pingMarkerLeaseResource is the coordinator lease the one-shot ping-marker
// backfill runs under (ADR 0048, i2goSignals #389). Like
// migrationLeaseResource it is none of the stream lease kinds.
const pingMarkerLeaseResource = "migration:ping-marker"

// migratePingMarkers runs EventService.MigratePingMarkers under
// pingMarkerLeaseResource, as migrateLegacyDeliveries does its migration: a
// node refused the lease waits for it and then finds the done flag recorded,
// so one node of a racing cluster does the work.
func migratePingMarkers(ctx context.Context, es *services.EventService, coord cluster.ClusterCoordinator, nodeId string) (interfaces.PingMarkerResult, error) {
	var res interfaces.PingMarkerResult
	err := underMigrationLease(ctx, coord, pingMarkerLeaseResource, "ping-marker", nodeId, func() error {
		var err error
		res, err = es.MigratePingMarkers(ctx)
		return err
	})
	return res, err
}

// underMigrationLease runs run while holding resource: it waits for the lease
// (retrying every migrationLeaseRetry, logging at INFO every
// migrationWaitLogEvery), renews it every migrationLeaseRenew while run runs
// and releases it afterwards, also on failure. A nil coordinator runs run
// directly; a store that is not connected returns ErrStoreNotReady without
// waiting; ctx ending while waiting returns ctx.Err().
func underMigrationLease(ctx context.Context, coord cluster.ClusterCoordinator, resource, name, nodeId string, run func() error) error {
	if coord == nil {
		return run()
	}
	var lastLog time.Time
	for {
		held, _, _, err := coord.TryAcquireOrRenewLease(resource, nodeId, migrationLeaseTTL)
		if err == nil && held {
			break
		}
		if errors.Is(err, interfaces.ErrStoreNotReady) {
			return err
		}
		if now := time.Now(); now.Sub(lastLog) >= migrationWaitLogEvery {
			lastLog = now
			eventLogger.Info("ROUTER: waiting for a migration lease", "migration", name, "resource", resource, "node", nodeId, "error", err)
		}
		if !SleepCtx(ctx, migrationLeaseRetry) {
			return ctx.Err()
		}
	}

	renewCtx, stopRenew := context.WithCancel(ctx)
	renewDone := make(chan struct{})
	go func() {
		defer close(renewDone)
		t := time.NewTicker(migrationLeaseRenew)
		defer t.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-t.C:
				if held, _, _, err := coord.TryAcquireOrRenewLease(resource, nodeId, migrationLeaseTTL); err != nil || !held {
					eventLogger.Warn("ROUTER: migration lease renewal failed", "migration", name, "resource", resource, "node", nodeId, "held", held, "error", err)
				}
			}
		}
	}()

	err := run()
	stopRenew()
	<-renewDone
	if rerr := coord.ReleaseLeaseIfOwned(resource, nodeId); rerr != nil {
		eventLogger.Warn("ROUTER: migration lease release failed", "migration", name, "resource", resource, "node", nodeId, "error", rerr)
	}
	return err
}
