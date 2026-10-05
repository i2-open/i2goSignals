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
	if coord == nil {
		return es.MigrateLegacyDeliveries(ctx, expireAt)
	}
	var lastLog time.Time
	for {
		held, _, _, err := coord.TryAcquireOrRenewLease(migrationLeaseResource, nodeId, migrationLeaseTTL)
		if err == nil && held {
			break
		}
		if errors.Is(err, interfaces.ErrStoreNotReady) {
			return interfaces.MigrationResult{}, err
		}
		if now := time.Now(); now.Sub(lastLog) >= migrationWaitLogEvery {
			lastLog = now
			eventLogger.Info("ROUTER: waiting for the deliveries migration lease", "resource", migrationLeaseResource, "node", nodeId, "error", err)
		}
		if !SleepCtx(ctx, migrationLeaseRetry) {
			return interfaces.MigrationResult{}, ctx.Err()
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
				if held, _, _, err := coord.TryAcquireOrRenewLease(migrationLeaseResource, nodeId, migrationLeaseTTL); err != nil || !held {
					eventLogger.Warn("ROUTER: deliveries migration lease renewal failed", "resource", migrationLeaseResource, "node", nodeId, "held", held, "error", err)
				}
			}
		}
	}()

	res, err := es.MigrateLegacyDeliveries(ctx, expireAt)
	stopRenew()
	<-renewDone
	if rerr := coord.ReleaseLeaseIfOwned(migrationLeaseResource, nodeId); rerr != nil {
		eventLogger.Warn("ROUTER: deliveries migration lease release failed", "resource", migrationLeaseResource, "node", nodeId, "error", rerr)
	}
	return res, err
}
