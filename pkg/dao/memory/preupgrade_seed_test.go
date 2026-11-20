package memory

import (
	"testing"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SeedPreUpgradeBody implements daotest.PreUpgradeSeeder (#389): it stores rec
// as a release before ADR 0048 did, with no receivedAt, and SortTime (the
// adapter's stored-at fallback) set to storedAt.
func (d *EventDAOMemory) SeedPreUpgradeBody(t *testing.T, rec *model.EventRecord, storedAt time.Time) {
	t.Helper()
	r := *rec
	r.ReceivedAt, r.SortTime = time.Time{}, storedAt
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, dup := d.events[r.Jti]; dup {
		t.Fatalf("seed %s: duplicate jti", r.Jti)
	}
	d.events[r.Jti] = &r
}
