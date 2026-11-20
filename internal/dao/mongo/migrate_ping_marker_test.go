package mongo

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/daotest"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// markerDAO is a fresh parity DAO with its own done-flag collection.
func (s *EventDAOMongoSuite) markerDAO(t *testing.T) *EventDAOMongo {
	d := s.freshDAO(t, false).(*EventDAOMongo)
	d.migrations = "migrations_" + bson.NewObjectID().Hex()
	t.Cleanup(func() { _ = d.migrationsCol(d.deliveries.load()).Drop(context.Background()) })
	return d
}

func legacyRecord(jti string, types []string, at time.Time) *model.EventRecord {
	ev := goSet.SecurityEventToken{Events: map[string]interface{}{types[0]: map[string]interface{}{}}}
	ev.ID = jti
	return &model.EventRecord{Jti: jti, Event: ev, Types: types, Original: `{"jti":"` + jti + `"}`, SortTime: at}
}

// pingFlags reads each delivery row's ping marker, keyed by jti.
func pingFlags(t *testing.T, d *EventDAOMongo) map[string]bool {
	t.Helper()
	cur, err := d.deliveries.load().Find(context.Background(), bson.D{})
	if err != nil {
		t.Fatalf("find deliveries: %v", err)
	}
	var rows []struct {
		Jti  string `bson:"jti"`
		Ping bool   `bson:"ping"`
	}
	if err := cur.All(context.Background(), &rows); err != nil {
		t.Fatalf("decode deliveries: %v", err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.Jti] = r.Ping
	}
	return got
}

// TestMigratePingMarkers (#389): the one-shot backfill marks the delivery rows
// of pre-upgrade ping bodies, pending and delivered, and no others; it records
// its done flag, so a second run is a no-op.
func (s *EventDAOMongoSuite) TestMigratePingMarkers() {
	t := s.T()
	ctx := context.Background()
	d := s.markerDAO(t)
	var seed daotest.PreUpgradeSeeder = d
	at := time.Now().UTC().Truncate(time.Second).Add(-48 * time.Hour)
	sidA, sidB := ids.NewObjectID(), ids.NewObjectID()

	seed.SeedPreUpgradeBody(t, legacyRecord("legacy-ping", []string{events.VerificationEventUri}, at), at)
	seed.SeedPreUpgradeBody(t, legacyRecord("legacy-ping-2", []string{events.VerificationEventUri}, at), at)
	seed.SeedPreUpgradeBody(t, legacyRecord("legacy-data", []string{"urn:test"}, at), at)
	for _, jti := range []string{"legacy-ping", "legacy-data"} {
		if err := d.AddPending(ctx, interfaces.PendingRef{Jti: jti, AckJti: jti, EnqueuedAt: at}, sidA); err != nil {
			t.Fatalf("AddPending %s: %v", jti, err)
		}
	}
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "legacy-ping-2", AckJti: "legacy-ping-2", EnqueuedAt: at}, sidB); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if _, err := d.Ack(ctx, interfaces.AckBatch{StreamID: sidB, Jtis: []string{"legacy-ping-2"}, AckDate: time.Now()}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	before := pingFlags(t, d)
	if before["legacy-ping"] || before["legacy-ping-2"] {
		t.Fatalf("rows marked before the backfill: %v", before)
	}

	res, err := d.MigratePingMarkers(ctx)
	if err != nil {
		t.Fatalf("MigratePingMarkers: %v", err)
	}
	if res.AlreadyDone || res.Marked != 2 {
		t.Errorf("first run = %+v, want 2 marked", res)
	}
	got := pingFlags(t, d)
	for jti, want := range map[string]bool{"legacy-ping": true, "legacy-ping-2": true, "legacy-data": false} {
		if got[jti] != want {
			t.Errorf("row %s ping = %v, want %v", jti, got[jti], want)
		}
	}

	// The delivered legacy ping is now purged by its stored-at fallback.
	if pr, err := d.PurgePingWindow(ctx, at.Add(-time.Hour), at.Add(time.Hour)); err != nil || pr.Deliveries != 1 {
		t.Errorf("PurgePingWindow = (%+v, %v), want the delivered legacy ping row", pr, err)
	}

	res, err = d.MigratePingMarkers(ctx)
	if err != nil || !res.AlreadyDone || res.Marked != 0 {
		t.Errorf("second run = (%+v, %v), want AlreadyDone", res, err)
	}
}

// TestLegacyPingWindowPlan (#389): the stored-at fallback query is index
// backed (the `_id` range or the ping partial index's null receivedAt key),
// never a collection scan.
func (s *EventDAOMongoSuite) TestLegacyPingWindowPlan() {
	t := s.T()
	d := s.markerDAO(t)
	now := time.Now().UTC().Truncate(time.Second)
	for _, f := range []bson.D{legacyPingFilter(), legacyPingWindowFilter(now.Add(-2*time.Hour), now.Add(-time.Hour))} {
		ec := d.events.load()
		var out bson.M
		err := ec.Database().RunCommand(context.Background(), bson.D{
			{Key: "explain", Value: bson.D{{Key: "find", Value: ec.Name()}, {Key: "filter", Value: f}}},
			{Key: "verbosity", Value: "queryPlanner"},
		}).Decode(&out)
		if err != nil {
			t.Fatalf("explain: %v", err)
		}
		plan, _ := bson.MarshalExtJSON(out["queryPlanner"], false, false)
		if strings.Contains(string(plan), "COLLSCAN") {
			t.Errorf("filter %v plans a COLLSCAN: %s", f, plan)
		}
	}
}

// TestPurgePingWindow_WaitsForMarkerBackfill: before MigratePingMarkers has
// recorded its done flag, the purge leaves pre-upgrade ping bodies alone, so
// the backfill can still find and mark their delivered rows; after it, the
// row and body go together.
func (s *EventDAOMongoSuite) TestPurgePingWindow_WaitsForMarkerBackfill() {
	t := s.T()
	ctx := context.Background()
	d := s.markerDAO(t)
	var seed daotest.PreUpgradeSeeder = d
	at := time.Now().UTC().Truncate(time.Second).Add(-48 * time.Hour)
	sid := ids.NewObjectID()

	seed.SeedPreUpgradeBody(t, legacyRecord("legacy-ping", []string{events.VerificationEventUri}, at), at)
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "legacy-ping", AckJti: "legacy-ping", EnqueuedAt: at}, sid); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if _, err := d.Ack(ctx, interfaces.AckBatch{StreamID: sid, Jtis: []string{"legacy-ping"}, AckDate: time.Now()}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	bodies := func() int64 {
		t.Helper()
		n, err := d.events.load().CountDocuments(ctx, bson.D{{Key: "jti", Value: "legacy-ping"}})
		if err != nil {
			t.Fatalf("count bodies: %v", err)
		}
		return n
	}

	if pr, err := d.PurgePingWindow(ctx, at.Add(-time.Hour), at.Add(time.Hour)); err != nil || pr.Deliveries != 0 || pr.Bodies != 0 {
		t.Fatalf("purge before the backfill = (%+v, %v), want nothing purged", pr, err)
	}
	if bodies() != 1 {
		t.Fatal("pre-upgrade body purged before the marker backfill")
	}

	if res, err := d.MigratePingMarkers(ctx); err != nil || res.Marked != 1 {
		t.Fatalf("MigratePingMarkers = (%+v, %v), want 1 marked", res, err)
	}
	if pr, err := d.PurgePingWindow(ctx, at.Add(-time.Hour), at.Add(time.Hour)); err != nil || pr.Deliveries != 1 || pr.Bodies != 1 {
		t.Errorf("purge after the backfill = (%+v, %v), want the row and body", pr, err)
	}
	if bodies() != 0 {
		t.Error("pre-upgrade body left after the backfill and purge")
	}
}
