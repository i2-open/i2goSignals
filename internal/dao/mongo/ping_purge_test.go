package mongo

import (
	"context"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// rawPing reports whether the deliveries row (sid, jti) carries the stored
// ping marker, and whether the field exists at all.
func rawPing(t *testing.T, ctx context.Context, d *EventDAOMongo, sid bson.ObjectID, jti string) (ping, present bool) {
	t.Helper()
	var raw bson.M
	if err := d.deliveries.load().FindOne(ctx, bson.D{{Key: "sid", Value: sid}, {Key: "jti", Value: jti}}).Decode(&raw); err != nil {
		t.Fatalf("find %s: %v", jti, err)
	}
	v, ok := raw["ping"]
	if !ok {
		return false, false
	}
	b, _ := v.(bool)
	return b, true
}

// TestPingMarkerStoredRaw: a ping's deliveries row stores ping: true on every
// write path; a data event's row carries no ping field (ADR 0048).
func (s *EventDAOMongoSuite) TestPingMarkerStoredRaw() {
	t := s.T()
	ctx := context.Background()
	d := s.freshDAO(t, true).(*EventDAOMongo)
	sid := bson.NewObjectID()
	mk := func(jti string, ping bool) *model.EventRecord {
		types := []string{"urn:test"}
		if ping {
			types = []string{events.VerificationEventUri}
		}
		return &model.EventRecord{Jti: jti, Types: types, Original: jti, SortTime: time.Now()}
	}
	for _, ping := range []bool{true, false} {
		suffix := map[bool]string{true: "ping", false: "data"}[ping]
		if err := d.Insert(ctx, mk("ap-"+suffix, ping)); err != nil {
			t.Fatal(err)
		}
		if err := d.AddPending(ctx, interfaces.PendingRef{Jti: "ap-" + suffix, AckJti: "ap-" + suffix, Ping: ping}, sid.Hex()); err != nil {
			t.Fatal(err)
		}
		if err := d.Insert(ctx, mk("apm-"+suffix, ping)); err != nil {
			t.Fatal(err)
		}
		if err := d.AddPendingMany(ctx, []interfaces.PendingRef{{Jti: "apm-" + suffix, AckJti: "apm-" + suffix, Ping: ping}}, sid.Hex()); err != nil {
			t.Fatal(err)
		}
		if _, err := d.InsertWithPending(ctx, []*model.EventRecord{mk("iwp-"+suffix, ping)}, map[string][]interfaces.PendingRef{sid.Hex(): {{Jti: "iwp-" + suffix, AckJti: "iwp-" + suffix, Ping: ping}}}); err != nil {
			t.Fatal(err)
		}
		if err := d.Insert(ctx, mk("ens-"+suffix, ping)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.EnsurePending(ctx, "ens-"+suffix, map[string]string{sid.Hex(): "ens-" + suffix}); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"ap-", "apm-", "iwp-", "ens-"} {
			got, present := rawPing(t, ctx, d, sid, p+suffix)
			if ping && !got {
				t.Errorf("%s%s: ping marker not stored", p, suffix)
			}
			if !ping && present {
				t.Errorf("%s%s: data row carries a ping field", p, suffix)
			}
		}
	}
}

// TestMigrateLegacyDeliveries_MarksPings: migrated rows whose body is a ping
// get the marker; others do not.
func (s *EventDAOMongoSuite) TestMigrateLegacyDeliveries_MarksPings() {
	t := s.T()
	ctx := context.Background()
	f := s.migrationFixture(t)
	sid := bson.NewObjectID()
	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	f.seed(t, sid, base)
	if err := f.dao.Insert(ctx, &model.EventRecord{Jti: "d1", Types: []string{events.VerificationEventUri}, Original: "d1", SortTime: base}); err != nil {
		t.Fatal(err)
	}
	if err := f.dao.Insert(ctx, &model.EventRecord{Jti: "p1", Types: []string{events.VerificationEventUri}, Original: "p1", SortTime: base}); err != nil {
		t.Fatal(err)
	}
	if err := f.dao.Insert(ctx, &model.EventRecord{Jti: "d2", Types: []string{"urn:test"}, Original: "d2", SortTime: base}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.dao.MigrateLegacyDeliveries(ctx, func(string, time.Time) *time.Time { return nil }); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for jti, want := range map[string]bool{"d1": true, "p1": true, "d2": false, "p2": false, "both": false} {
		if got, _ := rawPing(t, ctx, f.dao, sid, jti); got != want {
			t.Errorf("%s ping = %v, want %v", jti, got, want)
		}
	}
}
