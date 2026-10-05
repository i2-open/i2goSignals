package services

import (
	"context"
	"errors"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// fakeEventDAO is a minimal EventDAO used to exercise the
// addEvent/AddEvent/AddOperationalEvent dup-propagation contract. Only the
// methods touched by addEvent need real behaviour; the rest satisfy the
// interface as no-ops.
type fakeEventDAO struct {
	insertErr   error
	insertCalls int
	stored      map[string]*model.EventRecord
	// firstSeen is set by Insert from the record argument and returned by
	// FindByJTI — this lets the test assert that addEvent returns the
	// already-stored record, not the new one.
	firstSeen *model.EventRecord
	// findErr, if set, makes FindByJTI return (nil, findErr) so the
	// "dup detected then lookup fails" edge can be exercised.
	findErr error
	// pending is the set of JTIs RemovePendingMany reports as removed;
	// delivered records what Ack moved to delivered.
	pending                map[string]struct{}
	removePendingErr       error
	removePendingManyCalls int
	// insertWithPending, when set, is the per-record result InsertWithPending
	// returns; insertWithPendingErr is its whole-batch error. gotPending
	// records the pending map it was handed.
	insertWithPending      []error
	insertWithPendingErr   error
	gotPending             map[string][]interfaces.PendingRef
	markDeliveredManyCalls int
	delivered              []interfaces.DeliverableEvent
	// ackCalls counts Ack calls; Ack composes RemovePendingMany +
	// markDeliveredMany, as the memory provider does.
	ackCalls int
	ackJtis  [][]string
}

func (f *fakeEventDAO) Insert(_ context.Context, record *model.EventRecord) error {
	f.insertCalls++
	if f.insertErr != nil {
		return f.insertErr
	}
	if f.stored == nil {
		f.stored = make(map[string]*model.EventRecord)
	}
	if f.firstSeen == nil {
		f.firstSeen = record
	}
	f.stored[record.Jti] = record
	return nil
}

func (f *fakeEventDAO) FindByJTI(_ context.Context, jti string) (*model.EventRecord, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.firstSeen != nil && f.firstSeen.Jti == jti {
		return f.firstSeen, nil
	}
	if rec, ok := f.stored[jti]; ok {
		return rec, nil
	}
	return nil, nil
}

func (f *fakeEventDAO) FindByJTIs(_ context.Context, _ []string) ([]*model.EventRecord, error) {
	return nil, nil
}

func (f *fakeEventDAO) FindByTimeRange(_ context.Context, _ time.Time, _ *time.Time, _ func(*model.EventRecord) bool) ([]*model.EventRecord, error) {
	return nil, nil
}

func (f *fakeEventDAO) InsertMany(_ context.Context, _ []*model.EventRecord) ([]error, error) {
	return nil, nil
}
func (f *fakeEventDAO) AddPending(_ context.Context, _ interfaces.PendingRef, _ string) error {
	return nil
}
func (f *fakeEventDAO) AddPendingMany(_ context.Context, _ []interfaces.PendingRef, _ string) error {
	return nil
}
func (f *fakeEventDAO) EnsurePending(_ context.Context, _ string, _ map[string]string) ([]string, error) {
	return nil, nil
}
func (f *fakeEventDAO) GetPendingForStream(_ context.Context, _ string, _ int32) (interfaces.PendingPage, error) {
	return interfaces.PendingPage{}, nil
}
func (f *fakeEventDAO) RemovePendingMany(_ context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	f.removePendingManyCalls++
	if f.removePendingErr != nil {
		return nil, f.removePendingErr
	}
	var removed []interfaces.DeliverableEvent
	for _, jti := range jtis {
		if _, ok := f.pending[jti]; ok {
			removed = append(removed, interfaces.DeliverableEvent{Jti: jti, StreamId: streamID})
		}
	}
	return removed, nil
}
func (f *fakeEventDAO) InsertWithPending(_ context.Context, records []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	f.gotPending = pending
	if f.insertWithPendingErr != nil {
		return nil, f.insertWithPendingErr
	}
	if f.insertWithPending != nil {
		return f.insertWithPending, nil
	}
	return make([]error, len(records)), nil
}
func (f *fakeEventDAO) ClearPendingForStream(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// markDeliveredMany records the entries an Ack moved to delivered.
func (f *fakeEventDAO) markDeliveredMany(events []interfaces.DeliverableEvent) {
	f.markDeliveredManyCalls++
	f.delivered = append(f.delivered, events...)
}

// Ack composes RemovePendingMany + markDeliveredMany, as the memory provider
// does, and counts the calls.
func (f *fakeEventDAO) Ack(ctx context.Context, batch interfaces.AckBatch) (int64, error) {
	f.ackCalls++
	f.ackJtis = append(f.ackJtis, batch.Jtis)
	removed, err := f.RemovePendingMany(ctx, batch.Jtis, batch.StreamID)
	if err != nil || len(removed) == 0 {
		return 0, err
	}
	f.markDeliveredMany(removed)
	return int64(len(removed)), nil
}
func (f *fakeEventDAO) ResetPendingAckJti(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeEventDAO) SweepExpired(_ context.Context, _, _ time.Time, _ int) (interfaces.SweepResult, error) {
	return interfaces.SweepResult{}, nil
}
func (f *fakeEventDAO) MigrateLegacyDeliveries(_ context.Context, _ func(string, time.Time) *time.Time) (interfaces.MigrationResult, error) {
	return interfaces.MigrationResult{}, nil
}
func (f *fakeEventDAO) WatchPending(_ context.Context, _ func(ref interfaces.PendingRef, streamID string)) error {
	return nil
}
func (f *fakeEventDAO) ListDeliveredForStream(_ context.Context, _ string) ([]interfaces.DeliveredEvent, error) {
	return nil, nil
}
func (f *fakeEventDAO) RemoveDelivered(_ context.Context, _ string, _ string) error { return nil }
func (f *fakeEventDAO) DeleteBodyIfUnreferenced(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (f *fakeEventDAO) CountRetainedForStream(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func newTokenWithJTI(jti string) *goSet.SecurityEventToken {
	token := &goSet.SecurityEventToken{
		Events: map[string]interface{}{"test": "event"},
	}
	token.ID = jti
	return token
}

// TestAddEvent_DuplicateReturnsExistingRecord asserts that when the DAO
// reports ErrDuplicateJTI, AddEvent looks up the existing record via
// FindByJTI and returns (existingRec, ErrDuplicateJTI) — never (nil, err)
// and never the new in-flight record.
func TestAddEvent_DuplicateReturnsExistingRecord(t *testing.T) {
	existing := &model.EventRecord{
		Jti:      "dup-jti",
		Original: `{"first":true}`,
		Sid:      "stream-1",
		SortTime: time.Now(),
	}
	fake := &fakeEventDAO{
		insertErr: interfaces.ErrDuplicateJTI,
		firstSeen: existing,
	}
	svc := NewEventService(fake)

	rec, err := svc.AddEvent(context.Background(), newTokenWithJTI("dup-jti"), "stream-1", `{"second":true}`)
	if !errors.Is(err, interfaces.ErrDuplicateJTI) {
		t.Fatalf("AddEvent: expected ErrDuplicateJTI, got %v", err)
	}
	if rec == nil {
		t.Fatal("AddEvent: expected existing record, got nil")
	}
	if rec.Original != existing.Original {
		t.Errorf("AddEvent returned new record, not existing: got Original=%q want %q",
			rec.Original, existing.Original)
	}
}

func TestAddEvent_HappyPathReturnsNewRecord(t *testing.T) {
	fake := &fakeEventDAO{}
	svc := NewEventService(fake)

	rec, err := svc.AddEvent(context.Background(), newTokenWithJTI("fresh-jti"), "stream-1", `{"original":true}`)
	if err != nil {
		t.Fatalf("AddEvent: unexpected error %v", err)
	}
	if rec == nil || rec.Jti != "fresh-jti" {
		t.Fatalf("AddEvent: expected fresh record, got %+v", rec)
	}
	if rec.Operational {
		t.Errorf("AddEvent must not flag the record as Operational")
	}
}

// TestAddOperationalEvent_DuplicateReturnsExistingRecord exercises the
// shared addEvent path through the Operational=true variant. The dup
// short-circuit must behave identically.
func TestAddOperationalEvent_DuplicateReturnsExistingRecord(t *testing.T) {
	existing := &model.EventRecord{
		Jti:         "op-dup-jti",
		Original:    `{"first":true}`,
		Sid:         "stream-2",
		Operational: true,
		SortTime:    time.Now(),
	}
	fake := &fakeEventDAO{
		insertErr: interfaces.ErrDuplicateJTI,
		firstSeen: existing,
	}
	svc := NewEventService(fake)

	rec, err := svc.AddOperationalEvent(context.Background(), newTokenWithJTI("op-dup-jti"), "stream-2", `{"second":true}`)
	if !errors.Is(err, interfaces.ErrDuplicateJTI) {
		t.Fatalf("AddOperationalEvent: expected ErrDuplicateJTI, got %v", err)
	}
	if rec == nil || rec.Original != existing.Original {
		t.Fatalf("AddOperationalEvent: expected existing record, got %+v", rec)
	}
}

// TestAddEvent_DuplicateWithFindFailureSurfacesLookupError asserts the safety
// fix for the (rare) edge where the DAO reports ErrDuplicateJTI but the
// subsequent FindByJTI also fails. The service must NOT pair the dup
// sentinel with a nil record: SubmitOperationalEvent's short-circuit returns
// (rec, nil) to its caller and a nil rec would look like success.
func TestAddEvent_DuplicateWithFindFailureSurfacesLookupError(t *testing.T) {
	lookupBoom := errors.New("mongo connection blip")
	fake := &fakeEventDAO{
		insertErr: interfaces.ErrDuplicateJTI,
		findErr:   lookupBoom,
	}
	svc := NewEventService(fake)

	rec, err := svc.AddEvent(context.Background(), newTokenWithJTI("dup-then-lost"), "stream-1", "")
	if !errors.Is(err, lookupBoom) {
		t.Fatalf("AddEvent: expected the lookup error to be returned, got %v", err)
	}
	if errors.Is(err, interfaces.ErrDuplicateJTI) {
		t.Errorf("AddEvent must NOT pair ErrDuplicateJTI with a nil record; should surface findErr instead")
	}
	if rec != nil {
		t.Errorf("AddEvent must return nil record when lookup fails, got %+v", rec)
	}
}

func TestAddOperationalEvent_HappyPathReturnsNewRecord(t *testing.T) {
	fake := &fakeEventDAO{}
	svc := NewEventService(fake)

	rec, err := svc.AddOperationalEvent(context.Background(), newTokenWithJTI("op-fresh"), "stream-2", "")
	if err != nil {
		t.Fatalf("AddOperationalEvent: unexpected error %v", err)
	}
	if rec == nil || !rec.Operational {
		t.Fatalf("AddOperationalEvent must flag the record as Operational; got %+v", rec)
	}
}

// TestAckEvents_MarksOnlyRemovedDelivered asserts one AckEvents call makes one
// Ack call (the one-trip ack, #335, #359) whose delivered records are
// exactly the JTIs that were actually pending — never the unknown ones.
func TestAckEvents_MarksOnlyRemovedDelivered(t *testing.T) {
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}, "j-3": {}}}
	svc := NewEventService(fake)

	err := svc.AckEvents(context.Background(), []string{"j-1", "j-2", "j-3"}, "stream-1", 0)
	if err != nil {
		t.Fatalf("AckEvents: %v", err)
	}
	if fake.ackCalls != 1 {
		t.Fatalf("Ack calls = %d, want 1", fake.ackCalls)
	}
	if fake.removePendingManyCalls != 1 || fake.markDeliveredManyCalls != 1 {
		t.Fatalf("calls: removePendingMany=%d markDeliveredMany=%d, want 1 and 1",
			fake.removePendingManyCalls, fake.markDeliveredManyCalls)
	}
	if len(fake.delivered) != 2 {
		t.Fatalf("delivered = %v, want j-1 and j-3 only", fake.delivered)
	}
	for _, ev := range fake.delivered {
		if ev.StreamId != "stream-1" || (ev.Jti != "j-1" && ev.Jti != "j-3") {
			t.Errorf("unexpected delivered entry %+v", ev)
		}
	}
}

// TestAckEvents_NothingPendingSkipsDelivered: when no JTI was pending nothing
// is marked delivered; an empty batch touches the DAO not at all.
func TestAckEvents_NothingPendingSkipsDelivered(t *testing.T) {
	fake := &fakeEventDAO{}
	svc := NewEventService(fake)

	if err := svc.AckEvents(context.Background(), []string{"j-1"}, "stream-1", 0); err != nil {
		t.Fatalf("AckEvents: %v", err)
	}
	if fake.removePendingManyCalls != 1 || fake.markDeliveredManyCalls != 0 {
		t.Errorf("calls: removePendingMany=%d markDeliveredMany=%d, want 1 and 0",
			fake.removePendingManyCalls, fake.markDeliveredManyCalls)
	}

	if err := svc.AckEvents(context.Background(), nil, "stream-1", 0); err != nil {
		t.Fatalf("AckEvents empty: %v", err)
	}
	if fake.removePendingManyCalls != 1 || fake.ackCalls != 1 {
		t.Errorf("empty AckEvents must not call the DAO, got %d calls", fake.removePendingManyCalls)
	}
}

// TestAckEvent_RoutesThroughAck: a single-JTI ack uses the same one-trip DAO
// Ack as a batch.
func TestAckEvent_RoutesThroughAck(t *testing.T) {
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}}}
	svc := NewEventService(fake)

	if err := svc.AckEvent(context.Background(), "j-1", "stream-1", 0); err != nil {
		t.Fatalf("AckEvent: %v", err)
	}
	if fake.ackCalls != 1 {
		t.Fatalf("Ack calls = %d, want 1", fake.ackCalls)
	}
	if len(fake.ackJtis) != 1 || len(fake.ackJtis[0]) != 1 || fake.ackJtis[0][0] != "j-1" {
		t.Errorf("Ack jtis = %v, want [[j-1]]", fake.ackJtis)
	}
	if len(fake.delivered) != 1 || fake.delivered[0].Jti != "j-1" {
		t.Errorf("delivered = %v, want j-1", fake.delivered)
	}
}

// TestAckEvents_RemoveErrorPropagates: a RemovePendingMany failure is returned
// and nothing is marked delivered.
func TestAckEvents_RemoveErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	fake := &fakeEventDAO{removePendingErr: boom}
	svc := NewEventService(fake)

	err := svc.AckEvents(context.Background(), []string{"j-1"}, "stream-1", 0)
	if !errors.Is(err, boom) {
		t.Fatalf("AckEvents err = %v, want %v", err, boom)
	}
	if fake.markDeliveredManyCalls != 0 {
		t.Errorf("nothing may be marked delivered after a remove failure")
	}
}

// TestAddEventsWithPending_MapsPerRecordOutcomes asserts the one-trip ingest
// service contract (ADR 0043): the pending map reaches the DAO unchanged, an
// accepted record comes back as itself, a duplicate comes back as the EXISTING
// record paired with ErrDuplicateJTI, and any other per-record failure comes
// back as a nil record with that error, so the router cannot ack it.
func TestAddEventsWithPending_MapsPerRecordOutcomes(t *testing.T) {
	existing := &model.EventRecord{Jti: "dup", Original: "first"}
	markerErr := errors.New("pending marker write failed")
	fake := &fakeEventDAO{
		firstSeen:         existing,
		insertWithPending: []error{nil, interfaces.ErrDuplicateJTI, markerErr},
	}
	svc := NewEventService(fake)
	recs := NewIngestRecords(
		[]*goSet.SecurityEventToken{newTokenWithJTI("ok"), newTokenWithJTI("dup"), newTokenWithJTI("bad")},
		"stream-1", []string{"r-ok", "r-dup", "r-bad"})
	pending := map[string][]string{"out-1": {"ok", "dup", "bad"}}

	got, errs := svc.AddEventsWithPending(context.Background(), recs, "stream-1", pendingRefsOf(pending))

	if len(fake.gotPending["out-1"]) != 3 {
		t.Errorf("pending map not passed through: %v", fake.gotPending)
	}
	if errs[0] != nil || got[0] != recs[0] {
		t.Errorf("accepted: got (%v, %v), want the candidate and nil", got[0], errs[0])
	}
	if !errors.Is(errs[1], interfaces.ErrDuplicateJTI) || got[1] != existing {
		t.Errorf("duplicate: got (%v, %v), want the existing record and ErrDuplicateJTI", got[1], errs[1])
	}
	if !errors.Is(errs[2], markerErr) || got[2] != nil {
		t.Errorf("failure: got (%v, %v), want nil and the marker error", got[2], errs[2])
	}
}

// TestAddEventsWithPending_BatchErrorFailsEveryRecord: a whole-batch failure
// is reported at every position with no record, so nothing is acked.
func TestAddEventsWithPending_BatchErrorFailsEveryRecord(t *testing.T) {
	down := errors.New("store down")
	svc := NewEventService(&fakeEventDAO{insertWithPendingErr: down})
	recs := NewIngestRecords(
		[]*goSet.SecurityEventToken{newTokenWithJTI("a"), newTokenWithJTI("b")},
		"stream-1", []string{"", ""})

	got, errs := svc.AddEventsWithPending(context.Background(), recs, "stream-1", nil)

	for i := range recs {
		if got[i] != nil || !errors.Is(errs[i], down) {
			t.Errorf("position %d: got (%v, %v), want (nil, store down)", i, got[i], errs[i])
		}
	}
}
