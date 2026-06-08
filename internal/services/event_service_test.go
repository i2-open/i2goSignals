package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
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
	stored      map[string]*model.AgEventRecord
	// firstSeen is set by Insert from the record argument and returned by
	// FindByJTI — this lets the test assert that addEvent returns the
	// already-stored record, not the new one.
	firstSeen *model.AgEventRecord
}

func (f *fakeEventDAO) Insert(_ context.Context, record *model.AgEventRecord) error {
	f.insertCalls++
	if f.insertErr != nil {
		return f.insertErr
	}
	if f.stored == nil {
		f.stored = make(map[string]*model.AgEventRecord)
	}
	if f.firstSeen == nil {
		f.firstSeen = record
	}
	f.stored[record.Jti] = record
	return nil
}

func (f *fakeEventDAO) FindByJTI(_ context.Context, jti string) (*model.AgEventRecord, error) {
	if f.firstSeen != nil && f.firstSeen.Jti == jti {
		return f.firstSeen, nil
	}
	if rec, ok := f.stored[jti]; ok {
		return rec, nil
	}
	return nil, nil
}

func (f *fakeEventDAO) FindByJTIs(_ context.Context, _ []string) ([]*model.AgEventRecord, error) {
	return nil, nil
}

func (f *fakeEventDAO) FindByTimeRange(_ context.Context, _ time.Time, _ *time.Time, _ func(*model.AgEventRecord) bool) ([]*model.AgEventRecord, error) {
	return nil, nil
}

func (f *fakeEventDAO) AddPending(_ context.Context, _ string, _ string) error { return nil }
func (f *fakeEventDAO) GetPendingForStream(_ context.Context, _ string, _ int32) ([]string, int64, error) {
	return nil, 0, nil
}
func (f *fakeEventDAO) RemovePending(_ context.Context, _ string, _ string) (*interfaces.DeliverableEvent, error) {
	return nil, nil
}
func (f *fakeEventDAO) ClearPendingForStream(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeEventDAO) MarkDelivered(_ context.Context, _ *interfaces.DeliverableEvent, _ time.Time) error {
	return nil
}
func (f *fakeEventDAO) WatchPending(_ context.Context, _ func(jti string, streamID string)) error {
	return nil
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
	existing := &model.AgEventRecord{
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
	existing := &model.AgEventRecord{
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
