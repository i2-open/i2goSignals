package memory

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestEventDAOMemory_Insert(t *testing.T) {
	dao := NewEventDAO()
	ctx := context.Background()

	event := &goSet.SecurityEventToken{
		Events: map[string]interface{}{"test": "event"},
	}
	event.ID = "test-jti"

	record := &model.AgEventRecord{
		Jti:      event.ID,
		Event:    *event,
		Original: `{"jti":"test-jti"}`,
		Types:    []string{"test"},
		Sid:      "stream-1",
		SortTime: time.Now(),
	}

	err := dao.Insert(ctx, record)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Verify insertion
	retrieved, err := dao.FindByJTI(ctx, "test-jti")
	if err != nil {
		t.Fatalf("FindByJTI failed: %v", err)
	}

	if retrieved.Jti != "test-jti" {
		t.Errorf("Expected JTI test-jti, got %s", retrieved.Jti)
	}
}

func TestEventDAOMemory_FindByJTIs(t *testing.T) {
	dao := NewEventDAO()
	ctx := context.Background()

	// Insert multiple events
	jtis := []string{"jti-1", "jti-2", "jti-3"}
	for _, jti := range jtis {
		event := &goSet.SecurityEventToken{Events: map[string]interface{}{"test": "event"}}
		event.ID = jti

		record := &model.AgEventRecord{
			Jti:      jti,
			Event:    *event,
			Original: `{"jti":"` + jti + `"}`,
			SortTime: time.Now(),
		}
		_ = dao.Insert(ctx, record)
	}

	// Find by multiple JTIs
	records, err := dao.FindByJTIs(ctx, []string{"jti-1", "jti-3"})
	if err != nil {
		t.Fatalf("FindByJTIs failed: %v", err)
	}

	if len(records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(records))
	}
}

func TestEventDAOMemory_AddPending(t *testing.T) {
	dao := NewEventDAO()
	ctx := context.Background()

	// Insert an event first
	event := &goSet.SecurityEventToken{Events: map[string]interface{}{"test": "event"}}
	event.ID = "test-jti"

	record := &model.AgEventRecord{
		Jti:      event.ID,
		Event:    *event,
		SortTime: time.Now(),
	}
	_ = dao.Insert(ctx, record)

	// Add to pending
	streamID := bson.NewObjectID()
	err := dao.AddPending(ctx, "test-jti", streamID)
	if err != nil {
		t.Fatalf("AddPending failed: %v", err)
	}

	// Verify pending
	jtis, total, err := dao.GetPendingForStream(ctx, streamID.Hex(), 10)
	if err != nil {
		t.Fatalf("GetPendingForStream failed: %v", err)
	}

	if len(jtis) != 1 {
		t.Errorf("Expected 1 pending event, got %d", len(jtis))
	}

	if total != 1 {
		t.Errorf("Expected total 1, got %d", total)
	}

	if jtis[0] != "test-jti" {
		t.Errorf("Expected JTI test-jti, got %s", jtis[0])
	}
}

func TestEventDAOMemory_RemovePending(t *testing.T) {
	dao := NewEventDAO()
	ctx := context.Background()

	// Setup: Insert event and add to pending
	event := &goSet.SecurityEventToken{Events: map[string]interface{}{"test": "event"}}
	event.ID = "test-jti"

	record := &model.AgEventRecord{
		Jti:      event.ID,
		Event:    *event,
		SortTime: time.Now(),
	}
	_ = dao.Insert(ctx, record)

	streamID := bson.NewObjectID()
	_ = dao.AddPending(ctx, "test-jti", streamID)

	// Remove from pending
	removed, err := dao.RemovePending(ctx, "test-jti", streamID.Hex())
	if err != nil {
		t.Fatalf("RemovePending failed: %v", err)
	}

	if removed == nil {
		t.Fatal("Expected removed event, got nil")
	}

	if removed.Jti != "test-jti" {
		t.Errorf("Expected JTI test-jti, got %s", removed.Jti)
	}

	// Verify removal
	jtis, _, _ := dao.GetPendingForStream(ctx, streamID.Hex(), 10)
	if len(jtis) != 0 {
		t.Errorf("Expected 0 pending events after removal, got %d", len(jtis))
	}
}

func TestEventDAOMemory_MarkDelivered(t *testing.T) {
	dao := NewEventDAO()
	ctx := context.Background()

	streamID := bson.NewObjectID()
	deliverable := &interfaces.DeliverableEvent{
		Jti:      "test-jti",
		StreamId: streamID,
	}

	err := dao.MarkDelivered(ctx, deliverable, time.Now())
	if err != nil {
		t.Fatalf("MarkDelivered failed: %v", err)
	}

	// Note: We can't verify delivered events without exposing internal state
	// This is acceptable for a unit test
}

func TestEventDAOMemory_ClearPendingForStream(t *testing.T) {
	dao := NewEventDAO()
	ctx := context.Background()

	// Setup: Add multiple pending events
	streamID := bson.NewObjectID()
	for i := 1; i <= 3; i++ {
		event := &goSet.SecurityEventToken{Events: map[string]interface{}{"test": "event"}}
		jti := bson.NewObjectID().Hex()
		event.ID = jti

		record := &model.AgEventRecord{
			Jti:      jti,
			Event:    *event,
			SortTime: time.Now(),
		}
		_ = dao.Insert(ctx, record)
		_ = dao.AddPending(ctx, jti, streamID)
	}

	// Clear pending
	count, err := dao.ClearPendingForStream(ctx, streamID.Hex())
	if err != nil {
		t.Fatalf("ClearPendingForStream failed: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected 3 cleared events, got %d", count)
	}

	// Verify clearing
	jtis, _, _ := dao.GetPendingForStream(ctx, streamID.Hex(), 10)
	if len(jtis) != 0 {
		t.Errorf("Expected 0 pending events after clear, got %d", len(jtis))
	}
}

func TestEventDAOMemory_FindByTimeRange(t *testing.T) {
	dao := NewEventDAO()
	ctx := context.Background()

	// Use truncated times to match JWT NumericDate behavior
	now := time.Now().Truncate(time.Second)
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	// Insert events with different times
	events := []struct {
		jti  string
		time time.Time
	}{
		{"jti-past", past},
		{"jti-now", now},
		{"jti-future", future},
	}

	for _, e := range events {
		event := &goSet.SecurityEventToken{Events: map[string]interface{}{"test": "event"}}
		event.ID = e.jti

		record := &model.AgEventRecord{
			Jti:      e.jti,
			Event:    *event,
			SortTime: e.time,
		}
		_ = dao.Insert(ctx, record)
	}

	// Find events from now onwards
	records, err := dao.FindByTimeRange(ctx, now, nil, nil)
	if err != nil {
		t.Fatalf("FindByTimeRange failed: %v", err)
	}

	if len(records) != 2 { // now and future
		t.Errorf("Expected 2 records, got %d", len(records))
	}

	// Find events in range (past to future)
	records, err = dao.FindByTimeRange(ctx, past, &future, nil)
	if err != nil {
		t.Fatalf("FindByTimeRange with end failed: %v", err)
	}

	if len(records) != 3 { // past, now, and future
		t.Errorf("Expected 3 records in range, got %d", len(records))
	}
}

func TestEventDAOMemory_GetPendingForStream_Limit(t *testing.T) {
	dao := NewEventDAO()
	ctx := context.Background()

	streamID := bson.NewObjectID()

	// Add 5 pending events
	for i := 1; i <= 5; i++ {
		event := &goSet.SecurityEventToken{Events: map[string]interface{}{"test": "event"}}
		jti := bson.NewObjectID().Hex()
		event.ID = jti

		record := &model.AgEventRecord{
			Jti:      jti,
			Event:    *event,
			SortTime: time.Now(),
		}
		_ = dao.Insert(ctx, record)
		_ = dao.AddPending(ctx, jti, streamID)
	}

	// Get with limit
	jtis, total, err := dao.GetPendingForStream(ctx, streamID.Hex(), 3)
	if err != nil {
		t.Fatalf("GetPendingForStream with limit failed: %v", err)
	}

	if len(jtis) != 3 {
		t.Errorf("Expected 3 JTIs (limit), got %d", len(jtis))
	}

	if total != 5 {
		t.Errorf("Expected total 5, got %d", total)
	}
}
