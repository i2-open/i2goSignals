package memory

import (
	"context"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func insertBody(t *testing.T, dao *EventDAOMemory, jti string) {
	t.Helper()
	ev := &goSet.SecurityEventToken{Events: map[string]interface{}{"test": "e"}}
	ev.ID = jti
	rec := &model.EventRecord{Jti: jti, Event: *ev, SortTime: time.Now()}
	if err := dao.Insert(context.Background(), rec); err != nil {
		t.Fatalf("insert %s: %v", jti, err)
	}
}

func markDelivered(t *testing.T, dao *EventDAOMemory, jti, streamID string, ack time.Time) {
	t.Helper()
	err := dao.MarkDelivered(context.Background(), &interfaces.DeliverableEvent{Jti: jti, StreamId: streamID}, ack)
	if err != nil {
		t.Fatalf("mark delivered %s/%s: %v", jti, streamID, err)
	}
}

func TestEventDAOMemory_ListDeliveredForStream(t *testing.T) {
	ctx := context.Background()
	dao := NewEventDAO()
	ack := time.Now()
	insertBody(t, dao, "j1")
	markDelivered(t, dao, "j1", "s1", ack)

	got, err := dao.ListDeliveredForStream(ctx, "s1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Jti != "j1" || !got[0].AckDate.Equal(ack) {
		t.Fatalf("unexpected delivered list: %#v", got)
	}
	if empty, _ := dao.ListDeliveredForStream(ctx, "other"); len(empty) != 0 {
		t.Fatalf("expected no delivered for unknown stream, got %#v", empty)
	}
}

func TestEventDAOMemory_CountRetainedForStream(t *testing.T) {
	ctx := context.Background()
	dao := NewEventDAO()
	now := time.Now()
	insertBody(t, dao, "j1")
	insertBody(t, dao, "j2")
	markDelivered(t, dao, "j1", "s1", now)
	markDelivered(t, dao, "j2", "s1", now)

	n, err := dao.CountRetainedForStream(ctx, "s1")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 retained, got %d", n)
	}
}

func TestEventDAOMemory_RemoveDelivered_LeavesBody(t *testing.T) {
	ctx := context.Background()
	dao := NewEventDAO()
	insertBody(t, dao, "j1")
	markDelivered(t, dao, "j1", "s1", time.Now())

	if err := dao.RemoveDelivered(ctx, "j1", "s1"); err != nil {
		t.Fatalf("remove delivered: %v", err)
	}
	if n, _ := dao.CountRetainedForStream(ctx, "s1"); n != 0 {
		t.Fatalf("expected delivered entry removed, count=%d", n)
	}
	// Body must survive until a refcount-gated delete.
	if rec, _ := dao.FindByJTI(ctx, "j1"); rec == nil {
		t.Fatalf("RemoveDelivered must not delete the global body")
	}
	// Removing a non-existent entry is not an error.
	if err := dao.RemoveDelivered(ctx, "nope", "s1"); err != nil {
		t.Fatalf("remove missing: %v", err)
	}
}

func TestEventDAOMemory_DeleteBodyIfUnreferenced_Refcount(t *testing.T) {
	ctx := context.Background()
	dao := NewEventDAO()
	insertBody(t, dao, "j1")
	markDelivered(t, dao, "j1", "s1", time.Now())
	markDelivered(t, dao, "j1", "s2", time.Now())

	// Referenced by s2's delivered entry — must not delete.
	if err := dao.RemoveDelivered(ctx, "j1", "s1"); err != nil {
		t.Fatalf("remove s1: %v", err)
	}
	deleted, err := dao.DeleteBodyIfUnreferenced(ctx, "j1")
	if err != nil {
		t.Fatalf("delete-if-unref: %v", err)
	}
	if deleted {
		t.Fatalf("body must survive while s2 still references it")
	}
	if rec, _ := dao.FindByJTI(ctx, "j1"); rec == nil {
		t.Fatalf("body wrongly deleted while referenced")
	}

	// Drop the last reference — now it deletes.
	if err := dao.RemoveDelivered(ctx, "j1", "s2"); err != nil {
		t.Fatalf("remove s2: %v", err)
	}
	deleted, err = dao.DeleteBodyIfUnreferenced(ctx, "j1")
	if err != nil {
		t.Fatalf("delete-if-unref (2): %v", err)
	}
	if !deleted {
		t.Fatalf("body should be deleted once unreferenced")
	}
	if rec, _ := dao.FindByJTI(ctx, "j1"); rec != nil {
		t.Fatalf("body should be gone")
	}
}

func TestEventDAOMemory_DeleteBodyIfUnreferenced_PendingHolds(t *testing.T) {
	ctx := context.Background()
	dao := NewEventDAO()
	insertBody(t, dao, "j1")
	if err := dao.AddPending(ctx, "j1", "s1"); err != nil {
		t.Fatalf("add pending: %v", err)
	}

	// A still-pending JTI must keep its body (pending is never purged).
	deleted, err := dao.DeleteBodyIfUnreferenced(ctx, "j1")
	if err != nil {
		t.Fatalf("delete-if-unref: %v", err)
	}
	if deleted {
		t.Fatalf("pending reference must hold the body")
	}
	if rec, _ := dao.FindByJTI(ctx, "j1"); rec == nil {
		t.Fatalf("pending body wrongly deleted")
	}
}
