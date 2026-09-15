package memory

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func TestStreamDAOMemory_Create(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()

	streamState := &model.StreamStateRecord{
		Id:        model.NewRecordId(),
		ProjectId: "test-project",
		StreamConfiguration: model.StreamConfiguration{
			Id:  "stream-1",
			Iss: "test-issuer",
			Aud: []string{"test-audience"},
		},
		Status:    model.StreamStateEnabled,
		CreatedAt: time.Now(),
	}

	err := dao.Create(ctx, streamState)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify creation
	retrieved, err := dao.FindByID(ctx, "stream-1")
	if err != nil {
		t.Fatalf("FindByID failed: %v", err)
	}

	if retrieved.StreamConfiguration.Id != "stream-1" {
		t.Errorf("Expected ID stream-1, got %s", retrieved.StreamConfiguration.Id)
	}
}

func TestStreamDAOMemory_FindByID_NotFound(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()

	_, err := dao.FindByID(ctx, "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent stream, got nil")
	}
}

func TestStreamDAOMemory_Update(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()

	streamState := &model.StreamStateRecord{
		Id:        model.NewRecordId(),
		ProjectId: "test-project",
		StreamConfiguration: model.StreamConfiguration{
			Id:     "stream-1",
			Iss:    "test-issuer",
			Format: "opaque",
		},
		Status:    model.StreamStateEnabled,
		CreatedAt: time.Now(),
	}

	_ = dao.Create(ctx, streamState)

	// Update
	streamState.StreamConfiguration.Format = "email"
	err := dao.Update(ctx, streamState)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Verify update
	retrieved, _ := dao.FindByID(ctx, "stream-1")
	if retrieved.StreamConfiguration.Format != "email" {
		t.Errorf("Expected Format email, got %s", retrieved.StreamConfiguration.Format)
	}
}

func TestStreamDAOMemory_Delete(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()

	streamState := &model.StreamStateRecord{
		Id:        model.NewRecordId(),
		ProjectId: "test-project",
		StreamConfiguration: model.StreamConfiguration{
			Id:  "stream-1",
			Iss: "test-issuer",
		},
		Status:    model.StreamStateEnabled,
		CreatedAt: time.Now(),
	}

	_ = dao.Create(ctx, streamState)

	// Delete
	err := dao.Delete(ctx, "stream-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deletion
	_, err = dao.FindByID(ctx, "stream-1")
	if err == nil {
		t.Error("Expected error after deletion, got nil")
	}
}

func TestStreamDAOMemory_List(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()

	// Create multiple streams
	for i := 1; i <= 3; i++ {
		streamState := &model.StreamStateRecord{
			Id:        model.NewRecordId(),
			ProjectId: "test-project",
			StreamConfiguration: model.StreamConfiguration{
				Id:  ids.NewObjectID(),
				Iss: "test-issuer",
			},
			Status:    model.StreamStateEnabled,
			CreatedAt: time.Now(),
		}
		_ = dao.Create(ctx, streamState)
	}

	// List
	streams, err := dao.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(streams) != 3 {
		t.Errorf("Expected 3 streams, got %d", len(streams))
	}
}

func TestStreamDAOMemory_FindByProjectID(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()

	// Create streams with different project IDs
	projects := []string{"project-1", "project-1", "project-2"}
	for _, projectId := range projects {
		streamState := &model.StreamStateRecord{
			Id:        model.NewRecordId(),
			ProjectId: projectId,
			StreamConfiguration: model.StreamConfiguration{
				Id:  ids.NewObjectID(),
				Iss: "test-issuer",
			},
			Status:    model.StreamStateEnabled,
			CreatedAt: time.Now(),
		}
		_ = dao.Create(ctx, streamState)
	}

	// Find by project ID
	streams, err := dao.FindByProjectID(ctx, "project-1")
	if err != nil {
		t.Fatalf("FindByProjectID failed: %v", err)
	}

	if len(streams) != 2 {
		t.Errorf("Expected 2 streams for project-1, got %d", len(streams))
	}
}

func TestStreamDAOMemory_UpdateStatus(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()

	streamState := &model.StreamStateRecord{
		Id:        model.NewRecordId(),
		ProjectId: "test-project",
		StreamConfiguration: model.StreamConfiguration{
			Id:  "stream-1",
			Iss: "test-issuer",
		},
		Status:    model.StreamStateEnabled,
		CreatedAt: time.Now(),
	}

	_ = dao.Create(ctx, streamState)

	// Update status
	err := dao.UpdateStatus(ctx, "stream-1", model.StreamStatePause, "test error")
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	// Verify status update
	retrieved, _ := dao.FindByID(ctx, "stream-1")
	if retrieved.Status != model.StreamStatePause {
		t.Errorf("Expected status %s, got %s", model.StreamStatePause, retrieved.Status)
	}
	if retrieved.ErrorMsg != "test error" {
		t.Errorf("Expected error msg 'test error', got '%s'", retrieved.ErrorMsg)
	}
}

// TestStreamDAOMemory_TransmitterCausedStatus (#310): the transmitter-caused
// write stores the flag with the status, and an ordinary UpdateStatus clears it.
func TestStreamDAOMemory_TransmitterCausedStatus(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()
	_ = dao.Create(ctx, &model.StreamStateRecord{
		Id:                  model.NewRecordId(),
		StreamConfiguration: model.StreamConfiguration{Id: "rcv-1"},
		Status:              model.StreamStateEnabled,
	})

	if err := dao.UpdateTransmitterCausedStatus(ctx, "rcv-1", model.StreamStatePause, "Transmitter stream is paused: x"); err != nil {
		t.Fatalf("UpdateTransmitterCausedStatus failed: %v", err)
	}
	got, _ := dao.FindByID(ctx, "rcv-1")
	if got.Status != model.StreamStatePause || got.ErrorMsg != "Transmitter stream is paused: x" || !got.TransmitterCaused {
		t.Fatalf("got %q / %q / flag=%v, want paused with reason and flag", got.Status, got.ErrorMsg, got.TransmitterCaused)
	}

	if err := dao.UpdateStatus(ctx, "rcv-1", model.StreamStatePause, "operator"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}
	got, _ = dao.FindByID(ctx, "rcv-1")
	if got.TransmitterCaused {
		t.Error("UpdateStatus must clear the flag")
	}

	if err := dao.UpdateTransmitterCausedStatus(ctx, "missing", model.StreamStateDisable, "x"); err == nil {
		t.Error("expected an error for an unknown stream")
	}
}

// TestStreamDAOMemory_KeyUnavailablePause (#312): the key-unavailable pause
// stores paused, the reason and the marker; a repeat pause keeps the first
// failure's time; every other status write clears the marker.
func TestStreamDAOMemory_KeyUnavailablePause(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()
	_ = dao.Create(ctx, &model.StreamStateRecord{
		Id:                  model.NewRecordId(),
		StreamConfiguration: model.StreamConfiguration{Id: "poll-1"},
		Status:              model.StreamStateEnabled,
		TransmitterCaused:   true,
	})
	first := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	if err := dao.UpdateKeyUnavailablePause(ctx, "poll-1", "POLL-SRV: no key", first); err != nil {
		t.Fatalf("UpdateKeyUnavailablePause failed: %v", err)
	}
	got, _ := dao.FindByID(ctx, "poll-1")
	if got.Status != model.StreamStatePause || got.ErrorMsg != "POLL-SRV: no key" || got.KeyUnavailableSince == nil || !got.KeyUnavailableSince.Equal(first) {
		t.Fatalf("got %q / %q / marker=%v, want paused with reason and marker %v", got.Status, got.ErrorMsg, got.KeyUnavailableSince, first)
	}
	if got.TransmitterCaused {
		t.Error("a key-unavailable pause clears transmitter_caused")
	}

	if err := dao.UpdateKeyUnavailablePause(ctx, "poll-1", "POLL-SRV: no key", first.Add(time.Minute)); err != nil {
		t.Fatalf("repeat UpdateKeyUnavailablePause failed: %v", err)
	}
	got, _ = dao.FindByID(ctx, "poll-1")
	if !got.KeyUnavailableSince.Equal(first) {
		t.Errorf("a repeat failure moved the marker to %v", got.KeyUnavailableSince)
	}

	if err := dao.UpdateStatus(ctx, "poll-1", model.StreamStatePause, "operator"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}
	got, _ = dao.FindByID(ctx, "poll-1")
	if got.KeyUnavailableSince != nil {
		t.Error("UpdateStatus must clear the marker")
	}

	_ = dao.UpdateKeyUnavailablePause(ctx, "poll-1", "POLL-SRV: no key", first)
	if err := dao.UpdateTransmitterCausedStatus(ctx, "poll-1", model.StreamStatePause, "x"); err != nil {
		t.Fatalf("UpdateTransmitterCausedStatus failed: %v", err)
	}
	got, _ = dao.FindByID(ctx, "poll-1")
	if got.KeyUnavailableSince != nil {
		t.Error("UpdateTransmitterCausedStatus must clear the marker")
	}

	if err := dao.UpdateKeyUnavailablePause(ctx, "missing", "x", first); err == nil {
		t.Error("expected an error for an unknown stream")
	}
}

func TestStreamDAOMemory_UpdateRemoteAddress(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()

	streamState := &model.StreamStateRecord{
		Id:        model.NewRecordId(),
		ProjectId: "test-project",
		StreamConfiguration: model.StreamConfiguration{
			Id:  "stream-remote",
			Iss: "test-issuer",
		},
		Status:    model.StreamStateEnabled,
		CreatedAt: time.Now(),
	}
	_ = dao.Create(ctx, streamState)

	addr := &model.RemoteIP{
		Protocol:  "https",
		IP:        "10.1.2.3:443",
		Forwarded: "203.0.113.1",
	}

	err := dao.UpdateRemoteAddress(ctx, "stream-remote", addr)
	if err != nil {
		t.Fatalf("UpdateRemoteAddress failed: %v", err)
	}

	retrieved, _ := dao.FindByID(ctx, "stream-remote")
	if retrieved.RemoteAddress == nil {
		t.Fatal("expected RemoteAddress to be set, got nil")
	}
	if retrieved.RemoteAddress.Protocol != "https" {
		t.Errorf("expected Protocol https, got %s", retrieved.RemoteAddress.Protocol)
	}
	if retrieved.RemoteAddress.IP != "10.1.2.3:443" {
		t.Errorf("expected IP 10.1.2.3:443, got %s", retrieved.RemoteAddress.IP)
	}
	if retrieved.RemoteAddress.Forwarded != "203.0.113.1" {
		t.Errorf("expected Forwarded 203.0.113.1, got %s", retrieved.RemoteAddress.Forwarded)
	}
}
