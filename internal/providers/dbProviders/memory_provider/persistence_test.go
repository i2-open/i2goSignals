package memory_provider

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPersistence(t *testing.T) {
	// Setup temporary directory
	tmpDir := t.TempDir()

	t.Setenv(CEnvMemDir, tmpDir)
	t.Setenv(CEnvMemSaveRate, "0") // Save every change

	dbName := "testPersistence"
	provider, err := Open("memorydb:", dbName)
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Create a stream
	streamReq := model.StreamConfiguration{
		Aud: []string{"test-aud"},
	}
	authCtx := authUtil.ConvertProject("test-project")
	ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authCtx)
	createdStream, err := provider.streamService.CreateStream(ctx, streamReq, authCtx.ProjectId, nil)
	assert.NoError(t, err)
	streamID := createdStream.Id

	// Add an event
	set := goSet.CreateSet(nil, "issuer", []string{"test-aud"})
	eventRec, err := provider.eventService.AddEvent(context.Background(), &set, streamID, "raw-token")
	assert.NoError(t, err)
	assert.NotNil(t, eventRec)

	// Verify files exist
	assert.FileExists(t, filepath.Join(tmpDir, "streams.json"))
	assert.FileExists(t, filepath.Join(tmpDir, "events", eventRec.Jti+".set"))

	// Close and re-open
	err = provider.Close()
	assert.NoError(t, err)

	provider2, err := Open("memorydb:", dbName)
	require.NoError(t, err)
	defer func(provider2 *MemoryProvider) {
		_ = provider2.Close()
	}(provider2)

	// Verify state reloaded
	streams := provider2.streamService.ListStreams(context.Background())
	assert.Len(t, streams, 1)
	assert.Equal(t, streamID, streams[0].Id)

	eventRec2 := provider2.eventService.GetEventRecord(context.Background(), eventRec.Jti)
	assert.NotNil(t, eventRec2)
	assert.Equal(t, eventRec.Jti, eventRec2.Jti)
	// Verify memory protection (Original should be empty in memory, but reloaded when requested)
	assert.Equal(t, "raw-token", eventRec2.Original)

	// Verify full event can still be retrieved
	fullEvent := provider2.eventService.GetEvent(context.Background(), eventRec.Jti)
	assert.NotNil(t, fullEvent)
	assert.Equal(t, eventRec.Jti, fullEvent.ID)
}

func TestMemoryProtection(t *testing.T) {
	tmpDir := t.TempDir()

	t.Setenv(CEnvMemDir, tmpDir)
	t.Setenv(CEnvMemSaveRate, "0")

	provider, err := Open("memorydb:", "testMemProt")
	require.NoError(t, err)
	defer func(provider *MemoryProvider) {
		_ = provider.Close()
	}(provider)

	// Add an event with large raw content
	largeRaw := "raw-token-" + string(make([]byte, 10000))
	set := goSet.CreateSet(nil, "issuer", []string{"aud"})
	eventRec, err := provider.eventService.AddEvent(context.Background(), &set, "test-stream", largeRaw)
	assert.NoError(t, err)

	// Fetching through GetEventRecord should reload it
	eventRec2 := provider.eventService.GetEventRecord(context.Background(), eventRec.Jti)
	assert.Equal(t, largeRaw, eventRec2.Original)
}
