package services

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cachedTransmitterCaused reads the flag off this node's receiver cache copy of
// sid, which the poll loop's JWKS lookups read.
func cachedTransmitterCaused(t *testing.T, svc *StreamService, sid string) (status string, flag bool) {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	entry, ok := svc.receiverStreams[sid]
	require.True(t, ok, "receiver %s must be cached", sid)
	return entry.record.Status, entry.record.TransmitterCaused
}

// TestUpdateTransmitterCausedStatus_SetsAndOrdinaryWriteClears (#310): the
// transmitter-caused write stores the flag with the status on the stream store
// and on the receiver cache copy, and an ordinary UpdateStreamStatus (an
// operator's POST /status, or the poll loop's own enabled and retry-limit
// writes) clears it on both.
func TestUpdateTransmitterCausedStatus_SetsAndOrdinaryWriteClears(t *testing.T) {
	h := newRetryHarness(t)
	ctx := context.Background()
	rec := newReceiverFixture(t, model.ReceivePoll, model.RouteModeImport, "transmitter-caused")
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id
	h.svc.LoadReceiverStreams(ctx)

	h.svc.UpdateTransmitterCausedStatus(ctx, sid, model.StreamStatePause, "Transmitter stream is paused: maintenance")

	stored, err := h.svc.GetStreamState(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, stored.Status)
	assert.Equal(t, "Transmitter stream is paused: maintenance", stored.ErrorMsg)
	assert.True(t, stored.TransmitterCaused, "stored record carries the flag")
	status, flag := cachedTransmitterCaused(t, h.svc, sid)
	assert.Equal(t, model.StreamStatePause, status)
	assert.True(t, flag, "receiver cache copy carries the flag")

	h.svc.UpdateStreamStatus(ctx, sid, model.StreamStatePause, "operator pause")

	stored, err = h.svc.GetStreamState(ctx, sid)
	require.NoError(t, err)
	assert.False(t, stored.TransmitterCaused, "an ordinary status write clears the stored flag")
	_, flag = cachedTransmitterCaused(t, h.svc, sid)
	assert.False(t, flag, "an ordinary status write clears the cached flag")
}
