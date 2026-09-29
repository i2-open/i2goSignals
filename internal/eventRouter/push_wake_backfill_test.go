package eventRouter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #347: a cross-node wake says only "this stream has work". The push loop's
// backfill used to return at once whenever its buffer held anything, so a
// wake announcing a SET another node had written was dropped whenever the
// loop was busy, and the SET waited for the buffer to drain and the next
// backfill tick. On a wake the backfill is level-triggered: it reads the
// store past what is already queued or in flight, and keeps reading until a
// short read, so every pending SET is queued exactly once.
func TestBackfillOnWake_QueuesPendingPastABusyBuffer(t *testing.T) {
	h := newTestRouter(t)
	r := h.router
	r.backfillBatch = 2

	const sid = "push-wake-backfill"
	for i := 1; i <= 5; i++ {
		require.NoError(t, r.eventService.AddEventToStream(context.Background(), fmt.Sprintf("jti-wake-%d", i), sid))
	}

	// The loop is busy: its buffer already holds the oldest pending SET.
	eventBuf := buffer.CreateEventPushBuffer([]string{"jti-wake-1"})
	t.Cleanup(eventBuf.Close)

	r.backfillPushBufferOnWake(sid, eventBuf)

	want := []string{"jti-wake-1", "jti-wake-2", "jti-wake-3", "jti-wake-4", "jti-wake-5"}
	require.Eventually(t, func() bool { return len(eventBuf.Queued()) == len(want) }, time.Second, time.Millisecond)
	assert.ElementsMatch(t, want, eventBuf.Queued(), "every pending SET is queued once")
}
