package eventRouter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
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
		require.NoError(t, r.eventService.AddEventToStream(context.Background(), refOf(fmt.Sprintf("jti-wake-%d", i)), sid))
	}

	// The loop is busy: its buffer already holds the oldest pending SET.
	eventBuf := buffer.CreateEventPushBuffer([]string{"jti-wake-1"})
	// No runner reads Out here, so close and then drain the buffer the way
	// drainPushBufferWhenFinished does for a stopped runner; its pump exits
	// only once everything queued has been read.
	t.Cleanup(func() {
		eventBuf.Close()
		for range eventBuf.Out {
		}
	})

	r.backfillPushBufferOnWake(sid, eventBuf)

	want := []string{"jti-wake-1", "jti-wake-2", "jti-wake-3", "jti-wake-4", "jti-wake-5"}
	require.Eventually(t, func() bool { return len(eventBuf.Queued()) == len(want) }, time.Second, time.Millisecond)
	assert.ElementsMatch(t, want, eventBuf.Queued(), "every pending SET is queued once")
}

// #347 review: one wake's backfill is capped (maxWakeBackfillBatches), so a
// burst deeper than the cap left its tail to the backfill ticker, which only
// refilled an empty buffer one batch per tick. The push loop keeps reading
// while the last read was full, so the whole burst is delivered without
// waiting on the ticker.
func TestPushLoop_WakeBurstPastTheCapIsFullyDelivered(t *testing.T) {
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	seam := newPipelineSeam(time.Millisecond)
	h := newPipelineHarness(t, seam, "2")
	// The ticker never fires inside the test: only the wake path delivers.
	h.router.backfillInterval = time.Hour
	h.router.backfillBatch = 2

	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	h.router.UpdateStreamState(stream.DeepCopy())
	// One SET through proves the loop holds the lease and is idle in its select.
	h.addPendingEvents(t, sid, 1)
	h.router.WakeTransmitter(sid, "push")
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 5*time.Second, 5*time.Millisecond)

	const burst = 2*maxWakeBackfillBatches*2 + 7
	jtis := h.addPendingEvents(t, sid, burst)
	h.router.WakeTransmitter(sid, "push")

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 5*time.Second, 10*time.Millisecond,
		"the tail past one wake's cap is delivered without the ticker")
	_, _, accepted := seam.snapshot()
	for _, jti := range jtis {
		assert.Equal(t, 1, accepted[jti], "jti %s is delivered once", jti)
	}
}
