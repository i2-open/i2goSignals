package eventRouter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Retraction is the compensating half of the ADR 0038 ingest contract: a
// speculative marker whose body the concurrent write rejected is deleted again
// before anything can act on it. RetractPending deletes the NEWEST marker for a
// JTI, which is what makes a re-sent still-pending SET keep its real delivery
// intent — and it is also why retraction must never run for a target whose own
// marker write failed. There is nothing of ours to undo in that case, so the
// delete would consume an older, still-undelivered intent instead.

func pendingJtis(t *testing.T, h *filterPushHarness, sid string) []string {
	t.Helper()
	jtis, _ := h.eventService.GetEventIds(context.Background(), sid, model.PollParameters{
		MaxEvents:         100,
		ReturnImmediately: true,
	})
	return jtis
}

// TestCommitFanout_FailedMarkerWriteDoesNotRetract is the regression: the
// pre-existing intent survives when this batch never wrote a marker of its own.
func TestCommitFanout_FailedMarkerWriteDoesNotRetract(t *testing.T) {
	h := newFilterPushRouter(t)
	stream := h.createPushStream(t, "")
	sid := stream.StreamConfiguration.Id

	// The real, already-accepted delivery intent for a JTI that is still
	// undelivered — what a re-send of the same SET would collide with.
	const jti = "jti-real-intent"
	require.NoError(t, h.eventService.AddEventToStream(context.Background(), jti, stream.Id.Hex()))
	require.Equal(t, []string{jti}, pendingJtis(t, h, sid))

	// queued:false is what queueMatchingLocked records when AddEventsToStream
	// failed. The body write then rejects the JTI as a duplicate, so it lands
	// in the commit phase's drop set with no marker of its own to retract.
	target := &fanoutTarget{
		mode:   "PUSH",
		key:    sid,
		docID:  stream.Id.Hex(),
		stream: *stream,
		jtis:   []string{jti},
		queued: false,
	}

	h.router.mu.RLock()
	h.router.commitFanoutLocked([]*fanoutTarget{target}, map[string]*model.EventRecord{})
	h.router.mu.RUnlock()

	require.Equal(t, []string{jti}, pendingJtis(t, h, sid),
		"a failed marker write must not retract an older delivery intent for the same JTI")
}

// TestCommitFanout_SpeculativeMarkerIsRetracted is the other half: when this
// batch did write the marker, the rejected candidate's intent is withdrawn.
func TestCommitFanout_SpeculativeMarkerIsRetracted(t *testing.T) {
	h := newFilterPushRouter(t)
	stream := h.createPushStream(t, "")
	sid := stream.StreamConfiguration.Id

	const jti = "jti-speculative"
	require.NoError(t, h.eventService.AddEventToStream(context.Background(), jti, stream.Id.Hex()))
	require.Equal(t, []string{jti}, pendingJtis(t, h, sid))

	target := &fanoutTarget{
		mode:   "PUSH",
		key:    sid,
		docID:  stream.Id.Hex(),
		stream: *stream,
		jtis:   []string{jti},
		queued: true,
	}

	h.router.mu.RLock()
	h.router.commitFanoutLocked([]*fanoutTarget{target}, map[string]*model.EventRecord{})
	h.router.mu.RUnlock()

	require.Empty(t, pendingJtis(t, h, sid),
		"a marker this batch wrote for a rejected candidate must be retracted")
}

// TestCommitFanout_MissingBufferDoesNotPanic covers the window the two-phase
// fan-out opened. planFanoutLocked sees the stream under one RLock, r.mu is
// released across the body-write join, and RemoveStream can delete the buffer
// before commitFanoutLocked retakes the lock. The markers are already durable,
// so backfill still delivers them; the wake-up is simply skipped.
func TestCommitFanout_MissingBufferDoesNotPanic(t *testing.T) {
	h := newFilterPushRouter(t)
	stream := h.createPushStream(t, "")
	sid := stream.StreamConfiguration.Id

	// The stream and its buffer are gone, exactly as a DELETE /stream mid-join
	// would leave them, but the planned target still names them.
	h.router.RemoveStream(sid)

	const jti = "jti-buffer-gone"
	accepted := map[string]*model.EventRecord{
		jti: {Jti: jti, Sid: sid},
	}

	for _, mode := range []string{"PUSH", "POLL"} {
		t.Run(mode, func(t *testing.T) {
			target := &fanoutTarget{
				mode:   mode,
				key:    sid,
				docID:  stream.Id.Hex(),
				stream: *stream,
				jtis:   []string{jti},
				queued: true,
			}
			require.NotPanics(t, func() {
				h.router.mu.RLock()
				defer h.router.mu.RUnlock()
				h.router.commitFanoutLocked([]*fanoutTarget{target}, accepted)
			}, "a target whose buffer was removed across the join must not panic")
		})
	}
}
