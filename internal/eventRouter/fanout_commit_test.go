package eventRouter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// The ingest write stores a SET's body and its pending markers together (ADR
// 0043), so a marker only ever exists for a SET whose body was accepted. The
// commit phase therefore has nothing to retract: it only meters and wakes the
// accepted SETs, and must leave every marker — including an older intent for a
// JTI this batch saw rejected — exactly as it found it.

func pendingJtis(t *testing.T, h *filterPushHarness, sid string) []string {
	t.Helper()
	jtis, _ := h.eventService.GetEventIds(context.Background(), sid, model.PollParameters{
		MaxEvents:         100,
		ReturnImmediately: true,
	})
	return jtis
}

// TestIngest_ResentPendingSetKeepsOneIntent: a SET re-sent while its first copy
// is still undelivered is a duplicate, so the one-trip write adds no second
// marker and the original delivery intent survives untouched.
func TestIngest_ResentPendingSetKeepsOneIntent(t *testing.T) {
	s := setupDedupRouterPollStream(t)
	token := newRiscToken("resent-pending", dupTestIssuer, s.audience)
	ids := func() []string {
		jtis, _ := s.h.router.eventService.GetEventIds(context.Background(), s.streamID, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
		return jtis
	}

	require.NoError(t, s.h.router.HandleEvent(token, `{"first":true}`, s.streamID))
	require.Eventually(t, func() bool { return len(ids()) == 1 }, time.Second, 5*time.Millisecond)

	require.NoError(t, s.h.router.HandleEvent(token, `{"second":true}`, s.streamID),
		"a duplicate is acked (idempotent 202)")
	require.Equal(t, []string{"resent-pending"}, ids(),
		"a re-sent duplicate must neither add a second marker nor remove the first")
}

// TestReconcileIngest_NoAckWithoutBodyAndMarkers pins ADR 0038's contract at
// the router: a SET whose ingest write failed — body or pending marker — is
// answered ErrStoreUnavailable (503, never acked) and is not accepted for
// fan-out; a duplicate is acked without fan-out; only a SET whose body and
// markers are both durable is accepted.
func TestReconcileIngest_NoAckWithoutBodyAndMarkers(t *testing.T) {
	h := newFilterPushRouter(t)
	stream := h.createPushStream(t, "")

	tokens := []*goSet.SecurityEventToken{{}, {}, {}}
	recs := []*model.EventRecord{{Jti: "ok"}, nil, {Jti: "dup"}}
	errs := []error{nil, errors.New("pending marker write failed: boom"), interfaces.ErrDuplicateJTI}
	results := make([]error, len(recs))

	accepted := h.router.reconcileIngest(recs, errs, results, stream, tokens)

	require.NoError(t, results[0])
	require.ErrorIs(t, results[1], ErrStoreUnavailable, "a failed marker write must not be acked")
	require.NoError(t, results[2], "a duplicate is acked idempotently")
	require.Len(t, accepted, 1)
	require.Contains(t, accepted, "ok")
}

// TestCommitFanout_RejectedJtiLeavesExistingIntent: when the ingest write
// rejects a JTI, commitFanoutLocked skips it and deletes nothing, so an older,
// still-undelivered intent for the same JTI survives.
func TestCommitFanout_RejectedJtiLeavesExistingIntent(t *testing.T) {
	h := newFilterPushRouter(t)
	stream := h.createPushStream(t, "")
	sid := stream.StreamConfiguration.Id

	const jti = "jti-real-intent"
	require.NoError(t, h.eventService.AddEventToStream(context.Background(), jti, stream.Id.Hex()))
	require.Equal(t, []string{jti}, pendingJtis(t, h, sid))

	target := &fanoutTarget{mode: "PUSH", key: sid, docID: stream.Id.Hex(), sid: sid, jtis: []string{jti}}
	h.router.mu.RLock()
	h.router.commitFanoutLocked([]*fanoutTarget{target}, map[string]*model.EventRecord{})
	h.router.mu.RUnlock()

	require.Equal(t, []string{jti}, pendingJtis(t, h, sid),
		"the commit phase must not touch a marker for a rejected JTI")
}

// TestCommitFanout_MissingBufferDoesNotPanic covers the window between planning
// and commit. planFanoutLocked sees the stream under one RLock, r.mu is
// released across the ingest write, and RemoveStream can delete the buffer
// before commitFanoutLocked retakes the lock. The markers are already durable,
// so backfill still delivers them; the wake-up is simply skipped.
func TestCommitFanout_MissingBufferDoesNotPanic(t *testing.T) {
	h := newFilterPushRouter(t)
	stream := h.createPushStream(t, "")
	sid := stream.StreamConfiguration.Id

	// The stream and its buffer are gone, exactly as a DELETE /stream mid-write
	// would leave them, but the planned target still names them.
	h.router.RemoveStream(sid)

	const jti = "jti-buffer-gone"
	accepted := map[string]*model.EventRecord{
		jti: {Jti: jti, Sid: sid},
	}

	for _, mode := range []string{"PUSH", "POLL"} {
		t.Run(mode, func(t *testing.T) {
			target := &fanoutTarget{mode: mode, key: sid, docID: stream.Id.Hex(), sid: sid, jtis: []string{jti}}
			require.NotPanics(t, func() {
				h.router.mu.RLock()
				defer h.router.mu.RUnlock()
				h.router.commitFanoutLocked([]*fanoutTarget{target}, accepted)
			}, "a target whose buffer was removed across the write must not panic")
		})
	}
}
