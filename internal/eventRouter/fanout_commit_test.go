package eventRouter

import (
	"context"
	"errors"
	"github.com/i2-open/i2goSignals/internal/dao/pendingref"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/services"
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
	return pendingref.RefJtis(jtis)
}

// TestIngest_ResentPendingSetKeepsOneIntent: a SET re-sent while its first copy
// is still undelivered is a duplicate, so the one-trip write adds no second
// marker and the original delivery intent survives untouched.
func TestIngest_ResentPendingSetKeepsOneIntent(t *testing.T) {
	s := setupDedupRouterPollStream(t)
	token := newRiscToken("resent-pending", dupTestIssuer, s.audience)
	ids := func() []string {
		jtis, _ := s.h.router.eventService.GetEventIds(context.Background(), s.streamID, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
		return pendingref.RefJtis(jtis)
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
	require.NoError(t, h.eventService.AddEventToStream(context.Background(), refOf(jti), stream.Id.Hex()))
	require.Equal(t, []string{jti}, pendingJtis(t, h, sid))

	target := &fanoutTarget{mode: "PUSH", key: sid, docID: stream.Id.Hex(), sid: sid, jtis: []string{jti}}
	h.router.mu.RLock()
	h.router.commitFanoutLocked([]*fanoutTarget{target}, map[string]*model.EventRecord{}, nil)
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
				h.router.commitFanoutLocked([]*fanoutTarget{target}, accepted, nil)
			}, "a target whose buffer was removed across the write must not panic")
		})
	}
}

// seedBodyWithoutMarker stores a SET's body with no pending marker on any
// stream: the state ADR 0043's one-trip write leaves behind when the body
// insert landed and the marker write failed (#331).
func seedBodyWithoutMarker(t *testing.T, es *services.EventService, token *goSet.SecurityEventToken, sid string) {
	t.Helper()
	recs := services.NewIngestRecords([]*goSet.SecurityEventToken{token}, sid, []string{`{"orphan":true}`})
	_, errs := es.AddEventsWithPending(context.Background(), recs, sid, nil)
	require.NoError(t, errs[0])
}

// TestIngest_RetryAfterMarkerFailureDeliversOnce: a transmitter retrying a SET
// whose body landed but whose marker write failed (a 503 answered it) gets a
// duplicate back from the store; the router re-queues it on the streams that
// hold neither a pending nor a delivered record for it, so the SET is
// delivered exactly once and a further retry changes nothing (#331).
func TestIngest_RetryAfterMarkerFailureDeliversOnce(t *testing.T) {
	s := setupDedupRouterPollStream(t)
	token := newRiscToken("retry-after-marker-loss", dupTestIssuer, s.audience)
	ids := func() []string {
		jtis, _ := s.h.router.eventService.GetEventIds(context.Background(), s.streamID, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
		return pendingref.RefJtis(jtis)
	}
	seedBodyWithoutMarker(t, s.h.router.eventService, token, s.streamID)
	require.Empty(t, ids(), "precondition: body stored, no marker")

	require.NoError(t, s.h.router.HandleEvent(token, `{"retry":1}`, s.streamID), "the retry is acked")
	require.Eventually(t, func() bool { return s.pollBufferCh() == 1 }, time.Second, 5*time.Millisecond,
		"the re-queued SET is submitted for delivery")
	require.Equal(t, []string{"retry-after-marker-loss"}, ids(), "exactly one marker after the repair")
	require.InDelta(t, 0.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001,
		"a duplicate is not metered as ingress even when re-queued")

	require.NoError(t, s.h.router.HandleEvent(token, `{"retry":2}`, s.streamID))
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, []string{"retry-after-marker-loss"}, ids(), "a second retry adds no marker")
	require.Equal(t, 1, s.pollBufferCh(), "a second retry submits nothing")
}

// failingEnsureDAO fails every EnsurePending so the re-queue repair cannot run.
type failingEnsureDAO struct {
	interfaces.EventDAO
}

var errEnsureDown = errors.New("injected EnsurePending outage")

func (f failingEnsureDAO) EnsurePending(context.Context, string, map[string]string) ([]string, error) {
	return nil, errEnsureDown
}

// TestIngest_RequeueFailureIsStoreUnavailable: when the re-queue repair itself
// fails, the duplicate is answered ErrStoreUnavailable (503) instead of an
// idempotent 202, so the transmitter keeps retrying until the repair can run —
// an ack here could lose the SET (#331). Every duplicate takes the repair
// round-trip, since only the store knows whether its marker is in place.
func TestIngest_RequeueFailureIsStoreUnavailable(t *testing.T) {
	p := openMemPersistence(t)
	s := newWalRouterWith(t, p, t.TempDir(), nil, func(d *RouterDeps) {
		d.WAL = nil // majority path: the store is written inline
		d.EventService = services.NewEventService(failingEnsureDAO{p.EventDAO})
	})
	token := newRiscToken("requeue-fails", dupTestIssuer, s.audience)
	seedBodyWithoutMarker(t, p.EventService, token, s.streamID)

	err := s.router.HandleEvent(token, `{"retry":true}`, s.streamID)
	require.ErrorIs(t, err, ErrStoreUnavailable, "a failed repair must not be acked")
	require.Empty(t, s.pending(t), "nothing was queued")

	// A new SET is unaffected: it never reaches the repair.
	require.NoError(t, s.router.HandleEvent(newRiscToken("requeue-not-needed", dupTestIssuer, s.audience), `{"new":true}`, s.streamID))
	require.Equal(t, []string{"requeue-not-needed"}, s.pending(t))
}
