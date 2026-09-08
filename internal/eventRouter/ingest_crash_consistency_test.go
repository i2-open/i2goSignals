package eventRouter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// The ingest durability contract (ADR 0038): the event body and the pending
// marker are written concurrently, so a crash between the two can leave a
// pending marker whose body was never stored. These tests pin the behaviour
// every delivery leg must have in that state — the orphan is skipped, is never
// delivered, and is never acked, while its healthy neighbours in the same batch
// are delivered normally.

// orphanPendingMarker records a delivery intent for a JTI whose body is not in
// the event store — exactly the state a crash between the two concurrent ingest
// writes can leave behind.
func orphanPendingMarker(t *testing.T, h *filterPushHarness, sid string) string {
	t.Helper()
	const jti = "orphan-no-body"
	require.NoError(t, h.eventService.AddEventToStream(context.Background(), jti, sid))
	require.Nil(t, h.eventService.GetEventRecord(context.Background(), jti),
		"the orphan must have a pending marker and no body")
	return jti
}

// TestOrphanPendingMarker_PushSkipsAndDoesNotAck: the push leg drops the orphan
// out of the batch without pushing it and without acking it, and still delivers
// and acks the healthy SET beside it.
func TestOrphanPendingMarker_PushSkipsAndDoesNotAck(t *testing.T) {
	adapter := delivery.NewMemoryAdapter(delivery.PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
	})
	h := newPushBatchHarness(t, adapter)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id

	healthy := h.addPendingEvent(t, sid, emailSubjectFor("push@example.com"), false)
	orphan := orphanPendingMarker(t, h, sid)
	require.Equal(t, 2, h.pendingCount(sid))

	res := h.router.pushBatch([]string{orphan, healthy}, stream, nil, "", 0)

	require.Empty(t, res.failedJti, "an orphan is not a delivery failure")
	require.Equal(t, 1, res.acked, "only the SET that was really pushed is acked")
	require.Equal(t, 1, adapter.Calls(), "the orphan is never handed to the push seam")
	require.Equal(t, 1, h.pendingCount(sid), "the orphan's marker is left pending, not acked away")
}

// TestOrphanPendingMarker_PollSkipsAndLeavesPending: the poll leg leaves the
// orphan out of the response body and leaves its marker pending, so nothing is
// confirmed that was never sent.
func TestOrphanPendingMarker_PollSkipsAndLeavesPending(t *testing.T) {
	h := newPushBatchHarness(t, delivery.NewMemoryAdapter(delivery.PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
	}))
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id

	healthy := h.addPendingEvent(t, sid, emailSubjectFor("poll@example.com"), false)
	orphan := orphanPendingMarker(t, h, sid)

	jtis := []string{orphan, healthy}
	pollBuffer := buffer.CreateEventPollBuffer(jtis, h.router.pollDefaultTimeoutSecs, h.router.pollMaxTimeoutSecs)
	sets := h.router.assemblePollResponse(sid, stream, pollBuffer, jtis, true, nil, "")

	require.NotContains(t, sets, orphan, "an orphan must not appear in a poll response")
	require.Contains(t, sets, healthy)
	require.Equal(t, 2, h.pendingCount(sid), "the poll response acks nothing on its own")
}

// TestOrphanPendingMarker_SstpServerSkips: the SSTP responder's outbound
// assembly renders only the SETs it actually has, so an orphan never reaches
// the wire and is never counted as sent.
func TestOrphanPendingMarker_SstpServerSkips(t *testing.T) {
	h := newPushBatchHarness(t, delivery.NewMemoryAdapter(delivery.PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
	}))
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id

	healthy := h.addPendingEvent(t, sid, emailSubjectFor("sstp@example.com"), false)
	orphan := orphanPendingMarker(t, h, sid)

	// Forward mode renders the stored original verbatim, so the assembly turns
	// on record presence alone rather than on signing-key availability.
	pair := *stream
	pair.StreamConfiguration.RouteMode = model.RouteModeForward

	sets := h.router.buildSstpOutboundSets(&pair, []string{orphan, healthy})

	require.NotContains(t, sets, orphan, "an orphan must not be rendered onto an SSTP message")
	require.Contains(t, sets, healthy)
	require.Equal(t, 2, h.pendingCount(sid), "assembly acks nothing")
}

// TestOrphanPendingMarker_SstpClientSkips: the SSTP initiator's flush resolves
// its claimed JTIs to records and drops the orphan, so the cycle sends the
// healthy SET alone rather than failing or fabricating one.
func TestOrphanPendingMarker_SstpClientSkips(t *testing.T) {
	h := newPushBatchHarness(t, delivery.NewMemoryAdapter(delivery.PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
	}))
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id

	healthy := h.addPendingEvent(t, sid, emailSubjectFor("sstp-client@example.com"), false)
	orphan := orphanPendingMarker(t, h, sid)

	events := h.router.resolveSstpEventsByJti([]string{orphan, healthy})

	require.Len(t, events, 1, "the orphan is dropped from the flush")
	require.Equal(t, healthy, events[0].Jti)
}

// TestIngest_PendingMarkerIsIndependentOfBody proves the state the tests above
// exercise is reachable: a pending marker is a delivery intent recorded on its
// own, so ingest may write it before, after, or concurrently with the body
// (ADR 0038). The provider must not silently drop a marker whose body has not
// landed yet — that would lose the event instead of merely deferring it.
func TestIngest_PendingMarkerIsIndependentOfBody(t *testing.T) {
	h := newPushBatchHarness(t, delivery.NewMemoryAdapter(delivery.PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
	}))
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	ctx := context.Background()

	// Marker first, body second — the order the concurrent writes may produce.
	const jti = "marker-before-body"
	require.NoError(t, h.eventService.AddEventToStream(ctx, jti, sid))
	require.Equal(t, 1, h.pendingCount(sid), "the marker stands on its own")

	token := &goSet.SecurityEventToken{}
	token.ID = jti
	token.SubjectId = emailSubjectFor("late@example.com")
	_, err := h.eventService.AddEvent(ctx, token, sid, "")
	require.NoError(t, err)

	require.Equal(t, 1, h.pendingCount(sid), "the late body does not duplicate the marker")
	require.NotNil(t, h.eventService.GetEventRecord(ctx, jti), "the body is now deliverable")
}
