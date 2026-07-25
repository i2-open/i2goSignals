package eventRouter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dispatchPushFailureFixture drives dispatchPushFailure with the ancillary
// timers/config it needs but that these cases do not exercise.
func dispatchPushFailureFixture(t *testing.T, h *testHarness, stream *model.StreamStateRecord, jti string, cls goSetPush.Classification) (RecoveryOutcome, bool) {
	t.Helper()
	backfill := time.NewTicker(time.Hour)
	t.Cleanup(backfill.Stop)
	idle := time.NewTimer(time.Hour)
	t.Cleanup(func() { idle.Stop() })

	return h.router.dispatchPushFailure(
		context.Background(), stream, jti, cls,
		nil, RecoveryConfig{BaseDelay: time.Millisecond},
		backfill, idle, 0,
	)
}

// invalidRequestCls is what a receiver returns for both situations RFC8935 §2.4
// overloads onto one code — the wire form is identical either way, which is the
// whole reason the transmitter has to consult its own validators.
func invalidRequestCls(description string) goSetPush.Classification {
	return goSetPush.Classification{
		Class:              goSetPush.ClassRFC8935Error,
		RFC8935ErrCode:     goSetPush.ErrInvalidRequest,
		RFC8935Description: description,
	}
}

// persistPushEvent stores token against the stream and returns its JTI, so
// dispatchPushFailure's corroboration lookup finds a real event record.
func persistPushEvent(t *testing.T, h *testHarness, sid string, token *goSet.SecurityEventToken) string {
	t.Helper()
	rec, err := h.router.eventService.AddEvent(context.Background(), token, sid, "")
	require.NoError(t, err)
	require.NoError(t, h.router.eventService.AddEventToStream(context.Background(), rec.Jti, sid))
	return rec.Jti
}

// malformedRiscToken carries a RISC account-disabled event with no subject in
// either carrier (in-payload "subject" or top-level sub_id), which the RISC pack
// reports Malformed.
func malformedRiscToken(jti string) *goSet.SecurityEventToken {
	token := newRiscToken(jti, dupTestIssuer, "https://receiver.example.com")
	token.Events = map[string]interface{}{
		typeAcctDisabled: map[string]interface{}{},
	}
	return token
}

// conformantRiscToken carries the same event type with the subject the RISC pack
// requires, so our validators report it Valid.
func conformantRiscToken(jti string) *goSet.SecurityEventToken {
	token := newRiscToken(jti, dupTestIssuer, "https://receiver.example.com")
	token.Events = map[string]interface{}{
		typeAcctDisabled: map[string]interface{}{
			"subject": map[string]interface{}{
				"format": "email",
				"email":  "user@example.com",
			},
		},
	}
	return token
}

// pendingCount reports how many JTIs are still deliverable for sid — the check
// that separates "the event was cleared" from "the event survived".
func pendingCount(t *testing.T, h *testHarness, sid string) int {
	t.Helper()
	jtis, _ := h.router.eventService.GetEventIds(context.Background(), sid, model.PollParameters{
		MaxEvents: 100, ReturnImmediately: true,
	})
	return len(jtis)
}

// A receiver running event_validation=ENFORCE/STRICT rejects ONE non-conformant
// SET with RFC8935 §2.4 invalid_request. When our own validators agree the
// payload is malformed the receiver is corroborated, so the SET is cleared and
// delivery continues: disabling here meant a single bad payload stopped delivery
// for every subject until an operator intervened.
func TestDispatchPushFailure_CorroboratedInvalidRequestClearsAndContinues(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)
	sid := stream.StreamConfiguration.Id
	require.Equal(t, model.StreamStateEnabled, stream.Status)

	jti := persistPushEvent(t, h, sid, malformedRiscToken("corroborated-jti"))
	require.Equal(t, 1, pendingCount(t, h, sid))

	outcome, exit := dispatchPushFailureFixture(t, h, stream, jti,
		invalidRequestCls(`The event payload for "...account-disabled" is not conformant`))

	assert.Equal(t, RecoveryOutcomeResumed, outcome, "a corroborated rejection must resume, not disable")
	assert.False(t, exit, "the push loop must keep running")
	assert.Equal(t, model.StreamStateEnabled, stream.Status,
		"in-memory stream state must be untouched by a per-SET payload rejection")
	assert.Equal(t, 0, pendingCount(t, h, sid), "the corroborated bad payload must be cleared")

	persisted, err := h.streamService.GetStreamState(context.Background(), sid)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateEnabled, persisted.Status,
		"persisted stream state must be untouched by a per-SET payload rejection")
}

// However many corroborated rejections arrive, back to back and with no accepted
// delivery in between, the stream stays up: each one is an event we independently
// agree is bad, so clearing it loses nothing and there is no burst that can take
// a healthy stream down.
func TestDispatchPushFailure_CorroboratedBurstNeverDisables(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)
	sid := stream.StreamConfiguration.Id

	for i := 0; i < 25; i++ {
		jti := persistPushEvent(t, h, sid, malformedRiscToken(fmt.Sprintf("burst-jti-%d", i)))
		outcome, exit := dispatchPushFailureFixture(t, h, stream, jti,
			invalidRequestCls("not conformant"))
		require.Equal(t, RecoveryOutcomeResumed, outcome, "rejection %d must resume", i)
		require.False(t, exit)
	}

	assert.Equal(t, model.StreamStateEnabled, stream.Status,
		"a burst of independently-confirmed bad payloads must never disable the stream")
	assert.Equal(t, 0, pendingCount(t, h, sid))
}

// invalid_request is also what goSetPush's receiver returns for an unparseable
// SET, a signature it could not verify, and a stream with no trust anchor —
// receiver-side faults that reject EVERY SET. Our validators do not corroborate
// those, so the stream disables AND the event stays pending: the rejection cost
// zero events, and they replay once an operator fixes the receiver.
func TestDispatchPushFailure_UncorroboratedInvalidRequestDisablesWithoutLoss(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)
	sid := stream.StreamConfiguration.Id

	jti := persistPushEvent(t, h, sid, conformantRiscToken("uncorroborated-jti"))
	require.Equal(t, 1, pendingCount(t, h, sid))

	outcome, exit := dispatchPushFailureFixture(t, h, stream, jti,
		invalidRequestCls("The SET could not be verified: no trust anchor is configured."))

	assert.Equal(t, RecoveryOutcomeDisabled, outcome, "an uncorroborated rejection must disable")
	assert.True(t, exit, "the push loop must exit rather than keep draining")
	assert.Equal(t, model.StreamStateDisable, stream.Status)
	assert.Contains(t, stream.ErrorMsg, "receiver-side",
		"the operator needs to see WHY the stream stopped")
	assert.Equal(t, 1, pendingCount(t, h, sid),
		"a conformant event must survive a receiver-side rejection")

	persisted, err := h.streamService.GetStreamState(context.Background(), sid)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, persisted.Status)
}

// A JTI whose record has already gone (operator reset, racing ack) cannot be
// corroborated, so it takes the conservative branch: disable rather than treat an
// unverifiable rejection as proof the payload was bad.
func TestDispatchPushFailure_MissingEventRecordDisables(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)

	outcome, exit := dispatchPushFailureFixture(t, h, stream, "no-such-jti",
		invalidRequestCls("not conformant"))

	assert.Equal(t, RecoveryOutcomeDisabled, outcome)
	assert.True(t, exit)
	assert.Equal(t, model.StreamStateDisable, stream.Status)
}

// Every other RFC8935 §2.4 code still disables. jws_signature_failed has already
// been retried once by the key-flush sub-policy (ADR 0028) before reaching here,
// so what arrives is a deterministic stream-level fault rather than one bad
// payload — the distinction this test pins.
func TestDispatchPushFailure_OtherRFC8935CodesStillDisable(t *testing.T) {
	for _, errCode := range []string{
		goSetPush.ErrJwsSignatureFailed,
		"invalid_audience",
		"access_denied",
	} {
		h := newTestRouter(t)
		projectId := projectIdFromHarness(t, h)
		stream := mustCreateTestStream(t, h, projectId)

		outcome, exit := dispatchPushFailureFixture(t, h, stream, "jti-under-test", goSetPush.Classification{
			Class:          goSetPush.ClassRFC8935Error,
			RFC8935ErrCode: errCode,
		})

		assert.Equal(t, RecoveryOutcomeDisabled, outcome, "%s must still disable", errCode)
		assert.True(t, exit, "%s must exit the push loop", errCode)
		assert.Equal(t, model.StreamStateDisable, stream.Status, "%s must disable the stream", errCode)
	}
}
