package eventRouter

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dispatchPushFailureFixture drives dispatchPushFailure with the ancillary
// timers/config it needs but that these cases do not exercise.
func dispatchPushFailureFixture(t *testing.T, h *testHarness, stream *model.StreamStateRecord, cls goSetPush.Classification) (RecoveryOutcome, bool) {
	t.Helper()
	backfill := time.NewTicker(time.Hour)
	t.Cleanup(backfill.Stop)
	idle := time.NewTimer(time.Hour)
	t.Cleanup(func() { idle.Stop() })

	return h.router.dispatchPushFailure(
		context.Background(), stream, "jti-under-test", cls,
		nil, RecoveryConfig{BaseDelay: time.Millisecond},
		backfill, idle, 0,
	)
}

// A receiver running event_validation=ENFORCE/STRICT rejects ONE non-conformant
// SET with RFC8935 §2.4 invalid_request. That must not take the stream down:
// disabling meant a single bad payload stopped delivery for every subject until
// an operator intervened. Poll is the precedent — a setErr'd JTI is logged WARN
// and acked, leaving stream state alone (PollStreamHandler) — and push now
// matches it (code-review finding on spec #247).
func TestDispatchPushFailure_InvalidRequestDoesNotDisableStream(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)
	require.Equal(t, model.StreamStateEnabled, stream.Status)

	outcome, exit := dispatchPushFailureFixture(t, h, stream, goSetPush.Classification{
		Class:              goSetPush.ClassRFC8935Error,
		RFC8935ErrCode:     goSetPush.ErrInvalidRequest,
		RFC8935Description: "The event payload for \"...session-revoked\" is not conformant",
	})

	assert.Equal(t, RecoveryOutcomeResumed, outcome, "invalid_request must resume, not disable")
	assert.False(t, exit, "the push loop must keep running")
	assert.Equal(t, model.StreamStateEnabled, stream.Status,
		"in-memory stream state must be untouched by a per-SET payload rejection")

	persisted, err := h.streamService.GetStreamState(context.Background(), stream.StreamConfiguration.Id)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateEnabled, persisted.Status,
		"persisted stream state must be untouched by a per-SET payload rejection")
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

		outcome, exit := dispatchPushFailureFixture(t, h, stream, goSetPush.Classification{
			Class:          goSetPush.ClassRFC8935Error,
			RFC8935ErrCode: errCode,
		})

		assert.Equal(t, RecoveryOutcomeDisabled, outcome, "%s must still disable", errCode)
		assert.True(t, exit, "%s must exit the push loop", errCode)
		assert.Equal(t, model.StreamStateDisable, stream.Status, "%s must disable the stream", errCode)
	}
}
