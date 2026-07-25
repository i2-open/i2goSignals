package eventRouter

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pendingOutbound is the durable pending list for a transmit-side SID — the
// surface where "cleared" means the event is gone for good.
func pendingOutbound(t *testing.T, h *sstpRunnerHarness, txSid string) []string {
	t.Helper()
	pending, _ := h.router.eventService.GetEventIds(context.Background(), txSid, model.PollParameters{
		MaxEvents:         10,
		ReturnImmediately: true,
	})
	return pending
}

// Transmit-side setErr consumption on the SSTP-server path. Clearing an outbound
// SET is permanent — the same decision the dialer's clearedOutbound makes on the
// other leg — so the peer's error code has to be honored rather than treated as
// one undifferentiated "rejected" (code-review finding on spec #247).

// A deterministic rejection (event validation, unparseable payload) clears: the
// same bytes can never become acceptable, so leaving it pending would be an
// unbounded claim/sign/POST/reject/release loop.
func TestSstpServer_NonRetryableSetErrClearsOutbound(t *testing.T) {
	h := newSstpRunnerHarness(t)

	txSid, rxSid, pairId := "sstp-tx-err-clear", "sstp-rx-err-clear", "pair-err-clear"
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(),
		sstpServerPairState(txSid, rxSid, pairId)))

	jti := "sstp-err-clear-1"
	h.persistOutboundEvent(t, txSid, jti)

	resolved, err := h.router.streamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)
	h.router.SstpServerHandler(context.Background(), resolved, goSetSstp.Message{
		ReturnImmediately: goSetSstp.BoolPtr(true),
		SetErrs: map[string]goSetSstp.SetErr{
			jti: {Err: goSetSstp.ErrCodeInvalidRequest, Description: "payload not conformant"},
		},
	}, nil)

	assert.NotContains(t, pendingOutbound(t, h, txSid), jti,
		"a deterministically rejected SET must clear, not be re-sent every cycle")
}

// A retryable rejection must NOT clear. Our own acceptor answers a mid-rotation
// signing key or a briefly stale JWKS with ProblemSignatureInvalid /
// ProblemUnknownKID; clearing those deletes real events, silently, while the pair
// still reports enabled. Holding them re-sends the same SET once keys settle.
func TestSstpServer_RetryableSetErrHoldsOutbound(t *testing.T) {
	h := newSstpRunnerHarness(t)

	txSid, rxSid, pairId := "sstp-tx-err-hold", "sstp-rx-err-hold", "pair-err-hold"
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(),
		sstpServerPairState(txSid, rxSid, pairId)))

	jti := "sstp-err-hold-1"
	h.persistOutboundEvent(t, txSid, jti)

	resolved, err := h.router.streamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)
	h.router.SstpServerHandler(context.Background(), resolved, goSetSstp.Message{
		ReturnImmediately: goSetSstp.BoolPtr(true),
		SetErrs: map[string]goSetSstp.SetErr{
			jti: {Err: goSetSstp.ProblemSignatureInvalid, Description: "signature did not verify"},
		},
	}, nil)

	assert.Contains(t, pendingOutbound(t, h, txSid), jti,
		"a retryable rejection must leave the SET pending for a later cycle")
}

// binding-revoked is stream-fatal: every subsequent send is rejected the same
// way. Pausing the outbound direction makes that visible to an operator and keeps
// the queue replayable, instead of acking the backlog away one cycle at a time.
func TestSstpServer_StreamFatalSetErrPausesOutbound(t *testing.T) {
	h := newSstpRunnerHarness(t)

	txSid, rxSid, pairId := "sstp-tx-err-fatal", "sstp-rx-err-fatal", "pair-err-fatal"
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(),
		sstpServerPairState(txSid, rxSid, pairId)))

	jti := "sstp-err-fatal-1"
	h.persistOutboundEvent(t, txSid, jti)

	resolved, err := h.router.streamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)
	h.router.SstpServerHandler(context.Background(), resolved, goSetSstp.Message{
		ReturnImmediately: goSetSstp.BoolPtr(true),
		SetErrs: map[string]goSetSstp.SetErr{
			jti: {Err: goSetSstp.ProblemBindingRevoked, Description: "stream is revoked"},
		},
	}, nil)

	persisted, err := h.router.streamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, persisted.Status,
		"a stream the peer says is dead must stop, visibly")
	assert.Contains(t, persisted.ErrorMsg, "stream dead",
		"the operator needs the peer's own reason")
}
