package eventRouter

import (
	"errors"
	"strings"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// updateStream is the single transition point for a push stream's lifecycle state.
// All push-side transitions (recoveryLoop, pushEvent failure dispatch, pre-flight) MUST go through
// this helper so logging, audit, and (slice 8) metrics emission happen in exactly one place.
//
// Behavior:
//   - Persists the new status and reason via provider.UpdateStreamStatus.
//   - Mutates the in-memory stream record so the running runPushLoop sees the new state on its
//     next iteration without re-fetching.
//   - Emits a structured INFO log naming the from/to states and the reason. Recovery callers
//     should pass a reason that captures the trigger (failure class, RFC8935 code, etc.).
//   - Tells the other nodes in the background that the stream changed, so their copies
//     follow. A pause stored here carries pushRunnerReasonPrefix (see isRunnerPause).
//
// updateStream is a no-op (returns immediately, no log, no persist) when the requested state and
// reason match the current state — this keeps recoveryLoop polling cheap when the receiver stays
// in the same state across consecutive /status checks.
func (r *router) updateStream(stream *model.StreamStateRecord, newState string, reason string) {
	if stream == nil {
		eventLogger.Warn("PUSH-SRV: updateStream called with nil stream")
		return
	}
	from := stream.Status
	if from == newState && stream.ErrorMsg == reason {
		return
	}

	sid := stream.StreamConfiguration.Id
	r.streamService.UpdateStreamStatus(r.ctx, sid, newState, reason)
	// SetStatus mirrors the store: on an SSTP pair both halves move (#303).
	stream.SetStatus(newState, reason)

	eventLogger.Info("PUSH-SRV: state transition",
		"sid", sid,
		"from", from,
		"to", newState,
		"reason", reason,
	)
	if r.stats != nil {
		r.stats.RecordStateTransition(sid, from, newState)
	}
	// The peers' copies of the stream follow at once, not on their periodic
	// sync; nothing here waits for them.
	r.announceStreamChanged(sid)
}

// pushRunnerReasonPrefix starts every reason a push runner stores with the
// pause it takes itself (receiver recovery, a missing signing key).
const pushRunnerReasonPrefix = "PUSH-SRV: "

// isRunnerPause reports whether rec is paused by a push runner itself rather
// than by an operator. The store carries the reason, so every node reads it
// alike: such a pause leaves each node's runner running, since the holder's is
// what ends it and a standby's takes the stream over if the holder dies.
func isRunnerPause(rec *model.StreamStateRecord) bool {
	return rec.Status == model.StreamStatePause && strings.HasPrefix(rec.ErrorMsg, pushRunnerReasonPrefix)
}

// resumeOwnPause ends the pause stream's runner took itself (receiver
// recovery, a missing signing key) and reports whether the runner may go on.
// The stored record is read first, and enabled is written only while it is
// still paused with the runner's own reason. An operator's pause or disable
// stored meanwhile wins: nothing is written and it reports false, so the
// runner exits and leaves that status alone. A stream already enabled in the
// store (re-enabled by an operator) resumes with no write, and one deleted
// from the store reports false. A store read that fails resumes as before.
func (r *router) resumeOwnPause(stream *model.StreamStateRecord) bool {
	sid := stream.StreamConfiguration.Id
	if stream.Status == model.StreamStatePause {
		stored, err := r.streamService.GetStreamState(r.ctx, sid)
		switch {
		case errors.Is(err, interfaces.ErrNotFound):
			eventLogger.Info("PUSH-SRV: stream deleted during the runner's own pause; runner stopping", "sid", sid)
			return false
		case err != nil || stored == nil:
			eventLogger.Warn("PUSH-SRV: cannot confirm the stream's own pause before resuming; resuming", "sid", sid, "error", err)
		case stored.Status == model.StreamStateEnabled:
			stream.SetStatus(model.StreamStateEnabled, "")
			return true
		case stored.Status != model.StreamStatePause || stored.ErrorMsg != stream.ErrorMsg:
			eventLogger.Info("PUSH-SRV: stream status changed during the runner's own pause; leaving it and stopping",
				"sid", sid, "status", stored.Status, "reason", stored.ErrorMsg)
			return false
		}
	}
	r.updateStream(stream, model.StreamStateEnabled, "")
	return true
}
