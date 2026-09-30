package eventRouter

import (
	"errors"

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
//   - Notes a push runner's own pause (see pushOwnPause), and tells the other nodes in the
//     background that the stream changed, so their copies follow.
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
	// A push runner's own pause is noted before it is stored, so that a sync
	// or stream-changed call that reads it back finds it the runner's own and
	// leaves the runner running; any other status ends it once stored.
	push := stream.GetType() != model.DeliverySstpPair
	if push && newState == model.StreamStatePause {
		r.setOwnPause(sid, reason)
	}
	r.streamService.UpdateStreamStatus(r.ctx, sid, newState, reason)
	// SetStatus mirrors the store: on an SSTP pair both halves move (#303).
	stream.SetStatus(newState, reason)
	if push && newState != model.StreamStatePause {
		r.setOwnPause(sid, "")
	}

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

// setOwnPause records reason as the pause sid's push runner took itself, or
// clears it when reason is "".
func (r *router) setOwnPause(sid, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reason == "" {
		delete(r.pushOwnPause, sid)
		return
	}
	if r.pushOwnPause == nil {
		r.pushOwnPause = map[string]string{}
	}
	r.pushOwnPause[sid] = reason
}

// isOwnPauseLocked reports whether rec is paused with the reason sid's push
// runner stored for its own pause. The caller holds r.mu (read or write).
func (r *router) isOwnPauseLocked(sid string, rec *model.StreamStateRecord) bool {
	own, ok := r.pushOwnPause[sid]
	return ok && rec.Status == model.StreamStatePause && rec.ErrorMsg == own
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
			r.setOwnPause(sid, "")
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
