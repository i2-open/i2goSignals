package eventRouter

import (
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
	r.provider.UpdateStreamStatus(sid, newState, reason)
	stream.Status = newState
	stream.ErrorMsg = reason

	eventLogger.Info("PUSH-SRV: state transition",
		"sid", sid,
		"from", from,
		"to", newState,
		"reason", reason,
	)
}
