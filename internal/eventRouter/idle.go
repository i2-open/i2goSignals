package eventRouter

import (
    "fmt"
    "time"

    "github.com/i2-open/i2goSignals/pkg/goSet/events"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// idleVerifyEnvVar is the env var that controls T3 idle-keepalive cadence. Slice 8 documents
// it in docs/configuration_properties.md alongside the other I2SIG_PUSH_* knobs.
const idleVerifyEnvVar = "I2SIG_PUSH_IDLE_VERIFY_INTERVAL"

// defaultIdleVerifyInterval is the cadence used when the env var is unset or invalid. The
// 5-minute default trades off:
//   - Short enough that an idle push relationship surfaces a connectivity break before an
//     operator notices via "stream looks healthy but nothing arrived all morning".
//   - Long enough that we don't generate measurable load on a quiet receiver.
//
// Operators can tune via env to as low as a second (mostly useful in tests) or to disable
// entirely by setting "0" — the runPushLoop treats a non-positive interval as "no idle timer".
const defaultIdleVerifyInterval = 5 * time.Minute

// LoadIdleVerifyInterval returns the configured T3 idle-keepalive cadence. A non-positive
// value (including the explicit "0" override) disables idle generation in runPushLoop.
func LoadIdleVerifyInterval() time.Duration {
    return parseDurationEnv(idleVerifyEnvVar, defaultIdleVerifyInterval)
}

// GenerateVerifyEvent persists an SSF verification SET (per OpenID SSF §8.1.4.2) scoped to the
// named stream's iss/aud and submits it directly to that stream's pending list as an operational
// event (Operational=true, excluded from operator ResetDate/ResetJti replay queries — see slice 2).
//
// It is the single shared generation path used by:
//   - the operator-triggered API handler in pkg/goSignals/server/api_verify.go,
//   - the push-side T3 idle keepalive in runPushLoop.
//
// Both call paths produce identical persisted records: the only difference is who triggered the
// generation. Returns the persisted AgEventRecord (with Operational=true) on success.
func (r *router) GenerateVerifyEvent(sid string, state string) (*model.AgEventRecord, error) {
    stream, err := r.provider.GetStreamState(sid)
    if err != nil {
        return nil, fmt.Errorf("GenerateVerifyEvent: lookup stream %s: %w", sid, err)
    }
    if stream == nil {
        return nil, fmt.Errorf("GenerateVerifyEvent: stream not found: %s", sid)
    }
    set := events.CreateVerifyEvent(sid, state, stream.Iss, stream.Aud)
    return r.SubmitOperationalEvent(sid, set, "")
}

// resetIdleTimer drains any pending tick before resetting so callers don't fire spuriously
// after a Reset on a timer that already expired. This is defensive — Go 1.23+ Timer.Reset
// semantics make the drain a no-op in our specific call sites — but it costs nothing and
// makes the call safe regardless of who else might have raced to read t.C.
func resetIdleTimer(t *time.Timer, d time.Duration) {
    if t == nil || d <= 0 {
        return
    }
    if !t.Stop() {
        select {
        case <-t.C:
        default:
        }
    }
    t.Reset(d)
}
