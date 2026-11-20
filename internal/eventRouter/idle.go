package eventRouter

import (
	"fmt"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// idleVerifyEnvVar is the env var that controls T3 idle-keepalive cadence. Slice 8 documents
// it in docs/configuration_properties.md alongside the other I2SIG_PUSH_* knobs.
const idleVerifyEnvVar = "I2SIG_PUSH_KEEPALIVE_INTERVAL"

// idleVerifyEnvVarLegacy is the pre-0.11.0 name. envcompat issues a one-time deprecation
// WARN when it's set; remove in a future release.
const idleVerifyEnvVarLegacy = "I2SIG_PUSH_IDLE_VERIFY_INTERVAL"

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
	return parseDurationEnv(idleVerifyEnvVar, idleVerifyEnvVarLegacy, defaultIdleVerifyInterval)
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
// generation. Returns the persisted EventRecord (with Operational=true) on success.
func (r *router) GenerateVerifyEvent(sid string, state string) (*model.EventRecord, error) {
	// Resolve the per-direction StreamConfiguration so verify targets the
	// outbound side of whichever direction the SID names (Q40). For an SSTP
	// pair's rx-side SID this returns the inbound direction's iss/aud; for a
	// plain stream (or the tx side) it returns the primary StreamConfiguration.
	cfg, err := r.streamService.GetStreamConfigBySID(r.ctx, sid)
	if err != nil {
		return nil, fmt.Errorf("GenerateVerifyEvent: lookup stream %s: %w", sid, err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("GenerateVerifyEvent: stream not found: %s", sid)
	}
	set := events.CreateVerifyEvent(sid, state, cfg.Iss, cfg.Aud)
	return r.SubmitOperationalEvent(sid, set, "")
}

// idleKeepalive owns the T3 timer: the one that fires when a push stream has
// gone idleVerifyInterval without a successful delivery, so the transmitter can
// synthesise a verification SET and find out whether the receiver is still
// there. Its whole purpose is to NOT fire — a busy stream resets it on every
// accepted push and it never reaches zero.
//
// It is a type rather than the bare *time.Timer runPushLoop used to pass around
// for two reasons. First, the timer is optional (a non-positive interval
// disables the feature), which meant every one of the three call sites repeated
// `if idleTimer != nil && idleVerifyInterval > 0` and one of them got it subtly
// different. A nil *idleKeepalive is a working no-op here instead, so the
// call sites just say what they mean. Second, and more usefully: as an
// independent value the T3 cadence can be driven by a test through a synctest
// bubble in microseconds, where reaching it via runPushLoop needs a router, a
// provider, a lease and a live receiver. See idle_keepalive_test.go.
//
// Every method is nil-safe.
type idleKeepalive struct {
	interval time.Duration
	timer    *time.Timer
}

// newIdleKeepalive returns a keepalive armed for interval, or nil when interval
// is non-positive — the documented way to switch T3 off.
func newIdleKeepalive(interval time.Duration) *idleKeepalive {
	if interval <= 0 {
		return nil
	}
	return &idleKeepalive{interval: interval, timer: time.NewTimer(interval)}
}

// C returns the channel the idle deadline fires on. For a disabled keepalive it
// returns nil, and a select arm on a nil channel is never chosen — which is
// exactly "this feature is off" with no branch at the call site.
func (k *idleKeepalive) C() <-chan time.Time {
	if k == nil {
		return nil
	}
	return k.timer.C
}

// Reset restarts the idle deadline. Callers reach for it on every successful
// push (the stream is demonstrably alive, so the clock starts over) and after a
// T3 fire (so the next keepalive is one interval after this one, not immediate).
//
// A plain Reset with no Stop-and-drain preamble is correct: since Go 1.23 a
// Timer's channel is unbuffered and Reset atomically discards a tick that has
// not been received, so the old dance could never observe a stale value. Go
// 1.27 removed the asynctimerchan escape hatch that could re-enable the
// pre-1.23 buffered behaviour, so it is now unreachable in every build.
func (k *idleKeepalive) Reset() {
	if k == nil {
		return
	}
	k.timer.Reset(k.interval)
}

// Stop disarms the keepalive. runPushLoop stops it for the duration of a
// recovery — there is no point synthesising "are you there?" events at a
// receiver we are already probing on its status endpoint — and on the way out,
// so a finished stream leaves no armed runtime timer behind.
func (k *idleKeepalive) Stop() {
	if k == nil {
		return
	}
	k.timer.Stop()
}
