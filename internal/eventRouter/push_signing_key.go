package eventRouter

import (
	"context"
	"crypto"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// signingKeyRemedy is the operator action the key-unavailable ERROR names (ADR 0028).
const signingKeyRemedy = "create, rotate or reactivate a signing key for the issuer and algorithm"

// pushKeyWait counts a push runner's consecutive failed signing-key retries (#308).
// It lives for one runPushLoop. It is reset when a batch is delivered, and when a
// missing key comes back, so each key-unavailable pause gets the full retry limit.
// A pause caused by a signing failure keeps its count when the key resolves
// again, so a key that resolves but still cannot sign reaches the retry limit
// instead of pausing and resuming forever.
type pushKeyWait struct {
	tries int
}

// isSigningTransmitter reports whether a transmitter re-signs its SETs: every
// route mode but Forward, an empty one included (#308).
func isSigningTransmitter(stream *model.StreamStateRecord) bool {
	return stream.GetRouteMode() != model.RouteModeForward
}

// pushSigningKey resolves a signing push stream's active key through the router's
// cache. It returns an untyped nil signer when the issuer has no active key for the
// stream's signing_alg.
func (r *router) pushSigningKey(stream *model.StreamStateRecord) (crypto.Signer, string) {
	cfg := stream.StreamConfiguration
	return r.checkAndLoadKey(cfg.Id, cfg.Iss, cfg.SigningAlg)
}

// awaitSigningKey is a signing push runner's key-unavailable pause (#308). It is
// entered when the runner has no active signing key for the stream's iss and
// signing_alg, or when signing with the one it had failed, and nothing has been
// sent for the SET at hand.
//
// It logs an ERROR naming the issuer, algorithm and remedy, pauses the stream with
// a reason naming the issuer and algorithm, and leaves every event queued. It then
// retries the key every AuthRetryDelay: when the key resolves, the stream returns
// to enabled (Resumed); after AuthRetryLimit failed tries it is disabled with the
// same reason (Disabled). These are the receiver-401 retry settings, so a key
// failure adds no settings of its own. A cancelled ctx (lease lost, runner stopped,
// shutdown) returns ContextDone and moves no state.
//
// It resumes only its own pause. When the stored status shows an operator has
// since paused or disabled the stream, it returns Disabled without writing, so
// the runner exits and leaves the operator's status alone; a later re-enable
// starts a new runner.
func (r *router) awaitSigningKey(ctx context.Context, stream *model.StreamStateRecord, cfg RecoveryConfig, wait *pushKeyWait, cause error) RecoveryOutcome {
	cfg.fillDefaults()
	sc := stream.StreamConfiguration
	sid := sc.Id
	alg := signingKeyAlg(sc)
	reason := "PUSH-SRV: " + services.NoActiveSigningKeyReason(sc.Iss, sc.SigningAlg)

	logArgs := []any{"sid", sid, "issuer", sc.Iss, "alg", alg, "remedy", signingKeyRemedy,
		"retryDelay", cfg.AuthRetryDelay, "retryLimit", cfg.AuthRetryLimit}
	if cause != nil {
		logArgs = append(logArgs, "error", cause)
	}
	eventLogger.Error("PUSH-SRV: no active signing key for the stream's issuer; delivery paused, events stay queued", logArgs...)
	r.updateStream(stream, model.StreamStatePause, reason)

	started := cfg.Clock()
	for {
		if wait.tries >= cfg.AuthRetryLimit {
			eventLogger.Error("PUSH-SRV: still no active signing key after the retry limit; stream disabled",
				"sid", sid, "issuer", sc.Iss, "alg", alg, "remedy", signingKeyRemedy, "tries", wait.tries)
			r.updateStream(stream, model.StreamStateDisable, reason)
			r.logKeyWaitResolved(sid, RecoveryOutcomeDisabled, cfg.Clock().Sub(started))
			return RecoveryOutcomeDisabled
		}
		if !cfg.Sleep(ctx, cfg.AuthRetryDelay) {
			return RecoveryOutcomeContextDone
		}
		wait.tries++
		if r.keyPauseOverridden(sid, reason) {
			eventLogger.Info("PUSH-SRV: stream status changed during the key-unavailable pause; runner stopping", "sid", sid)
			return RecoveryOutcomeDisabled
		}
		if key, _ := r.pushSigningKey(stream); key != nil {
			if cause == nil {
				wait.tries = 0
			}
			r.updateStream(stream, model.StreamStateEnabled, "")
			r.logKeyWaitResolved(sid, RecoveryOutcomeResumed, cfg.Clock().Sub(started))
			return RecoveryOutcomeResumed
		}
		eventLogger.Debug("PUSH-SRV: signing key still unavailable", "sid", sid, "issuer", sc.Iss, "alg", alg, "tries", wait.tries)
	}
}

// keyPauseOverridden reports whether sid's stored status is no longer this runner's
// key-unavailable pause nor enabled, meaning someone else (an operator) has paused or
// disabled the stream since. A store that cannot answer is not an override.
func (r *router) keyPauseOverridden(sid, reason string) bool {
	rec, err := r.streamService.GetStreamState(r.ctx, sid)
	if err != nil || rec == nil {
		return false
	}
	switch {
	case rec.Status == model.StreamStateEnabled:
		return false
	case rec.Status == model.StreamStatePause && rec.ErrorMsg == reason:
		return false
	default:
		return true
	}
}

// pauseForSigningKey runs awaitSigningKey from inside the push loop, with backfill
// and the T3 idle timer stopped for the pause. On Resumed it restarts both and
// backfills at once, so SETs taken from the buffer before the pause, which stayed
// pending in the store, are delivered promptly.
func (r *router) pauseForSigningKey(ctx context.Context, stream *model.StreamStateRecord, cfg RecoveryConfig, wait *pushKeyWait, cause error,
	backfillTicker *time.Ticker, idle *idleKeepalive, eventBuf *buffer.EventPushBuffer) RecoveryOutcome {
	backfillTicker.Stop()
	idle.Stop()
	outcome := r.awaitSigningKey(ctx, stream, cfg, wait, cause)
	if outcome == RecoveryOutcomeResumed {
		backfillTicker.Reset(r.backfillInterval)
		idle.Reset()
		r.backfillPushBuffer(stream.StreamConfiguration.Id, eventBuf)
	}
	return outcome
}

// logKeyWaitResolved records how a key-unavailable pause ended, alongside the
// receiver recovery resolutions.
func (r *router) logKeyWaitResolved(sid string, outcome RecoveryOutcome, elapsed time.Duration) {
	eventLogger.Info("PUSH-SRV: key-unavailable pause resolved", "sid", sid, "outcome", outcome.String(), "elapsed", elapsed)
}
