package eventRouter

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// RecoveryMode selects the cadence and cap policy used by recoveryLoop.
type RecoveryMode int

const (
	// RecoveryModePausedByRemote: enter when the receiver's /status reports paused
	// (whether discovered via T2 pre-flight or T1 reactive). Polls /status at
	// StatusCheckInterval indefinitely until the receiver flips back to enabled or disabled.
	RecoveryModePausedByRemote RecoveryMode = iota

	// RecoveryModeTransportBackoff: enter on transport errors or HTTP 5xx (without Retry-After).
	// Exponential backoff between /status probes; total elapsed time capped by TransportLimit.
	// On cap → disable.
	RecoveryModeTransportBackoff

	// RecoveryModeAuthBounded: enter on HTTP 401. Fixed AuthRetryDelay between probes;
	// capped by AuthRetryLimit attempts. On cap → disable.
	RecoveryModeAuthBounded
)

// String returns the RecoveryMode label suitable for logs and metric labels.
func (m RecoveryMode) String() string {
	switch m {
	case RecoveryModePausedByRemote:
		return "paused-by-remote"
	case RecoveryModeTransportBackoff:
		return "transport-backoff"
	case RecoveryModeAuthBounded:
		return "auth-bounded"
	default:
		return "unknown"
	}
}

// RecoveryOutcome describes how recoveryLoop exited. Caller dispatches on this:
// Resumed → return to runPushLoop active mode; Disabled → exit the lifecycle goroutine;
// ContextDone → caller's context was cancelled (lease loss, shutdown).
type RecoveryOutcome int

const (
	RecoveryOutcomeResumed RecoveryOutcome = iota
	RecoveryOutcomeDisabled
	RecoveryOutcomeContextDone
)

// String returns the RecoveryOutcome label suitable for logs and metric labels.
func (o RecoveryOutcome) String() string {
	switch o {
	case RecoveryOutcomeResumed:
		return "resumed"
	case RecoveryOutcomeDisabled:
		return "disabled"
	case RecoveryOutcomeContextDone:
		return "context-done"
	default:
		return "unknown"
	}
}

// StatusFetcher abstracts the receiver-status interrogation. It returns the receiver's
// reported StreamStatus, or an error if the fetch itself failed (transport, HTTP error,
// auth failure). recoveryLoop treats nil-status-with-error as "couldn't determine state"
// and applies the mode-specific backoff/cap.
type StatusFetcher func(ctx context.Context, stream *model.StreamStateRecord) (*model.StreamStatus, error)

// RecoveryConfig governs the timing and caps of recoveryLoop. Production code populates
// this from env vars via LoadRecoveryConfig; tests inject deterministic values.
type RecoveryConfig struct {
	// StatusCheckInterval: cadence for paused-by-remote re-checks.
	StatusCheckInterval time.Duration

	// BaseDelay, BackoffFactor, MaxDelay: exponential backoff parameters for TransportBackoff.
	BaseDelay     time.Duration
	BackoffFactor float64
	MaxDelay      time.Duration

	// TransportLimit: maximum total elapsed time in TransportBackoff before disable.
	TransportLimit time.Duration

	// AuthRetryDelay: sleep between AuthBounded probes.
	AuthRetryDelay time.Duration
	// AuthRetryLimit: maximum attempts in AuthBounded before disable.
	AuthRetryLimit int

	// Clock returns the current time. Defaults to time.Now. Tests may inject a fake clock.
	Clock func() time.Time
	// Sleep waits for d or returns when ctx is cancelled. Returns true if d elapsed,
	// false if ctx was cancelled. Defaults to a real time.After + ctx.Done() select.
	Sleep func(ctx context.Context, d time.Duration) bool
}

// fillDefaults backfills zero-valued config fields with safe defaults so callers can pass
// a partial config. RecoveryLoop must never observe a nil Clock or Sleep.
func (c *RecoveryConfig) fillDefaults() {
	if c.StatusCheckInterval == 0 {
		c.StatusCheckInterval = 30 * time.Second
	}
	if c.BaseDelay == 0 {
		c.BaseDelay = 1 * time.Second
	}
	if c.BackoffFactor == 0 {
		c.BackoffFactor = 2.0
	}
	if c.MaxDelay == 0 {
		c.MaxDelay = 5 * time.Minute
	}
	if c.TransportLimit == 0 {
		c.TransportLimit = 6 * time.Hour
	}
	if c.AuthRetryDelay == 0 {
		c.AuthRetryDelay = 15 * time.Second
	}
	if c.AuthRetryLimit == 0 {
		c.AuthRetryLimit = 10
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = defaultSleep
	}
}

func defaultSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// LoadRecoveryConfig reads I2SIG_PUSH_* env vars and returns a RecoveryConfig with defaults
// for any unset values. Slice 8 will document these env vars in docs/configuration_properties.md.
func LoadRecoveryConfig() RecoveryConfig {
	cfg := RecoveryConfig{
		StatusCheckInterval: parseDurationEnv("I2SIG_PUSH_PROBE_INTERVAL", "I2SIG_PUSH_STATUS_CHECK_INTERVAL", 30*time.Second),
		BaseDelay:           parseDurationEnv("I2SIG_PUSH_RETRY_BASE_DELAY", "", 1*time.Second),
		BackoffFactor:       parseFloatEnv("I2SIG_PUSH_RETRY_BACKOFF_FACTOR", "", 2.0),
		MaxDelay:            parseDurationEnv("I2SIG_PUSH_RETRY_MAX_DELAY", "", 5*time.Minute),
		TransportLimit:      parseDurationEnv("I2SIG_PUSH_RETRY_LIMIT", "", 6*time.Hour),
		AuthRetryDelay:      parseDurationEnv("I2SIG_PUSH_AUTH_RETRY_DELAY", "I2SIG_PUSH_UNAUTHORIZED_RETRY_DELAY", 15*time.Second),
		AuthRetryLimit:      parseIntEnv("I2SIG_PUSH_AUTH_RETRY_LIMIT", "I2SIG_PUSH_UNAUTHORIZED_RETRY_LIMIT", 10),
	}
	cfg.fillDefaults()
	return cfg
}

// parseDurationEnv reads `name` first, then falls back to `oldName` (logged once
// as deprecated by envcompat) when `oldName` is non-empty.
func parseDurationEnv(name, oldName string, defaultVal time.Duration) time.Duration {
	v := lookupEnv(name, oldName)
	if v == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		eventLogger.Warn("PUSH-SRV: invalid duration env var, using default", "name", name, "value", v, "default", defaultVal)
		return defaultVal
	}
	return d
}

func parseFloatEnv(name, oldName string, defaultVal float64) float64 {
	v := lookupEnv(name, oldName)
	if v == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		eventLogger.Warn("PUSH-SRV: invalid float env var, using default", "name", name, "value", v, "default", defaultVal)
		return defaultVal
	}
	return f
}

func parseIntEnv(name, oldName string, defaultVal int) int {
	v := lookupEnv(name, oldName)
	if v == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		eventLogger.Warn("PUSH-SRV: invalid int env var, using default", "name", name, "value", v, "default", defaultVal)
		return defaultVal
	}
	return i
}

func lookupEnv(name, oldName string) string {
	if oldName == "" {
		return envcompat.Lookup(name, "")
	}
	return envcompat.Lookup(name, oldName)
}

// recoveryLoop interrogates the receiver's /status endpoint until it can return a definite
// outcome. It blocks the calling goroutine — the lifecycle goroutine for this stream — and
// performs all state transitions through r.updateStream so logging/audit/metrics flow through
// a single point.
//
// Cap behavior depends on `mode`:
//
//   - PausedByRemote: no cap. Loops forever until the receiver flips back to enabled or
//     disabled, or the context is cancelled. /status fetch errors during recheck are silent
//     and don't downgrade — we already know the receiver was reachable.
//
//   - TransportBackoff: total elapsed time is capped by cfg.TransportLimit. On cap, the
//     stream is disabled with the last fetch error in the reason.
//
//   - AuthBounded: attempt count is capped by cfg.AuthRetryLimit. On cap, the stream is
//     disabled with the last fetch error in the reason.
//
// Once a /status fetch succeeds with Paused (regardless of starting mode), subsequent fetch
// failures use PausedByRemote cadence — we know the receiver is reachable, just self-paused.
//
// Returns RecoveryOutcomeResumed if the receiver returned to enabled, RecoveryOutcomeDisabled
// if the loop disabled the stream (cap or remote disabled), or RecoveryOutcomeContextDone
// if the caller's context was cancelled (e.g. lease loss).
func (r *router) recoveryLoop(ctx context.Context, stream *model.StreamStateRecord, mode RecoveryMode, fetcher StatusFetcher, cfg RecoveryConfig) RecoveryOutcome {
	cfg.fillDefaults()
	if stream == nil {
		eventLogger.Warn("PUSH-SRV: recoveryLoop called with nil stream")
		return RecoveryOutcomeDisabled
	}
	if fetcher == nil {
		eventLogger.Error("PUSH-SRV: recoveryLoop called with nil fetcher", "sid", stream.StreamConfiguration.Id)
		return RecoveryOutcomeDisabled
	}

	sid := stream.StreamConfiguration.Id
	started := cfg.Clock()
	delay := cfg.BaseDelay
	attempts := 0
	currentMode := mode
	var lastErr error

	eventLogger.Info("PUSH-SRV: recovery entered", "sid", sid, "mode", mode.String())

	for {
		if ctx.Err() != nil {
			return RecoveryOutcomeContextDone
		}

		attempts++
		status, err := fetcher(ctx, stream)

		if err == nil && status != nil {
			switch status.Status {
			case model.StreamStateEnabled:
				r.updateStream(stream, model.StreamStateEnabled, "")
				r.logRecoveryResolved(sid, RecoveryOutcomeResumed, currentMode, cfg.Clock().Sub(started))
				return RecoveryOutcomeResumed

			case model.StreamStateDisable:
				reason := fmt.Sprintf("PUSH-SRV: remote stream disabled: %s", status.Reason)
				r.updateStream(stream, model.StreamStateDisable, reason)
				r.logRecoveryResolved(sid, RecoveryOutcomeDisabled, currentMode, cfg.Clock().Sub(started))
				return RecoveryOutcomeDisabled

			case model.StreamStatePause:
				reason := fmt.Sprintf("PUSH-SRV: remote stream paused: %s", status.Reason)
				r.updateStream(stream, model.StreamStatePause, reason)
				// Once we've seen the receiver report paused, drop into paused-by-remote cadence
				// regardless of original mode. We know the receiver is reachable.
				currentMode = RecoveryModePausedByRemote
				if !cfg.Sleep(ctx, cfg.StatusCheckInterval) {
					return RecoveryOutcomeContextDone
				}
				continue
			}
		}

		// Fetch failed or returned an unknown status.
		lastErr = err

		switch currentMode {
		case RecoveryModePausedByRemote:
			// No cap. Errors during recheck are tolerated — keep polling.
			if err != nil {
				eventLogger.Debug("PUSH-SRV: status recheck error during paused-by-remote", "sid", sid, "error", err)
			}
			if !cfg.Sleep(ctx, cfg.StatusCheckInterval) {
				return RecoveryOutcomeContextDone
			}

		case RecoveryModeTransportBackoff:
			elapsed := cfg.Clock().Sub(started)
			if elapsed >= cfg.TransportLimit {
				reason := fmt.Sprintf("PUSH-SRV: transport recovery exhausted after %v (last error: %v)", cfg.TransportLimit, lastErr)
				r.updateStream(stream, model.StreamStateDisable, reason)
				r.logRecoveryResolved(sid, RecoveryOutcomeDisabled, currentMode, elapsed)
				return RecoveryOutcomeDisabled
			}
			if !cfg.Sleep(ctx, delay) {
				return RecoveryOutcomeContextDone
			}
			delay = nextBackoff(delay, cfg.BackoffFactor, cfg.MaxDelay)

		case RecoveryModeAuthBounded:
			if attempts >= cfg.AuthRetryLimit {
				reason := fmt.Sprintf("PUSH-SRV: auth recovery exhausted after %d attempts (last error: %v)", cfg.AuthRetryLimit, lastErr)
				r.updateStream(stream, model.StreamStateDisable, reason)
				r.logRecoveryResolved(sid, RecoveryOutcomeDisabled, currentMode, cfg.Clock().Sub(started))
				return RecoveryOutcomeDisabled
			}
			if !cfg.Sleep(ctx, cfg.AuthRetryDelay) {
				return RecoveryOutcomeContextDone
			}
		}
	}
}

// nextBackoff returns the next exponential-backoff delay, capped by maxDelay.
func nextBackoff(current time.Duration, factor float64, maxDelay time.Duration) time.Duration {
	if factor <= 1.0 {
		factor = 2.0
	}
	next := time.Duration(float64(current) * factor)
	if next > maxDelay || next < 0 {
		return maxDelay
	}
	if next == 0 {
		return time.Duration(math.Max(float64(current), float64(maxDelay/16)))
	}
	return next
}

// logRecoveryResolved emits the structured INFO log when recoveryLoop exits and observes the
// elapsed duration into push_recovery_duration_seconds. Both the log and the histogram fire
// regardless of outcome — operators dashboarding "stream stuck in recovery" want to see the
// long tail (Disabled cap-out at 6h is the primary alerting signal).
func (r *router) logRecoveryResolved(sid string, outcome RecoveryOutcome, mode RecoveryMode, elapsed time.Duration) {
	eventLogger.Info("PUSH-SRV: recovery resolved",
		"sid", sid,
		"outcome", outcome.String(),
		"mode", mode.String(),
		"elapsed", elapsed,
	)
	if r.stats != nil {
		r.stats.ObservePushRecoveryDuration(sid, elapsed.Seconds())
	}
}
