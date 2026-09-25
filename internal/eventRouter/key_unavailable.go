package eventRouter

import (
	"context"
	"errors"
	"net/http"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Key-unavailable pause for poll transmitters and SSTP pairs (#312).
//
// A signing transmitter (every route mode but Forward) that has no active
// signing key for its iss and signing_alg never sends an unsigned or empty SET
// and never silently leaves one out. A push runner owns its own pause and
// retries (#308). A poll transmitter or SSTP pair has no runner of its own
// that could wait, so it takes a stored key-unavailable pause instead: paused
// with a reason naming the issuer and algorithm, and KeyUnavailableSince set
// to the first failure. Every node's background key check then retries the key
// for the stored streams in that pause, resumes them when it is back and
// disables them once the retry limit has passed.

// PollKeyUnavailableStatus is the HTTP status PollStreamHandler returns when a
// signing poll transmitter has no active signing key (#312). The stream has
// been paused and nothing was sent; the events stay queued.
const PollKeyUnavailableStatus = http.StatusServiceUnavailable

// keyCheckedStream reports whether rec's key-unavailable pause belongs to the
// background key check: a poll transmitter or an SSTP pair.
func keyCheckedStream(rec *model.StreamStateRecord) bool {
	switch rec.GetType() {
	case model.DeliveryPoll, model.DeliverySstpPair:
		return true
	default:
		return false
	}
}

// inKeyUnavailablePause reports whether rec is paused with the key-unavailable
// marker.
func inKeyUnavailablePause(rec *model.StreamStateRecord) bool {
	return rec != nil && rec.Status == model.StreamStatePause && rec.KeyUnavailableSince != nil
}

// signingKeyAlg names the algorithm a transmitter signs with, RS256 when unset.
func signingKeyAlg(cfg model.StreamConfiguration) string {
	if cfg.SigningAlg == "" {
		return "RS256"
	}
	return cfg.SigningAlg
}

// errNoActiveSigningKey is the error a refused exchange reports for cfg.
func errNoActiveSigningKey(cfg model.StreamConfiguration) error {
	return errors.New(services.NoActiveSigningKeyReason(cfg.Iss, cfg.SigningAlg))
}

// keyUnavailableReason is a key-unavailable pause's reason for cfg: the issuer
// and algorithm, and the expired or not-yet-valid key with its time when a
// validity period is the cause (#318).
func (r *router) keyUnavailableReason(cfg model.StreamConfiguration) string {
	return r.streamService.SigningKeyUnavailableReason(r.ctx, cfg.Iss, cfg.SigningAlg)
}

// keyUnavailableForValidity reports whether cfg's issuer, already found to
// have no active signing key, has one that is expired or not yet valid: the
// key-unavailable reason then carries the key's validity detail.
func (r *router) keyUnavailableForValidity(cfg model.StreamConfiguration) bool {
	return r.keyUnavailableReason(cfg) != services.NoActiveSigningKeyReason(cfg.Iss, cfg.SigningAlg)
}

// takeKeyUnavailablePause pauses a signing poll transmitter or SSTP pair that
// has no active signing key, or whose key failed to sign (cause), with nothing
// sent. component prefixes the reason (POLL-SRV, SSTP-SRV, SSTP-CLIENT).
//
// It stores the pause with the marker (a repeat failure keeps the first time),
// mirrors it onto stream and this node's copy of the stream, and ends any
// long poll waiting on the stream here. A signing failure also evicts the
// cached key, so the retries read the key store. It logs one ERROR, naming the
// issuer, algorithm and remedy, when this node's copy was not already in the
// pause (ADR 0028), rather than one per SET or per refused request.
func (r *router) takeKeyUnavailablePause(stream *model.StreamStateRecord, component string, cause error) {
	r.takeKeyUnavailablePauseAt(stream, component, cause, time.Now().UTC())
}

// takeKeyUnavailablePauseAt is takeKeyUnavailablePause with the pause starting
// at since.
func (r *router) takeKeyUnavailablePauseAt(stream *model.StreamStateRecord, component string, cause error, since time.Time) {
	sc := stream.StreamConfiguration
	sid := sc.Id
	reason := component + ": " + r.keyUnavailableReason(sc)
	if cause != nil {
		r.dropCachedKey(sc.Iss, sc.SigningAlg)
	}

	first := !inKeyUnavailablePause(stream)
	var pollBuffer interface{ Wakeup() }
	r.mu.Lock()
	switch {
	case stream.GetType() == model.DeliverySstpPair:
		if local, ok := r.sstpClientStreams[stream.PairId]; ok {
			first = !inKeyUnavailablePause(&local)
			local.SetKeyUnavailablePause(reason, since)
			r.sstpClientStreams[stream.PairId] = local
		}
		if local, ok := r.sstpServerStreams[sid]; ok {
			first = !inKeyUnavailablePause(&local)
			local.SetKeyUnavailablePause(reason, since)
			r.sstpServerStreams[sid] = local
		}
	default:
		if local, ok := r.pollStreams[sid]; ok {
			first = !inKeyUnavailablePause(&local)
			local.SetKeyUnavailablePause(reason, since)
			r.pollStreams[sid] = local
		}
		if pb, ok := r.pollBuffers[sid]; ok {
			pollBuffer = pb
		}
	}
	r.mu.Unlock()

	// Always written, even when this node's copy already shows the pause: that
	// copy can be stale if another node has resumed the stream meanwhile.
	r.streamService.UpdateKeyUnavailablePause(r.ctx, sid, reason, since)
	from := stream.Status
	stream.SetKeyUnavailablePause(reason, since)
	if pollBuffer != nil {
		pollBuffer.Wakeup()
	}
	if !first {
		return
	}
	logArgs := []any{"sid", sid, "issuer", sc.Iss, "alg", signingKeyAlg(sc), "remedy", signingKeyRemedy}
	if stream.PairId != "" {
		logArgs = append(logArgs, "pairId", stream.PairId)
	}
	if cause != nil {
		logArgs = append(logArgs, "error", cause)
	}
	eventLogger.Error(component+": no active signing key for the stream's issuer; stream paused, events stay queued", logArgs...)
	if r.stats != nil && from != model.StreamStatePause {
		r.stats.RecordStateTransition(sid, from, model.StreamStatePause)
	}
}

// CheckSstpSigningKey is the SSTP accepting end's key check (#312). See the
// EventRouter interface.
func (r *router) CheckSstpSigningKey(rec *model.StreamStateRecord) error {
	if rec == nil || rec.Status != model.StreamStateEnabled || !isSigningTransmitter(rec) {
		return nil
	}
	cfg := rec.StreamConfiguration
	if key, _ := r.checkAndLoadKey(cfg.Id, cfg.Iss, cfg.SigningAlg); key != nil {
		return nil
	}
	r.takeKeyUnavailablePause(rec, "SSTP-SRV", nil)
	return errNoActiveSigningKey(cfg)
}

// PauseForSigningKey is the SSTP dialing end's key-unavailable pause (#312).
// See SstpOutbound.
func (r *router) PauseForSigningKey(stream *model.StreamStateRecord, cause error) {
	r.takeKeyUnavailablePause(stream, "SSTP-CLIENT", cause)
}

// expiryWarner is the KeyService's signing-key expiry WARN (#318), optional so a
// stub signerSource need not provide it.
type expiryWarner interface {
	WarnExpiringSigningKeys(ctx context.Context)
}

// keyCheckComponent names the end that takes rec's key-unavailable pause in the
// background key check: the poll server or the SSTP pair's transmit end.
func keyCheckComponent(rec *model.StreamStateRecord) string {
	if rec.GetType() == model.DeliverySstpPair {
		return "SSTP-SRV"
	}
	return "POLL-SRV"
}

// runKeyUnavailableCheck runs the background key check every retry delay until
// the router shuts down. The retry settings are the push receiver-401 ones
// (I2SIG_PUSH_AUTH_RETRY_DELAY / _LIMIT), as for a push key pause (#308).
func (r *router) runKeyUnavailableCheck(cfg RecoveryConfig) {
	for SleepCtx(r.ctx, cfg.AuthRetryDelay) {
		r.checkKeyUnavailablePauses(cfg)
	}
}

// checkKeyUnavailablePauses is one pass of the background key check (#312) over
// the stored poll transmitters and SSTP pairs:
//
//   - enabled, signing, and its issuer's only key is now expired or not yet
//     valid (#318): take the stored key-unavailable
//     pause, even with nothing to send, so the stream status tells a receiver
//     why the stream is down;
//   - paused with the marker and the key active again: set enabled, which clears
//     the reason and the marker;
//   - paused with the marker, the key still missing, and the limit (retry delay
//     times retry limit) passed since the marker: set disabled with the reason,
//     which clears the marker;
//   - otherwise it is left alone. A key store that cannot answer changes nothing.
//
// A stored record without the marker whose copy on this node still has it was
// resumed or changed on another node; this node's copy is brought up to date, so
// a dial loop paused here restarts. Several nodes running the check at once is
// harmless: every write is conditional on the record still being in the same
// pause (resolveKeyUnavailablePause).
//
// Each pass also WARNs of signing keys about to expire (#318); the KeyService
// paces that to once a day per key. It also nudges this node's push runners,
// each of which checks its own key and takes its own pause (#308), so an idle
// push stream is paused at expiry rather than at its next delivery.
func (r *router) checkKeyUnavailablePauses(cfg RecoveryConfig) {
	cfg.fillDefaults()
	if w, ok := r.keyService.(expiryWarner); ok {
		w.WarnExpiringSigningKeys(r.ctx)
	}
	r.nudgePushRunnersKeyCheck()
	recs, err := r.streamService.ListTransmitterStreams(r.ctx)
	if err != nil {
		if r.ctx.Err() == nil {
			eventLogger.Warn("Key check: could not list transmitter streams", "error", err)
		}
		return
	}
	limit := cfg.AuthRetryDelay * time.Duration(cfg.AuthRetryLimit)
	outside := map[string]bool{}
	for i := range recs {
		rec := &recs[i]
		if !keyCheckedStream(rec) {
			continue
		}
		if !inKeyUnavailablePause(rec) {
			if rec.Status == model.StreamStateEnabled && isSigningTransmitter(rec) && r.signingKeyOutsideValidity(rec, outside) {
				r.pauseAtKeyCheck(rec, cfg.Clock().UTC())
				continue
			}
			r.syncResolvedKeyPause(rec)
			continue
		}
		err := r.streamService.RequireActiveSigningKey(r.ctx, rec)
		switch {
		case err == nil:
			r.resolveKeyUnavailablePause(rec, model.StreamStateEnabled, "")
		case !errors.Is(err, services.ErrInvalidRequest):
			eventLogger.Warn("Key check: could not check the signing key", "sid", rec.StreamConfiguration.Id, "error", err)
		case cfg.Clock().Sub(*rec.KeyUnavailableSince) >= limit:
			r.resolveKeyUnavailablePause(rec, model.StreamStateDisable, rec.ErrorMsg)
		}
	}
}

// signingKeyOutsideValidity reports whether rec's issuer has no active signing
// key of its signing_alg at the key service's clock because its key is expired
// or not yet valid (#318). A missing key without a validity cause is left to
// the next signing attempt (#312), so the brief gap of a key replace pauses
// nothing; a key store that cannot answer is not a missing key. memo holds the
// answers of one pass per issuer and algorithm.
func (r *router) signingKeyOutsideValidity(rec *model.StreamStateRecord, memo map[string]bool) bool {
	cfg := rec.StreamConfiguration
	cacheKey := signingCacheKey(cfg.Iss, cfg.SigningAlg)
	if answer, ok := memo[cacheKey]; ok {
		return answer
	}
	_, _, err := r.keyService.GetSigner(r.ctx, cfg.Iss, cfg.SigningAlg)
	answer := false
	switch {
	case errors.Is(err, interfaces.ErrKeyNotFound):
		answer = r.keyUnavailableForValidity(cfg)
	case err != nil && r.ctx.Err() == nil:
		eventLogger.Warn("Key check: could not check the signing key", "sid", cfg.Id, "error", err)
	}
	memo[cacheKey] = answer
	return answer
}

// pauseAtKeyCheck takes listed's key-unavailable pause from the background key
// check, starting at since. The stored record is re-read first and paused only
// while it is still enabled, so an operator change made meanwhile wins.
func (r *router) pauseAtKeyCheck(listed *model.StreamStateRecord, since time.Time) {
	current, err := r.streamService.GetStreamState(r.ctx, listed.StreamConfiguration.Id)
	if err != nil || current == nil || current.Status != model.StreamStateEnabled {
		return
	}
	r.dropCachedKey(listed.StreamConfiguration.Iss, listed.StreamConfiguration.SigningAlg)
	r.takeKeyUnavailablePauseAt(listed, keyCheckComponent(listed), nil, since)
}

// nudgePushRunnersKeyCheck asks every push runner on this node to check its
// signing key. It never blocks: a runner with a nudge already pending needs no
// second one.
func (r *router) nudgePushRunnersKeyCheck() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, runner := range r.pushRunners {
		runner.nudgeKeyCheck()
	}
}

// resolveKeyUnavailablePause ends listed's key-unavailable pause with status and
// reason, through the path an operator's status change takes on this node: the
// stream store, then the router, so the poll copy and the SSTP dial loop react.
// The stored record is re-read first and written only while it is still in the
// same pause, so an operator change made meanwhile, or another node's check,
// wins.
func (r *router) resolveKeyUnavailablePause(listed *model.StreamStateRecord, status, reason string) {
	sc := listed.StreamConfiguration
	sid := sc.Id
	current, err := r.streamService.GetStreamState(r.ctx, sid)
	if err != nil || !inKeyUnavailablePause(current) || !current.KeyUnavailableSince.Equal(*listed.KeyUnavailableSince) {
		return
	}
	r.streamService.UpdateStreamStatus(r.ctx, sid, status, reason)
	if status == model.StreamStateEnabled {
		eventLogger.Info("Key check: signing key active again; stream resumed",
			"sid", sid, "issuer", sc.Iss, "alg", signingKeyAlg(sc), "pausedSince", *listed.KeyUnavailableSince)
	} else {
		eventLogger.Error("Key check: still no active signing key after the retry limit; stream disabled",
			"sid", sid, "issuer", sc.Iss, "alg", signingKeyAlg(sc), "remedy", signingKeyRemedy, "pausedSince", *listed.KeyUnavailableSince)
	}
	if r.stats != nil {
		r.stats.RecordStateTransition(sid, model.StreamStatePause, status)
	}
	if fresh, err := r.streamService.GetStreamStateBySID(r.ctx, sid); err == nil && fresh != nil {
		r.UpdateStreamState(fresh)
	}
}

// syncResolvedKeyPause brings this node's copy of stored up to date when that
// copy is still in a key-unavailable pause the stored record no longer carries.
func (r *router) syncResolvedKeyPause(stored *model.StreamStateRecord) {
	r.mu.RLock()
	var local model.StreamStateRecord
	var ok bool
	if stored.GetType() == model.DeliverySstpPair {
		local, ok = r.sstpClientStreams[stored.PairId]
		if !ok {
			local, ok = r.sstpServerStreams[stored.StreamConfiguration.Id]
		}
	} else {
		local, ok = r.pollStreams[stored.StreamConfiguration.Id]
	}
	r.mu.RUnlock()
	if ok && local.KeyUnavailableSince != nil {
		r.UpdateStreamState(stored)
	}
}
