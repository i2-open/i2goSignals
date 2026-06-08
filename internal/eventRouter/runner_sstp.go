package eventRouter

import (
	"context"
	"crypto/rsa"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SSTP-client runner (PRD #154 slice 7, issue #164).
//
// The SSTP-client (initiator) side of an SSTP pair opens and re-opens the single
// HTTP connection cycle, owned by exactly one cluster node via an
// sstp-client:<PairId> Mongo lease (30s lease, 10s heartbeat). It is parallel to
// PushStreamHandler/runPushLoop but uses an EventPollBuffer for the
// outbound-to-flush queue and the SSTP wire classifier for failure handling.

const (
	// sstpLeaseDuration is the lease TTL; sstpHeartbeatInterval is the renew
	// cadence — mirroring the push-transmitter lease (Q4.1, Q14).
	sstpLeaseDuration     = 30 * time.Second
	sstpHeartbeatInterval = 10 * time.Second

	// sstpTakeoverJitterMin/Max bound the randomized delay a new lease owner
	// waits before opening its first connection, spreading thundering-herd after
	// a cluster-wide blip (Q16).
	sstpTakeoverJitterMin = 100 * time.Millisecond
	sstpTakeoverJitterMax = 500 * time.Millisecond
)

// sstpBackoffConfig holds the POLL_RETRY_* exponential-backoff parameters used by
// the SSTP-client transport/transient retry path (Q25). The same env knobs tune
// the poll receiver, so operators have one place to configure both.
type sstpBackoffConfig struct {
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64

	// LeaseDuration / HeartbeatInterval are the lease TTL and renew cadence.
	// Production uses sstpLeaseDuration / sstpHeartbeatInterval; tests shrink
	// them to keep the heartbeat / lease-loss paths fast.
	LeaseDuration     time.Duration
	HeartbeatInterval time.Duration
	// HeartbeatRetryDelay is the pause before the single heartbeat-renew retry
	// (Q14.c). Defaults to 1s; tests shrink it.
	HeartbeatRetryDelay time.Duration

	// Sleep waits for d or returns false when ctx is cancelled. Defaults to
	// defaultSleep; tests inject a deterministic implementation.
	Sleep func(ctx context.Context, d time.Duration) bool
	// Jitter returns the takeover jitter to wait before the first connection.
	// Defaults to a uniform draw in [sstpTakeoverJitterMin, sstpTakeoverJitterMax].
	Jitter func() time.Duration
}

func (c *sstpBackoffConfig) fillDefaults() {
	if c.BaseDelay <= 0 {
		c.BaseDelay = 1 * time.Second
	}
	if c.MaxDelay <= 0 {
		c.MaxDelay = 5 * time.Minute
	}
	if c.BackoffFactor <= 1.0 {
		c.BackoffFactor = 2.0
	}
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = sstpLeaseDuration
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = sstpHeartbeatInterval
	}
	if c.HeartbeatRetryDelay <= 0 {
		c.HeartbeatRetryDelay = 1 * time.Second
	}
	if c.Sleep == nil {
		c.Sleep = defaultSleep
	}
	if c.Jitter == nil {
		c.Jitter = defaultSstpJitter
	}
}

// defaultSstpJitter draws a uniform takeover delay in [min, max] (Q16).
func defaultSstpJitter() time.Duration {
	span := sstpTakeoverJitterMax - sstpTakeoverJitterMin
	return sstpTakeoverJitterMin + time.Duration(rand.Int63n(int64(span)+1))
}

// loadSstpBackoffConfig reads the POLL_RETRY_* env knobs (Q25). Seconds-valued
// floats, parsed via envcompat so the v0.11.0 I2SIG_POLL_* names take precedence
// over the legacy POLL_* names.
func loadSstpBackoffConfig() sstpBackoffConfig {
	cfg := sstpBackoffConfig{
		BaseDelay:     parseSecondsEnv("I2SIG_POLL_RETRY_BASE_DELAY", "POLL_RETRY_BASE_DELAY", 1*time.Second),
		MaxDelay:      parseSecondsEnv("I2SIG_POLL_RETRY_MAX_DELAY", "POLL_RETRY_MAX_DELAY", 5*time.Minute),
		BackoffFactor: parseFloatEnv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "POLL_RETRY_BACKOFF_FACTOR", 2.0),
	}
	cfg.fillDefaults()
	return cfg
}

// parseSecondsEnv reads a float-seconds env var (POLL_RETRY_* are seconds-valued)
// and returns the corresponding Duration, falling back to defaultVal.
func parseSecondsEnv(name, oldName string, defaultVal time.Duration) time.Duration {
	v := envcompat.Lookup(name, oldName)
	if v == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		eventLogger.Warn("SSTP-CLIENT: invalid float env var, using default", "name", name, "value", v, "default", defaultVal)
		return defaultVal
	}
	return time.Duration(f * float64(time.Second))
}

// sstpConfig returns the runner's backoff/lease config. Production loads it from
// the POLL_RETRY_* env knobs; tests may set r.sstpCfgOverride for deterministic,
// fast lease/heartbeat timing.
func (r *router) sstpConfig() sstpBackoffConfig {
	r.mu.RLock()
	override := r.sstpCfgOverride
	r.mu.RUnlock()
	if override != nil {
		cfg := *override
		cfg.fillDefaults()
		return cfg
	}
	return loadSstpBackoffConfig()
}

// initSstpClientStreamLocked registers an SSTP pair's client side and starts its
// runner. The caller must hold r.mu.
func (r *router) initSstpClientStreamLocked(state *model.StreamStateRecord, jtis []string) {
	pairId := state.PairId
	r.sstpClientStreams[pairId] = *state
	buf := buffer.CreateEventPollBuffer(jtis, r.pollDefaultTimeoutSecs, r.pollMaxTimeoutSecs)
	r.sstpBuffers[pairId] = buf
	go r.SstpClientStreamHandler(state, buf)
}

// SstpClientStreamHandler manages the lifecycle of an SSTP-client connection for
// a pair: it acquires the sstp-client:<PairId> lease, runs the cycle loop while it
// holds the lease, and re-acquires after lease loss. Mirrors PushStreamHandler.
func (r *router) SstpClientStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPollBuffer) {
	pairId := stream.PairId
	resource := fmt.Sprintf("sstp-client:%s", pairId)
	cfg := r.sstpConfig()

	for {
		if stream.Status != model.StreamStateEnabled {
			eventLogger.Info("SSTP-CLIENT no longer enabled. Handler exiting.", "pairId", pairId)
			return
		}

		acquired, fencingToken, err := r.coordinator.TryAcquireOrRenewLease(resource, r.nodeId, cfg.LeaseDuration)
		if r.stats != nil {
			r.stats.TrackLeaseAcquisition(resource, acquired && err == nil)
		}
		if err != nil {
			eventLogger.Error("SSTP-CLIENT: lease acquisition error", "pairId", pairId, "error", err)
		}

		if !acquired {
			eventLogger.Debug("SSTP-CLIENT: lease not held, waiting...", "pairId", pairId)
			select {
			case <-time.After(cfg.HeartbeatInterval + cfg.LeaseDuration/2):
				continue
			case <-r.ctx.Done():
				return
			}
		}

		eventLogger.Info("SSTP-CLIENT: lease acquired, opening connection", "pairId", pairId)
		// Takeover jitter (Q16): spread the thundering-herd after a cluster blip.
		if !cfg.Sleep(r.ctx, cfg.Jitter()) {
			r.releaseSstpLease(resource, pairId)
			return
		}

		shouldRetry := r.runSstpClientLoop(resource, stream, eventBuf, fencingToken, cfg)
		r.releaseSstpLease(resource, pairId)
		if !shouldRetry {
			return
		}

		select {
		case <-r.ctx.Done():
			return
		default:
		}
	}
}

// releaseSstpLease explicitly releases the Mongo lease so the next node can take
// over immediately (Q14.b graceful-shutdown / lease-loss handoff).
func (r *router) releaseSstpLease(resource, pairId string) {
	if err := r.coordinator.ReleaseLeaseIfOwned(resource, r.nodeId); err != nil {
		eventLogger.Warn("SSTP-CLIENT: lease release failed", "pairId", pairId, "error", err)
	}
}

// runSstpClientLoop runs SSTP HTTP cycles while this node holds the lease.
// A heartbeat goroutine renews the lease every sstpHeartbeatInterval, retrying a
// single failed renew once before declaring the lease lost (Q14.c). The loop's
// context (cycleCtx) parents every HTTP cycle; losing the lease or shutting down
// cancels cycleCtx, aborting any in-flight cycle (Q14.a). Returns true when the
// caller should attempt to re-acquire (lease lost), false to exit (shutdown,
// buffer closed, stream disabled).
func (r *router) runSstpClientLoop(resource string, stream *model.StreamStateRecord, eventBuf *buffer.EventPollBuffer, fencingToken int64, cfg sstpBackoffConfig) bool {
	pairId := stream.PairId
	if r.stats != nil {
		r.stats.IncLeasesHeld()
		defer r.stats.DecLeasesHeld()
	}

	// cycleCtx parents every outbound HTTP cycle. Cancelled on lease loss
	// (heartbeat) or router shutdown (r.ctx) so in-flight requests abort.
	cycleCtx, cycleCancel := context.WithCancel(r.ctx)
	defer cycleCancel()

	go r.sstpHeartbeat(cycleCtx, cycleCancel, resource, pairId, cfg)

	delay := cfg.BaseDelay
	wakeup := eventBuf.WakeupCh()

	for {
		select {
		case <-cycleCtx.Done():
			// Lease lost or shutdown. Distinguish: if the router is shutting down,
			// exit; otherwise re-acquire.
			if r.ctx.Err() != nil {
				return false
			}
			return true
		default:
		}

		outcome, resumeDelay, exit := r.runSstpCycle(cycleCtx, stream, eventBuf, fencingToken, cfg, &delay)
		_ = outcome
		if exit {
			if r.ctx.Err() != nil {
				return false
			}
			return true
		}

		// On a delay (transport/transient/idle empty buffer), wait it out, but
		// wake early on a new outbound event or lease loss.
		if resumeDelay > 0 {
			timer := time.NewTimer(resumeDelay)
			select {
			case <-cycleCtx.Done():
				timer.Stop()
				if r.ctx.Err() != nil {
					return false
				}
				return true
			case <-wakeup:
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}

// runSstpCycle performs one SSTP HTTP cycle: drain the outbound buffer, deliver
// via the seam, and apply the classifier result. It returns the classification,
// the delay the caller should wait before the next cycle (0 = immediate), and
// exit=true when the loop should terminate (stream disabled or context done).
// delay carries the running exponential-backoff value across transport/transient
// retries; it is reset to BaseDelay on a successful (ClassOK/ClassPerJTI) cycle.
func (r *router) runSstpCycle(ctx context.Context, stream *model.StreamStateRecord, eventBuf *buffer.EventPollBuffer, fencingToken int64, cfg sstpBackoffConfig, delay *time.Duration) (goSetSstp.Classification, time.Duration, bool) {
	pairId := stream.PairId
	sid := stream.StreamConfiguration.Id

	// Gather the outbound JTIs to flush this cycle. Drain whatever is already in
	// the buffer first; if it is empty, pull the pending list directly from the
	// provider (recovery after takeover relies on persisted outbound events,
	// Q13). The direct pull avoids racing the buffer's async channel drain.
	outJtis := drainSstpBuffer(eventBuf, r.backfillBatch)
	if len(outJtis) == 0 {
		outJtis, _ = r.eventService.GetEventIds(r.ctx, sid, model.PollParameters{
			MaxEvents:         int32(r.backfillBatch),
			ReturnImmediately: true,
		})
	}

	// Nothing to flush: idle a short cycle so we don't busy-loop. (The inbound
	// long-poll wait is the SSTP-server runner's job, #165.)
	if len(outJtis) == 0 {
		*delay = cfg.BaseDelay
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}, cfg.BaseDelay, false
	}

	events := r.resolveSstpEventsByJti(outJtis)

	var rsaKey *rsa.PrivateKey
	var kid string
	if stream.GetRouteMode() != model.RouteModeForward {
		rsaKey, kid = r.checkAndLoadKey(stream.StreamConfiguration.Id, stream.StreamConfiguration.Iss)
	}

	outcome := r.sstpDelivery.DeliverSstp(ctx, delivery.SstpRequest{
		Stream: stream,
		Events: events,
		Key:    rsaKey,
		Kid:    kid,
	})

	if ctx.Err() != nil {
		return outcome.Classification, 0, true
	}

	cls := outcome.Classification
	switch cls.Class {
	case goSetSstp.ClassOK, goSetSstp.ClassPerJTI:
		acked := r.handleSstpAcks(stream, outcome.Acked, events, fencingToken)
		*delay = cfg.BaseDelay
		// If we acked everything we sent, the next cycle can drain more
		// immediately; otherwise idle a short cycle to avoid re-sending the same
		// un-acked SETs in a tight loop.
		if acked >= len(events) {
			return cls, 0, false
		}
		return cls, cfg.BaseDelay, false

	case goSetSstp.ClassRequestError:
		// 4xx: pause ONLY the outbound (client) direction of the pair. Inbound
		// (server side) keeps running independently (Q12.3).
		reason := fmt.Sprintf("SSTP-CLIENT: 4xx request error on pair=%s", pairId)
		r.pauseSstpOutbound(stream, reason)
		return cls, 0, true

	case goSetSstp.ClassTransient, goSetSstp.ClassTransport:
		// 5xx / connection failure: back off per POLL_RETRY_*, do NOT pause (Q25).
		next := *delay
		if cls.NextDelay > 0 {
			next = cls.NextDelay
		}
		eventLogger.Warn("SSTP-CLIENT: transport/transient failure, backing off",
			"pairId", pairId, "class", cls.Class.String(), "delay", next)
		*delay = nextBackoff(*delay, cfg.BackoffFactor, cfg.MaxDelay)
		return cls, next, false

	default: // ClassWeirdResponse
		reason := fmt.Sprintf("SSTP-CLIENT: weird response on pair=%s", pairId)
		r.pauseSstpOutbound(stream, reason)
		return cls, 0, true
	}
}

// sstpHeartbeat renews the lease every sstpHeartbeatInterval. A single renew
// failure is retried once after a short pause before the lease is declared lost
// (Q14.c) — one-shot Mongo blips do not trigger takeover churn. On a confirmed
// loss it cancels cycleCtx, aborting any in-flight cycle (Q14.a).
func (r *router) sstpHeartbeat(cycleCtx context.Context, cancel context.CancelFunc, resource, pairId string, cfg sstpBackoffConfig) {
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if r.renewSstpLeaseWithRetry(cycleCtx, resource, pairId, cfg) {
				continue
			}
			eventLogger.Warn("SSTP-CLIENT: lease lost, cancelling in-flight cycle", "pairId", pairId)
			cancel()
			return
		case <-cycleCtx.Done():
			return
		}
	}
}

// renewSstpLeaseWithRetry attempts a lease renew; on failure it retries exactly
// once after a 1s pause (cancellable via ctx). Returns true while ownership is
// retained, false once the lease is confirmed lost.
func (r *router) renewSstpLeaseWithRetry(ctx context.Context, resource, pairId string, cfg sstpBackoffConfig) bool {
	ok, _, err := r.coordinator.TryAcquireOrRenewLease(resource, r.nodeId, cfg.LeaseDuration)
	if r.stats != nil {
		r.stats.TrackLeaseAcquisition(resource, ok && err == nil)
	}
	if ok && err == nil {
		return true
	}
	eventLogger.Debug("SSTP-CLIENT: heartbeat renew blip, retrying once", "pairId", pairId, "error", err)

	// Single retry after a brief pause; a transient Mongo blip should clear.
	t := time.NewTimer(cfg.HeartbeatRetryDelay)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
		return false
	}

	ok, _, err = r.coordinator.TryAcquireOrRenewLease(resource, r.nodeId, cfg.LeaseDuration)
	if r.stats != nil {
		r.stats.TrackLeaseAcquisition(resource, ok && err == nil)
	}
	return ok && err == nil
}

// drainSstpBuffer pops up to max JTIs currently resident in the buffer (the
// synchronous portion — events whose async channel-drain has completed). Returns
// nil when the buffer is empty.
func drainSstpBuffer(eventBuf *buffer.EventPollBuffer, max int) []string {
	jtis, _ := eventBuf.GetEvents(model.PollParameters{
		MaxEvents:         int32(max),
		ReturnImmediately: true,
	})
	if jtis == nil || len(*jtis) == 0 {
		return nil
	}
	out := make([]string, len(*jtis))
	copy(out, *jtis)
	return out
}

// resolveSstpEventsByJti turns a slice of JTIs into the event records to flush,
// skipping any that have since been deleted.
func (r *router) resolveSstpEventsByJti(jtis []string) []*model.AgEventRecord {
	if len(jtis) == 0 {
		return nil
	}
	events := make([]*model.AgEventRecord, 0, len(jtis))
	for _, jti := range jtis {
		rec := r.eventService.GetEventRecord(r.ctx, jti)
		if rec == nil {
			continue
		}
		events = append(events, rec)
	}
	return events
}

// handleSstpAcks acks (in the provider) the peer-acknowledged JTIs that we
// actually sent this cycle, and increments the outbound eventsOut counter
// (tfr=SSTP, stream_id=txSid) per acked event (Q46). A peer ack is honored only
// for JTIs in the sent set — a stray ack for something we did not send is
// ignored, so an un-sent SET is never removed from the pending list. When the
// peer returns no explicit ack list, every SET sent this cycle is treated as
// accepted (the §2.3 success-without-detail case). Returns the number of acked
// (and counted) events.
func (r *router) handleSstpAcks(stream *model.StreamStateRecord, acked []string, sent []*model.AgEventRecord, fencingToken int64) int {
	sid := stream.StreamConfiguration.Id
	if len(sent) == 0 {
		return 0
	}

	sentByJti := make(map[string]*model.AgEventRecord, len(sent))
	for _, ev := range sent {
		sentByJti[ev.Jti] = ev
	}

	ackSet := acked
	if len(ackSet) == 0 {
		ackSet = make([]string, 0, len(sent))
		for _, ev := range sent {
			ackSet = append(ackSet, ev.Jti)
		}
	}

	count := 0
	for _, jti := range ackSet {
		ev := sentByJti[jti]
		if ev == nil {
			continue // ack for a JTI we did not send this cycle — ignore.
		}
		_ = r.eventService.AckEvent(r.ctx, jti, sid, fencingToken)
		r.IncrementCounter(stream, &ev.Event, false)
		count++
	}
	return count
}

// pushSstpWhilePollHeld performs a SECOND, parallel SSTP POST to flush queued
// outbound SETs while the pair's primary long-poll cycle is held open by the peer
// (push-while-poll-held, Q7.2, #166). It carries returnEvents=false so the peer
// returns immediately without holding a long-poll for this short-lived push, and
// classifies the response through the same goSetSstp classifier as the primary
// cycle. On 4xx it pauses ONLY the outbound direction (Q12.3); on 5xx/transport it
// does not pause (the primary cycle owns backoff). The held primary cycle is
// unaffected — this is an independent HTTP request with its own context.
//
// Concurrency is bounded to at most one in-flight secondary push per pair: if a
// push is already running for the pair, this call returns ClassOK without opening
// a third parallel request (the in-flight push drains the shared buffer, Q7.2).
func (r *router) pushSstpWhilePollHeld(ctx context.Context, stream *model.StreamStateRecord, eventBuf *buffer.EventPollBuffer, fencingToken int64) goSetSstp.Classification {
	pairId := stream.PairId
	sid := stream.StreamConfiguration.Id

	if !r.acquireSstpSecondPushSlot(pairId) {
		// A secondary push is already in flight for this pair; coalesce.
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}
	}
	defer r.releaseSstpSecondPushSlot(pairId)

	// Drain whatever outbound is queued; recovery after takeover relies on persisted
	// outbound events, so fall back to the provider's pending list when the buffer's
	// async drain has not yet surfaced anything (mirrors runSstpCycle).
	outJtis := drainSstpBuffer(eventBuf, r.backfillBatch)
	if len(outJtis) == 0 {
		outJtis, _ = r.eventService.GetEventIds(r.ctx, sid, model.PollParameters{
			MaxEvents:         int32(r.backfillBatch),
			ReturnImmediately: true,
		})
	}
	if len(outJtis) == 0 {
		// Nothing to push: do not open a second POST.
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}
	}

	events := r.resolveSstpEventsByJti(outJtis)
	if len(events) == 0 {
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}
	}

	var rsaKey *rsa.PrivateKey
	var kid string
	if stream.GetRouteMode() != model.RouteModeForward {
		rsaKey, kid = r.checkAndLoadKey(stream.StreamConfiguration.Id, stream.StreamConfiguration.Iss)
	}

	outcome := r.sstpDelivery.DeliverSstp(ctx, delivery.SstpRequest{
		Stream:       stream,
		Events:       events,
		Key:          rsaKey,
		Kid:          kid,
		ReturnEvents: goSetSstp.BoolPtr(false),
	})

	cls := outcome.Classification
	switch cls.Class {
	case goSetSstp.ClassOK, goSetSstp.ClassPerJTI:
		r.handleSstpAcks(stream, outcome.Acked, events, fencingToken)
	case goSetSstp.ClassRequestError:
		// 4xx on the second push pauses ONLY the outbound direction; the held
		// primary long-poll (inbound) continues uninterrupted (Q12.3).
		r.pauseSstpOutbound(stream, fmt.Sprintf("SSTP-CLIENT: 4xx on push-while-poll-held for pair=%s", pairId))
	case goSetSstp.ClassWeirdResponse:
		r.pauseSstpOutbound(stream, fmt.Sprintf("SSTP-CLIENT: weird response on push-while-poll-held for pair=%s", pairId))
	default: // ClassTransient / ClassTransport: do not pause; the primary cycle owns backoff.
		eventLogger.Warn("SSTP-CLIENT: push-while-poll-held transport/transient failure",
			"pairId", pairId, "class", cls.Class.String())
	}
	return cls
}

// acquireSstpSecondPushSlot reserves the single in-flight push-while-poll-held slot
// for a pair, returning false when one is already held (Q7.2 concurrency bound).
func (r *router) acquireSstpSecondPushSlot(pairId string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sstpSecondPushInFlight[pairId] {
		return false
	}
	r.sstpSecondPushInFlight[pairId] = true
	return true
}

// releaseSstpSecondPushSlot releases the in-flight push-while-poll-held slot.
func (r *router) releaseSstpSecondPushSlot(pairId string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sstpSecondPushInFlight, pairId)
}

// pauseSstpOutbound pauses ONLY the outbound (client) direction of the pair by
// setting the record's Status to paused via the single transition point. The
// inbound side (InboundStatus) is owned by the SSTP-server runner (#165) and is
// untouched here (Q12.3).
func (r *router) pauseSstpOutbound(stream *model.StreamStateRecord, reason string) {
	r.updateStream(stream, model.StreamStatePause, reason)
}
