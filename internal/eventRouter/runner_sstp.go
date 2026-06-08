package eventRouter

import (
	"context"
	"crypto/rsa"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
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
//
// Finding #9: r.sstpClientStreams[pairId] is the SINGLE source of truth for the
// pair's live config (endpoint, bearer, status). The runner does NOT close over a
// divergent copy; it re-reads the map under r.mu each cycle (refreshSstpClientStream)
// so a rotated bearer / changed endpoint / pause applied via UpdateStreamState is
// observed within one cycle. We pass a fresh copy to the goroutine purely as its
// initial snapshot.
func (r *router) initSstpClientStreamLocked(state *model.StreamStateRecord, jtis []string) {
	pairId := state.PairId
	r.sstpClientStreams[pairId] = *state
	buf := buffer.CreateEventPollBuffer(jtis, r.pollDefaultTimeoutSecs, r.pollMaxTimeoutSecs)
	r.sstpBuffers[pairId] = buf
	initial := *state
	go r.SstpClientStreamHandler(&initial, buf)
}

// refreshSstpClientStream returns the current source-of-truth record for the pair
// from r.sstpClientStreams under r.mu. ok=false means the pair has been removed
// (RemoveStream / Finding #8) and the runner should exit. The returned value is a
// copy, safe to read without further locking. (Finding #9.)
func (r *router) refreshSstpClientStream(pairId string) (model.StreamStateRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.sstpClientStreams[pairId]
	return rec, ok
}

// SstpClientStreamHandler manages the lifecycle of an SSTP-client connection for
// a pair: it acquires the sstp-client:<PairId> lease, runs the cycle loop while it
// holds the lease, and re-acquires after lease loss. Mirrors PushStreamHandler.
func (r *router) SstpClientStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPollBuffer) {
	pairId := stream.PairId
	resource := fmt.Sprintf("sstp-client:%s", pairId)
	cfg := r.sstpConfig()

	for {
		// Finding #9 / #8: re-read the live record from the source-of-truth map. A
		// missing entry means the pair was removed (RemoveStream); a non-enabled
		// status means it was paused/disabled. Either way the handler exits and the
		// goroutine stops — no leak.
		live, ok := r.refreshSstpClientStream(pairId)
		if !ok {
			eventLogger.Info("SSTP-CLIENT pair removed. Handler exiting.", "pairId", pairId)
			return
		}
		*stream = live
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

		// Finding #9 / #8: refresh the live config from the source-of-truth map each
		// cycle so a rotated bearer / changed endpoint / pause applied via
		// UpdateStreamState (which mutates the map) is observed within one cycle, and
		// a RemoveStream (map entry gone) stops the loop. Returning false here exits
		// the handler entirely (do not re-acquire a deleted/paused pair's lease).
		live, ok := r.refreshSstpClientStream(pairId)
		if !ok || live.Status != model.StreamStateEnabled {
			return false
		}
		*stream = live

		// Run the primary cycle concurrently so the loop can react to a new outbound
		// SET arriving while the peer holds this cycle's connection open as a
		// long-poll (push-while-poll-held, Q7.2, #166). A synchronous call would
		// block here for the whole long-poll, delaying the new SET to the end of it.
		// While the primary is in flight we select on the buffer wake signal and fire
		// a bounded SECOND POST (returnEvents=false) to flush the freshly-arrived
		// outbound immediately. The second push uses cycleCtx, so lease loss /
		// shutdown cancels both the primary and any in-flight second push.
		outcome, resumeDelay, exit := r.runPrimaryCycleWithSecondPush(cycleCtx, stream, eventBuf, fencingToken, cfg, &delay)
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
			case <-eventBuf.WakeupCh():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}

// runPrimaryCycleWithSecondPush runs one primary SSTP cycle in a goroutine while
// the calling loop watches the outbound buffer's wake signal. When a new outbound
// SET arrives (SubmitEvent + Wakeup from routeEventToSstpPairsLocked / WakeSstpClient)
// WHILE the primary cycle is still held open by the peer as a long-poll, it fires a
// bounded SECOND POST (pushSstpWhilePollHeld, returnEvents=false) to flush the
// queued outbound immediately rather than waiting for the held long-poll to return
// (Q7.2, #166). The one-in-flight guard inside pushSstpWhilePollHeld coalesces a
// storm of wake-ups into at most one secondary push per pair. Both the primary
// cycle and any second push share ctx (cycleCtx), so lease loss / shutdown cancels
// both. Returns the primary cycle's (classification, resumeDelay, exit) verbatim.
func (r *router) runPrimaryCycleWithSecondPush(ctx context.Context, stream *model.StreamStateRecord, eventBuf *buffer.EventPollBuffer, fencingToken int64, cfg sstpBackoffConfig, delay *time.Duration) (goSetSstp.Classification, time.Duration, bool) {
	// Capture pairId before launching the primary cycle goroutine: PairId is stable
	// for the record's life, but reading it after the goroutine may write *stream
	// (updateStream on a pause) would otherwise be a concurrent access.
	pairId := stream.PairId
	type cycleResult struct {
		cls   goSetSstp.Classification
		delay time.Duration
		exit  bool
	}
	done := make(chan cycleResult, 1)
	go func() {
		cls, d, exit := r.runSstpCycle(ctx, stream, eventBuf, fencingToken, cfg, delay)
		done <- cycleResult{cls: cls, delay: d, exit: exit}
	}()

	// secondPushWg tracks any in-flight second-push goroutines so we do not leak
	// them past this cycle: we wait for them before returning. Each goroutine
	// respects ctx and releases its in-flight slot via pushSstpWhilePollHeld's defer.
	var secondPushWg sync.WaitGroup
	defer secondPushWg.Wait()

	wakeup := eventBuf.WakeupCh()
	for {
		select {
		case res := <-done:
			return res.cls, res.delay, res.exit
		case <-ctx.Done():
			// Lease loss / shutdown: the primary cycle observes ctx and returns
			// (with exit=true); wait for it so we return its result and never leak it.
			res := <-done
			return res.cls, res.delay, res.exit
		case <-wakeup:
			// A new outbound SET arrived (or a state-change wake) while the primary
			// cycle is held. Fire a bounded second push to flush it now. The guard in
			// pushSstpWhilePollHeld coalesces concurrent wakes to one in-flight push.
			wakeup = eventBuf.WakeupCh() // re-arm: Wakeup() swapped the notifier channel.
			// The second push gets its OWN copy of the record, snapshotted from the
			// source-of-truth map under r.mu (not the shared *stream the primary cycle
			// goroutine may be writing via updateStream on a pause — that would race).
			// The copy carries the live endpoint/bearer/route. A pause from the second
			// push still lands durably because pauseSstpOutbound writes it back into the
			// map, which the loop re-reads on its next cycle.
			live, ok := r.refreshSstpClientStream(pairId)
			if !ok {
				continue // pair removed; the primary cycle's next refresh exits the loop.
			}
			streamCopy := live
			secondPushWg.Add(1)
			go func() {
				defer secondPushWg.Done()
				r.pushSstpWhilePollHeld(ctx, &streamCopy, eventBuf, fencingToken)
			}()
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
	// the buffer first (claiming it in-flight so a concurrent push-while-poll-held
	// second push does not re-send the same SET, NEW Finding #2); if it is empty,
	// pull the pending list directly from the provider (recovery after takeover
	// relies on persisted outbound events, Q13) and claim those too. The direct pull
	// avoids racing the buffer's async channel drain.
	outJtis := r.drainSstpBuffer(pairId, eventBuf, r.backfillBatch)
	if len(outJtis) == 0 {
		pending, _ := r.eventService.GetEventIds(r.ctx, sid, model.PollParameters{
			MaxEvents:         int32(r.backfillBatch),
			ReturnImmediately: true,
		})
		outJtis = r.claimSstpJtis(pairId, pending)
	}

	// Nothing to flush: idle a short cycle so we don't busy-loop. (The inbound
	// long-poll wait is the SSTP-server runner's job, #165.)
	if len(outJtis) == 0 {
		*delay = cfg.BaseDelay
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}, cfg.BaseDelay, false
	}

	events := r.resolveSstpEventsByJti(outJtis)
	// resolveSstpEventsByJti may drop JTIs whose event record was deleted; release
	// the claim on those so we never leak a permanent claim for a vanished event.
	r.releaseUnresolvedSstpClaims(pairId, outJtis, events)

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
		// Cancelled in flight (lease loss / shutdown): release the claim so the
		// next owner re-drains and retries these events (they are not acked).
		r.releaseSstpEventClaims(pairId, events)
		return outcome.Classification, 0, true
	}

	cls := outcome.Classification
	switch cls.Class {
	case goSetSstp.ClassOK, goSetSstp.ClassPerJTI:
		acked := r.handleSstpAcks(stream, eventBuf, outcome.Acked, events, fencingToken)
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
		// (server side) keeps running independently (Q12.3). Release the claim so a
		// later resume re-drains and retries these (un-acked) events.
		r.releaseSstpEventClaims(pairId, events)
		reason := fmt.Sprintf("SSTP-CLIENT: 4xx request error on pair=%s", pairId)
		r.pauseSstpOutbound(stream, reason)
		return cls, 0, true

	case goSetSstp.ClassTransient, goSetSstp.ClassTransport:
		// 5xx / connection failure: back off per POLL_RETRY_*, do NOT pause (Q25).
		// Release the claim so the retried cycle re-drains these un-acked events.
		r.releaseSstpEventClaims(pairId, events)
		next := *delay
		if cls.NextDelay > 0 {
			next = cls.NextDelay
		}
		eventLogger.Warn("SSTP-CLIENT: transport/transient failure, backing off",
			"pairId", pairId, "class", cls.Class.String(), "delay", next)
		*delay = nextBackoff(*delay, cfg.BackoffFactor, cfg.MaxDelay)
		return cls, next, false

	default: // ClassWeirdResponse
		// Release the claim so a later resume re-drains and retries these events.
		r.releaseSstpEventClaims(pairId, events)
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

// drainSstpBuffer reads up to max JTIs currently resident in the buffer (the
// synchronous portion — events whose async channel-drain has completed) that are
// NOT already claimed in flight for the pair, and claims the survivors. EventPollBuffer.GetEvents
// only COPIES (it does not remove), so without the claim filter a SET already in
// flight in the primary long-poll cycle would be re-handed-out to a concurrent
// push-while-poll-held second push and re-sent (NEW Finding #2). Returns nil when
// the buffer is empty or every resident JTI is already claimed. Caller MUST later
// ack (ackSstpJtis) or release (releaseSstpClaims) the returned JTIs.
func (r *router) drainSstpBuffer(pairId string, eventBuf *buffer.EventPollBuffer, max int) []string {
	jtis, _ := eventBuf.GetEvents(model.PollParameters{
		MaxEvents:         int32(max),
		ReturnImmediately: true,
	})
	if jtis == nil || len(*jtis) == 0 {
		return nil
	}
	candidates := make([]string, len(*jtis))
	copy(candidates, *jtis)
	return r.claimSstpJtis(pairId, candidates)
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

// handleSstpAcks acks the peer-acknowledged JTIs that we actually sent this cycle:
// it removes each acked JTI from the pair's outbound buffer (eventBuf.AckEvents —
// NEW Finding #1: without this the buffer's copy-only GetEvents re-drains and
// re-sends an already-acked SET forever), acks it in the provider, clears its
// in-flight claim, and increments the outbound eventsOut counter (tfr=SSTP,
// stream_id=txSid) per acked event (Q46). A peer ack is honored only for JTIs in
// the sent set — a stray ack for something we did not send is ignored, so an
// un-sent SET is never removed. When the peer returns no explicit ack list, every
// SET sent this cycle is treated as accepted (the §2.3 success-without-detail
// case). Any sent-but-NOT-acked JTI has its in-flight claim released so it is
// re-drained and retried on a later cycle. Returns the number of acked (and
// counted) events. This mirrors the SSTP-server runner's inbound-Ack consumption
// (runner_sstp_server.go) and the RFC8936 poll path (event_router.go ~1035).
func (r *router) handleSstpAcks(stream *model.StreamStateRecord, eventBuf *buffer.EventPollBuffer, acked []string, sent []*model.AgEventRecord, fencingToken int64) int {
	sid := stream.StreamConfiguration.Id
	pairId := stream.PairId
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

	ackedJtis := make([]string, 0, len(ackSet))
	count := 0
	for _, jti := range ackSet {
		ev := sentByJti[jti]
		if ev == nil {
			continue // ack for a JTI we did not send this cycle — ignore.
		}
		_ = r.eventService.AckEvent(r.ctx, jti, sid, fencingToken)
		r.IncrementCounter(stream, &ev.Event, false)
		ackedJtis = append(ackedJtis, jti)
		count++
	}

	// Finding #1: remove the confirmed-delivered SETs from the outbound buffer so
	// GetEvents (copy-only) never re-hands them out, and clear their in-flight claim.
	if len(ackedJtis) > 0 {
		if eventBuf != nil {
			eventBuf.AckEvents(ackedJtis)
		}
		r.releaseSstpClaims(pairId, ackedJtis)
	}

	// Release the in-flight claim on any sent-but-unacked SET so it is re-drained
	// and retried on a later cycle (it stays in the buffer / pending list).
	ackedSet := make(map[string]bool, len(ackedJtis))
	for _, jti := range ackedJtis {
		ackedSet[jti] = true
	}
	unacked := make([]string, 0, len(sent))
	for _, ev := range sent {
		if !ackedSet[ev.Jti] {
			unacked = append(unacked, ev.Jti)
		}
	}
	r.releaseSstpClaims(pairId, unacked)

	return count
}

// releaseSstpEventClaims releases the in-flight claim on every JTI in events.
func (r *router) releaseSstpEventClaims(pairId string, events []*model.AgEventRecord) {
	if len(events) == 0 {
		return
	}
	jtis := make([]string, len(events))
	for i, ev := range events {
		jtis[i] = ev.Jti
	}
	r.releaseSstpClaims(pairId, jtis)
}

// releaseUnresolvedSstpClaims releases the claim on any claimed JTI that did NOT
// resolve to an event record (deleted between claim and resolve), so a vanished
// event never holds a permanent claim that would block an unrelated re-add.
func (r *router) releaseUnresolvedSstpClaims(pairId string, claimed []string, resolved []*model.AgEventRecord) {
	if len(claimed) == len(resolved) {
		return
	}
	have := make(map[string]bool, len(resolved))
	for _, ev := range resolved {
		have[ev.Jti] = true
	}
	gone := make([]string, 0, len(claimed)-len(resolved))
	for _, jti := range claimed {
		if !have[jti] {
			gone = append(gone, jti)
		}
	}
	r.releaseSstpClaims(pairId, gone)
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

	// Drain whatever outbound is queued (claiming it so the held primary cycle does
	// not also re-send the same SET, NEW Finding #2); recovery after takeover relies
	// on persisted outbound events, so fall back to the provider's pending list when
	// the buffer's async drain has not yet surfaced anything (mirrors runSstpCycle).
	outJtis := r.drainSstpBuffer(pairId, eventBuf, r.backfillBatch)
	if len(outJtis) == 0 {
		pending, _ := r.eventService.GetEventIds(r.ctx, sid, model.PollParameters{
			MaxEvents:         int32(r.backfillBatch),
			ReturnImmediately: true,
		})
		outJtis = r.claimSstpJtis(pairId, pending)
	}
	if len(outJtis) == 0 {
		// Nothing to push (or everything already in flight in the primary cycle): do
		// not open a second POST.
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}
	}

	events := r.resolveSstpEventsByJti(outJtis)
	r.releaseUnresolvedSstpClaims(pairId, outJtis, events)
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
		r.handleSstpAcks(stream, eventBuf, outcome.Acked, events, fencingToken)
	case goSetSstp.ClassRequestError:
		// 4xx on the second push pauses ONLY the outbound direction; the held
		// primary long-poll (inbound) continues uninterrupted (Q12.3). Release the
		// claim so the un-acked events are re-drained on resume.
		r.releaseSstpEventClaims(pairId, events)
		r.pauseSstpOutbound(stream, fmt.Sprintf("SSTP-CLIENT: 4xx on push-while-poll-held for pair=%s", pairId))
	case goSetSstp.ClassWeirdResponse:
		r.releaseSstpEventClaims(pairId, events)
		r.pauseSstpOutbound(stream, fmt.Sprintf("SSTP-CLIENT: weird response on push-while-poll-held for pair=%s", pairId))
	default: // ClassTransient / ClassTransport: do not pause; the primary cycle owns backoff.
		// Release the claim so these un-acked events are retried on a later cycle.
		r.releaseSstpEventClaims(pairId, events)
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

// claimSstpJtis filters candidate JTIs to those NOT already claimed in-flight for
// the pair, marks the survivors as claimed, and returns them. The primary
// long-poll cycle and a concurrent push-while-poll-held second push both call this
// before delivering, so a SET already in flight in one is never re-sent by the
// other (NEW Finding #2). Claims are cleared by ackSstpJtis (on peer-ack) or
// releaseSstpClaims (on delivery failure). The events collection / pending list
// remains the durable source of truth, so this in-memory claim is purely a
// same-node dedup and is safe across takeover.
func (r *router) claimSstpJtis(pairId string, candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	claimed := r.sstpInFlight[pairId]
	if claimed == nil {
		claimed = map[string]bool{}
		r.sstpInFlight[pairId] = claimed
	}
	out := make([]string, 0, len(candidates))
	for _, jti := range candidates {
		if claimed[jti] {
			continue // already in flight in another concurrent push/cycle.
		}
		claimed[jti] = true
		out = append(out, jti)
	}
	return out
}

// releaseSstpClaims drops the in-flight claim on the given JTIs WITHOUT removing
// them from the buffer, so a failed-delivery SET is re-drained (and retried) on a
// later cycle. Called from the delivery-failure paths.
func (r *router) releaseSstpClaims(pairId string, jtis []string) {
	if len(jtis) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	claimed := r.sstpInFlight[pairId]
	if claimed == nil {
		return
	}
	for _, jti := range jtis {
		delete(claimed, jti)
	}
	if len(claimed) == 0 {
		delete(r.sstpInFlight, pairId)
	}
}

// pauseSstpOutbound pauses ONLY the outbound (client) direction of the pair by
// setting the record's Status to paused via the single transition point. The
// inbound side (InboundStatus) is owned by the SSTP-server runner (#165) and is
// untouched here (Q12.3).
func (r *router) pauseSstpOutbound(stream *model.StreamStateRecord, reason string) {
	r.updateStream(stream, model.StreamStatePause, reason)
	// Finding #9: write the pause back into the source-of-truth map so the runner's
	// next-cycle refresh observes it (and the cycle exits) rather than reverting to
	// the stale enabled status held in the map.
	r.mu.Lock()
	if rec, ok := r.sstpClientStreams[stream.PairId]; ok {
		rec.Status = stream.Status
		rec.ErrorMsg = stream.ErrorMsg
		r.sstpClientStreams[stream.PairId] = rec
	}
	r.mu.Unlock()
}
