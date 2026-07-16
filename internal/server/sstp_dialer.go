// SSTP client dialer (PRD #49 slice 2a — dialer loop relocation).
//
// This is the community-side SSTP business-stream dialer, relocated from
// internal/eventRouter/runner_sstp.go to internal/server per ADR-0067's
// loop-relocation pin: pkg/goSetSstp is single-cycle (Exchange), and the
// consumer-owned loop — lease acquire/renew, backoff/idle cadence, ack
// bookkeeping, pause-on-4xx, push-while-poll-held second push — lives at
// the composition root that also holds cluster.Coordinator, node identity,
// and (in slice 2b) the credential-chain HTTP client.
//
// Behavior parity with runner_sstp.go @ 4585557: this slice is a
// structural refactor only. No new capability, no latent-bug fixes.
//   - 2b (issue #242): credential-chain helper + PeerServerAlias field —
//     the HTTP client here is still today's inline *http.Client construction.
//   - 2c (issue #243): inbound-half literal ack, request-side Ack carriage,
//     ±25% jitter, sign-failure = error, ack-all-sent fallback removal.
//
// The dialer speaks to the router through the narrow eventRouter.SstpOutbound
// surface for buffer/claim/ack/release/wake/refresh/pause/key/second-push
// state. It obtains cluster.Coordinator + node ID and its own inline
// http.Client directly (no back-reference to the router for those).
package server

import (
	"context"
	"crypto/rsa"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var sstpDialerLog = logger.Sub("SSTP-CLIENT")

const (
	// sstpLeaseDuration is the lease TTL; sstpHeartbeatInterval is the renew
	// cadence — mirroring the push-transmitter lease (Q4.1, Q14).
	sstpLeaseDuration     = 30 * time.Second
	sstpHeartbeatInterval = 10 * time.Second

	// sstpTakeoverJitterMin/Max bound the randomized delay a new lease
	// owner waits before opening its first connection, spreading
	// thundering-herd after a cluster-wide blip (Q16).
	sstpTakeoverJitterMin = 100 * time.Millisecond
	sstpTakeoverJitterMax = 500 * time.Millisecond
)

// SstpDialerStats is the optional lease-stats sink for the SSTP dialer,
// mirroring the eventRouter push loop. Nil ⇒ no reporting.
type SstpDialerStats interface {
	TrackLeaseAcquisition(resource string, success bool)
	IncLeasesHeld()
	DecLeasesHeld()
}

// SstpDialerConfig configures the relocated dialer: backoff/lease timing,
// jitter, sleep injection. Production uses NewSstpDialer's derived defaults
// (POLL_RETRY_* env, sstpLeaseDuration, sstpHeartbeatInterval); tests may
// shrink every duration.
type SstpDialerConfig struct {
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64

	// LeaseDuration / HeartbeatInterval are the lease TTL and renew cadence.
	// Production uses sstpLeaseDuration / sstpHeartbeatInterval; tests
	// shrink them to keep heartbeat / lease-loss paths fast.
	LeaseDuration     time.Duration
	HeartbeatInterval time.Duration
	// HeartbeatRetryDelay is the pause before the single heartbeat-renew
	// retry (Q14.c). Defaults to 1s; tests shrink it.
	HeartbeatRetryDelay time.Duration

	// Sleep waits for d or returns false when ctx is cancelled. Defaults to
	// sstpDefaultSleep; tests inject a deterministic implementation.
	Sleep func(ctx context.Context, d time.Duration) bool
	// Jitter returns the takeover jitter to wait before the first
	// connection. Defaults to a uniform draw in
	// [sstpTakeoverJitterMin, sstpTakeoverJitterMax].
	Jitter func() time.Duration

	// HTTPClient is the outbound client used by every SSTP cycle. AC 1
	// parity: this slice keeps today's inline construction (default 60s
	// timeout). Slice 2b routes it through the credential-chain resolver.
	HTTPClient *http.Client

	// BackfillBatch is the claim/drain batch size (mirrors the router's
	// backfillBatch). 0 ⇒ 100 (the router's own default).
	BackfillBatch int
}

func (c *SstpDialerConfig) fillDefaults() {
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
		c.Sleep = sstpDefaultSleep
	}
	if c.Jitter == nil {
		c.Jitter = defaultSstpJitter
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	if c.BackfillBatch <= 0 {
		c.BackfillBatch = 100
	}
}

// sstpDefaultSleep waits for d or returns false when ctx is cancelled.
func sstpDefaultSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
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

// defaultSstpJitter draws a uniform takeover delay in [min, max] (Q16).
func defaultSstpJitter() time.Duration {
	span := sstpTakeoverJitterMax - sstpTakeoverJitterMin
	return sstpTakeoverJitterMin + time.Duration(rand.Int63n(int64(span)+1))
}

// LoadSstpDialerConfig reads the POLL_RETRY_* env knobs (Q25) and returns a
// production-ready SstpDialerConfig. Seconds-valued floats, parsed via
// envcompat so the v0.11.0 I2SIG_POLL_* names take precedence over the
// legacy POLL_* names. Callers may further override individual fields
// (HTTPClient, BackfillBatch) after this returns.
func LoadSstpDialerConfig() SstpDialerConfig {
	cfg := SstpDialerConfig{
		BaseDelay:     parseSstpSecondsEnv("I2SIG_POLL_RETRY_BASE_DELAY", "POLL_RETRY_BASE_DELAY", 1*time.Second),
		MaxDelay:      parseSstpSecondsEnv("I2SIG_POLL_RETRY_MAX_DELAY", "POLL_RETRY_MAX_DELAY", 5*time.Minute),
		BackoffFactor: parseSstpFloatEnv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "POLL_RETRY_BACKOFF_FACTOR", 2.0),
	}
	cfg.fillDefaults()
	return cfg
}

// parseSstpSecondsEnv reads a float-seconds env var (POLL_RETRY_* are
// seconds-valued) and returns the corresponding Duration, falling back to
// defaultVal.
func parseSstpSecondsEnv(name, oldName string, defaultVal time.Duration) time.Duration {
	v := envcompat.Lookup(name, oldName)
	if v == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		sstpDialerLog.Warn("invalid float env var, using default", "name", name, "value", v, "default", defaultVal)
		return defaultVal
	}
	return time.Duration(f * float64(time.Second))
}

func parseSstpFloatEnv(name, oldName string, defaultVal float64) float64 {
	v := envcompat.Lookup(name, oldName)
	if v == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		sstpDialerLog.Warn("invalid float env var, using default", "name", name, "value", v, "default", defaultVal)
		return defaultVal
	}
	return f
}

// nextSstpBackoff returns the next exponential-backoff delay, capped by
// maxDelay. Duplicated inline (rather than reused from eventRouter) so the
// dialer stays self-contained after the loop relocation.
func nextSstpBackoff(current time.Duration, factor float64, maxDelay time.Duration) time.Duration {
	next := time.Duration(float64(current) * factor)
	if next > maxDelay {
		next = maxDelay
	}
	return next
}

// SstpDialer is the community-side SSTP business-stream dialer. It owns
// per-pair goroutines, the cluster.Coordinator (for lease), and the outbound
// http.Client. Router-owned per-pair state (buffer, claims, second-push slot,
// source-of-truth record, issuer keys) is reached exclusively through the
// narrow eventRouter.SstpOutbound surface, so this file never touches
// eventRouter internals.
//
// Implements eventRouter.SstpDialerHooks — the router calls RegisterPair
// when a new SSTP-client pair lands (initSstpClientStreamLocked) and
// UnregisterPair when a pair is removed (RemoveStream). RegisterPair starts
// a per-pair goroutine; UnregisterPair cancels its context so the goroutine
// exits promptly rather than waiting for the map-deletion signal it also
// observes via RefreshPair.
type SstpDialer struct {
	coordinator cluster.ClusterCoordinator
	nodeID      string
	stats       SstpDialerStats
	cfg         SstpDialerConfig

	mu       sync.Mutex
	outbound eventRouter.SstpOutbound
	bound    bool
	// pending queues pairIds whose RegisterPair fired before Bind
	// (NewRouter's startup UpdateStreamState iteration lands in this
	// window — the router calls sstpDialer.RegisterPair for every existing
	// SSTP-client pair before application.go can late-bind outbound).
	// Bind drains this queue.
	pending []string
	running map[string]*sstpPairLoop
}

// sstpPairLoop is a running per-pair goroutine's cancel/wait handle. The
// goroutine exits on ctx cancel or when RefreshPair returns ok=false.
type sstpPairLoop struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// NewSstpDialer wires a dialer against cluster.Coordinator and node
// identity. Bind must be called with the router's narrow outbound surface
// before per-pair goroutines actually start (a RegisterPair fired before
// Bind is queued and drained by Bind). stats is optional.
//
// The two-step construction accommodates the composition-root ordering in
// application.go: NewRouter's startup UpdateStreamState iteration calls
// sstpDialer.RegisterPair for every existing SSTP-client pair BEFORE the
// application can late-bind outbound to the just-constructed router.
func NewSstpDialer(coord cluster.ClusterCoordinator, nodeID string, stats SstpDialerStats, cfg SstpDialerConfig) *SstpDialer {
	cfg.fillDefaults()
	return &SstpDialer{
		coordinator: coord,
		nodeID:      nodeID,
		stats:       stats,
		cfg:         cfg,
		running:     map[string]*sstpPairLoop{},
	}
}

// Bind late-binds the router's narrow outbound surface and starts any
// per-pair goroutines that were queued via RegisterPair before Bind ran.
// Safe to call exactly once — a second Bind is a silent no-op after the
// first replaces outbound / drains pending.
func (d *SstpDialer) Bind(outbound eventRouter.SstpOutbound) {
	d.mu.Lock()
	if d.bound {
		d.mu.Unlock()
		return
	}
	d.outbound = outbound
	d.bound = true
	pending := d.pending
	d.pending = nil
	d.mu.Unlock()
	for _, pairId := range pending {
		d.startPair(pairId)
	}
}

// Compile-time assertion: SstpDialer satisfies eventRouter.SstpDialerHooks.
var _ eventRouter.SstpDialerHooks = (*SstpDialer)(nil)

// RegisterPair starts the per-pair dialer goroutine. When called before
// Bind (during NewRouter's startup UpdateStreamState iteration) the pairId
// is queued for Bind to drain. Idempotent: a second call for a pair that
// already has a running loop is a silent no-op.
func (d *SstpDialer) RegisterPair(pairId string) {
	d.mu.Lock()
	if !d.bound {
		d.pending = append(d.pending, pairId)
		d.mu.Unlock()
		return
	}
	if _, ok := d.running[pairId]; ok {
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()
	d.startPair(pairId)
}

// startPair is the internal starter used by both RegisterPair (post-Bind)
// and Bind (draining pending). Caller must have observed !d.running[pairId].
func (d *SstpDialer) startPair(pairId string) {
	d.mu.Lock()
	if _, ok := d.running[pairId]; ok {
		d.mu.Unlock()
		return
	}
	// Parent the pair's context on the router's shutdown context so
	// router.Shutdown() cancels every in-flight cycle (Q14.a).
	parent := d.outbound.Ctx()
	ctx, cancel := context.WithCancel(parent)
	loop := &sstpPairLoop{cancel: cancel, done: make(chan struct{})}
	d.running[pairId] = loop
	d.mu.Unlock()

	go func() {
		defer close(loop.done)
		d.runPair(ctx, pairId)
		// Self-clean the running-map entry when the goroutine exits on its
		// own (e.g. pair removed via RefreshPair ok=false), so a subsequent
		// RegisterPair of the same pairId is not swallowed as a duplicate.
		d.mu.Lock()
		if cur, ok := d.running[pairId]; ok && cur == loop {
			delete(d.running, pairId)
		}
		d.mu.Unlock()
	}()
}

// UnregisterPair signals the per-pair goroutine to exit and drops the
// registry entry. Waits briefly for the goroutine to acknowledge so a
// subsequent RegisterPair sees a clean slate. Also drops any pre-Bind
// pending entry so a queued pair that is removed before Bind never starts.
// Idempotent — a pair that was never registered (or already stopped) is a
// silent no-op.
func (d *SstpDialer) UnregisterPair(pairId string) {
	d.mu.Lock()
	loop, ok := d.running[pairId]
	if ok {
		delete(d.running, pairId)
	}
	if len(d.pending) > 0 {
		filtered := d.pending[:0]
		for _, p := range d.pending {
			if p != pairId {
				filtered = append(filtered, p)
			}
		}
		d.pending = filtered
	}
	d.mu.Unlock()
	if !ok {
		return
	}
	loop.cancel()
	// Best-effort wait so a UnregisterPair immediately followed by a
	// RegisterPair does not race the old goroutine's cleanup.
	select {
	case <-loop.done:
	case <-time.After(2 * time.Second):
		sstpDialerLog.Warn("UnregisterPair: goroutine did not exit within 2s", "pairId", pairId)
	}
}

// runPair is the per-pair top-level loop: acquire the sstp-client:<PairId>
// lease, run cycles while it is held, re-acquire on lease loss. Mirrors the
// old SstpClientStreamHandler / runSstpClientLoop verbatim, differing only
// in where per-pair state comes from (the SstpOutbound facade).
func (d *SstpDialer) runPair(ctx context.Context, pairId string) {
	resource := fmt.Sprintf("sstp-client:%s", pairId)

	for {
		// Finding #9 / #8: re-read the live record from the source-of-truth
		// map. A missing entry means the pair was removed (RemoveStream); a
		// non-enabled status means it was paused/disabled. Either way exit.
		live, ok := d.outbound.RefreshPair(pairId)
		if !ok {
			sstpDialerLog.Info("pair removed. Loop exiting.", "pairId", pairId)
			return
		}
		if live.Status != model.StreamStateEnabled {
			sstpDialerLog.Info("no longer enabled. Loop exiting.", "pairId", pairId)
			return
		}

		acquired, fencingToken, err := d.coordinator.TryAcquireOrRenewLease(resource, d.nodeID, d.cfg.LeaseDuration)
		if d.stats != nil {
			d.stats.TrackLeaseAcquisition(resource, acquired && err == nil)
		}
		if err != nil {
			sstpDialerLog.Error("lease acquisition error", "pairId", pairId, "error", err)
		}

		if !acquired {
			sstpDialerLog.Debug("lease not held, waiting...", "pairId", pairId)
			select {
			case <-time.After(d.cfg.HeartbeatInterval + d.cfg.LeaseDuration/2):
				continue
			case <-ctx.Done():
				return
			}
		}

		sstpDialerLog.Info("lease acquired, opening connection", "pairId", pairId)
		// Takeover jitter (Q16): spread thundering-herd after a cluster blip.
		if !d.cfg.Sleep(ctx, d.cfg.Jitter()) {
			d.releaseLease(resource, pairId)
			return
		}

		shouldRetry := d.runCycleLoop(ctx, pairId, fencingToken)
		d.releaseLease(resource, pairId)
		if !shouldRetry {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// releaseLease explicitly releases the Mongo lease so the next node can take
// over immediately (Q14.b graceful-shutdown / lease-loss handoff).
func (d *SstpDialer) releaseLease(resource, pairId string) {
	if err := d.coordinator.ReleaseLeaseIfOwned(resource, d.nodeID); err != nil {
		sstpDialerLog.Warn("lease release failed", "pairId", pairId, "error", err)
	}
}

// runCycleLoop runs SSTP HTTP cycles while this node holds the lease. A
// heartbeat goroutine renews the lease every HeartbeatInterval, retrying a
// single failed renew once before declaring the lease lost (Q14.c). The
// loop's context (cycleCtx) parents every HTTP cycle; losing the lease or
// shutting down cancels cycleCtx, aborting any in-flight cycle (Q14.a).
// Returns true when the caller should attempt to re-acquire (lease lost),
// false to exit (shutdown, pair removed, stream disabled).
func (d *SstpDialer) runCycleLoop(parentCtx context.Context, pairId string, fencingToken int64) bool {
	if d.stats != nil {
		d.stats.IncLeasesHeld()
		defer d.stats.DecLeasesHeld()
	}

	resource := fmt.Sprintf("sstp-client:%s", pairId)

	// cycleCtx parents every outbound HTTP cycle. Cancelled on lease loss
	// (heartbeat) or shutdown (parent ctx) so in-flight requests abort.
	cycleCtx, cycleCancel := context.WithCancel(parentCtx)
	defer cycleCancel()

	go d.heartbeat(cycleCtx, cycleCancel, resource, pairId)

	delay := d.cfg.BaseDelay

	for {
		select {
		case <-cycleCtx.Done():
			// Lease lost or shutdown: distinguish by checking the parent.
			if parentCtx.Err() != nil {
				return false
			}
			return true
		default:
		}

		// Finding #9 / #8: refresh the live config each cycle so a rotated
		// bearer / changed endpoint / pause applied via UpdateStreamState is
		// observed within one cycle, and a RemoveStream stops the loop.
		live, ok := d.outbound.RefreshPair(pairId)
		if !ok || live.Status != model.StreamStateEnabled {
			return false
		}
		streamCopy := live

		// Run the primary cycle concurrently so the loop can react to a new
		// outbound SET arriving while the peer holds this cycle's connection
		// as a long-poll (push-while-poll-held, Q7.2, #166).
		outcome, resumeDelay, exit := d.runPrimaryCycleWithSecondPush(cycleCtx, &streamCopy, fencingToken, &delay)
		_ = outcome
		if exit {
			if parentCtx.Err() != nil {
				return false
			}
			return true
		}

		// On a delay (transport/transient/idle empty buffer), wait it out,
		// but wake early on a new outbound event or lease loss.
		if resumeDelay > 0 {
			timer := time.NewTimer(resumeDelay)
			wake := d.outbound.WakeCh(pairId)
			select {
			case <-cycleCtx.Done():
				timer.Stop()
				if parentCtx.Err() != nil {
					return false
				}
				return true
			case <-wake:
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}

// runPrimaryCycleWithSecondPush runs one primary SSTP cycle in a goroutine
// while the calling loop watches the outbound buffer's wake signal. When a
// new outbound SET arrives WHILE the primary is still held open as a
// long-poll, fires a bounded SECOND POST (returnEvents=false) to flush the
// queued outbound immediately (Q7.2, #166). Both share ctx so lease loss /
// shutdown cancels both. Returns the primary cycle's outcome verbatim.
func (d *SstpDialer) runPrimaryCycleWithSecondPush(ctx context.Context, stream *model.StreamStateRecord, fencingToken int64, delay *time.Duration) (goSetSstp.Classification, time.Duration, bool) {
	pairId := stream.PairId
	type cycleResult struct {
		cls   goSetSstp.Classification
		delay time.Duration
		exit  bool
	}
	done := make(chan cycleResult, 1)
	go func() {
		cls, dly, exit := d.runCycle(ctx, stream, fencingToken, delay)
		done <- cycleResult{cls: cls, delay: dly, exit: exit}
	}()

	// secondPushWg tracks in-flight second-push goroutines so we do not
	// leak them past this cycle: we wait for them before returning.
	var secondPushWg sync.WaitGroup
	defer secondPushWg.Wait()

	wakeup := d.outbound.WakeCh(pairId)
	for {
		select {
		case res := <-done:
			return res.cls, res.delay, res.exit
		case <-ctx.Done():
			// Lease loss / shutdown: primary observes ctx and returns
			// (exit=true); wait for it so we return its result and never
			// leak it.
			res := <-done
			return res.cls, res.delay, res.exit
		case <-wakeup:
			// A new outbound SET arrived while the primary is held. Fire a
			// bounded second push to flush it now. The guard in
			// pushWhilePollHeld coalesces concurrent wakes to one in-flight
			// push per pair.
			wakeup = d.outbound.WakeCh(pairId) // re-arm: Wakeup() swapped the notifier.
			live, ok := d.outbound.RefreshPair(pairId)
			if !ok {
				continue // pair removed; primary's next refresh exits the loop.
			}
			streamCopy := live
			secondPushWg.Add(1)
			go func() {
				defer secondPushWg.Done()
				d.pushWhilePollHeld(ctx, &streamCopy, fencingToken)
			}()
		}
	}
}

// runCycle performs one SSTP HTTP cycle: drain the outbound buffer, deliver,
// and apply the classifier result. Returns the classification, the delay
// the caller should wait before the next cycle (0 = immediate), and
// exit=true when the loop should terminate (stream disabled or ctx done).
// delay carries the running exponential-backoff value across transport /
// transient retries; it is reset to BaseDelay on ClassOK/ClassPerJTI.
func (d *SstpDialer) runCycle(ctx context.Context, stream *model.StreamStateRecord, fencingToken int64, delay *time.Duration) (goSetSstp.Classification, time.Duration, bool) {
	pairId := stream.PairId

	// Gather the outbound JTIs to flush this cycle. Drain the buffer first
	// (claim in-flight); the ClaimOutbound surface method already falls
	// back to the pending list when the buffer is empty (Q13).
	outJtis := d.outbound.ClaimOutbound(pairId, d.cfg.BackfillBatch)

	// Nothing to flush: idle a short cycle so we don't busy-loop.
	if len(outJtis) == 0 {
		*delay = d.cfg.BaseDelay
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}, d.cfg.BaseDelay, false
	}

	events := d.outbound.ResolveEvents(pairId, outJtis)

	var rsaKey *rsa.PrivateKey
	var kid string
	if stream.GetRouteMode() != model.RouteModeForward {
		rsaKey, kid = d.outbound.LoadSigningKey(stream.StreamConfiguration.Id, stream.StreamConfiguration.Iss)
	}

	cls, acked := d.deliver(ctx, stream, events, rsaKey, kid, nil)

	if ctx.Err() != nil {
		// Cancelled in flight: release the claim so the next owner
		// re-drains and retries these events.
		d.outbound.ReleaseOutbound(pairId, events)
		return cls, 0, true
	}

	switch cls.Class {
	case goSetSstp.ClassOK, goSetSstp.ClassPerJTI:
		ackedCount := d.outbound.AckOutbound(stream, acked, events, fencingToken)
		*delay = d.cfg.BaseDelay
		// If we acked everything we sent, drain more immediately;
		// otherwise idle a short cycle to avoid re-sending unacked SETs.
		if ackedCount >= len(events) {
			return cls, 0, false
		}
		return cls, d.cfg.BaseDelay, false

	case goSetSstp.ClassRequestError:
		// 4xx: pause ONLY the outbound (client) direction of the pair.
		// Release the claim so a later resume re-drains and retries.
		d.outbound.ReleaseOutbound(pairId, events)
		reason := fmt.Sprintf("SSTP-CLIENT: 4xx request error on pair=%s", pairId)
		d.outbound.PauseOutbound(stream, reason)
		return cls, 0, true

	case goSetSstp.ClassTransient, goSetSstp.ClassTransport:
		// 5xx / connection failure: back off per POLL_RETRY_*, do NOT
		// pause (Q25). Release the claim so the retried cycle re-drains.
		d.outbound.ReleaseOutbound(pairId, events)
		next := *delay
		if cls.NextDelay > 0 {
			next = cls.NextDelay
		}
		sstpDialerLog.Warn("transport/transient failure, backing off",
			"pairId", pairId, "class", cls.Class.String(), "delay", next)
		*delay = nextSstpBackoff(*delay, d.cfg.BackoffFactor, d.cfg.MaxDelay)
		return cls, next, false

	default: // ClassWeirdResponse
		d.outbound.ReleaseOutbound(pairId, events)
		reason := fmt.Sprintf("SSTP-CLIENT: weird response on pair=%s", pairId)
		d.outbound.PauseOutbound(stream, reason)
		return cls, 0, true
	}
}

// heartbeat renews the lease every HeartbeatInterval. A single renew
// failure is retried once after a short pause before the lease is declared
// lost (Q14.c) — one-shot Mongo blips do not trigger takeover churn. On a
// confirmed loss it cancels cycleCtx, aborting any in-flight cycle (Q14.a).
func (d *SstpDialer) heartbeat(cycleCtx context.Context, cancel context.CancelFunc, resource, pairId string) {
	ticker := time.NewTicker(d.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if d.renewLeaseWithRetry(cycleCtx, resource, pairId) {
				continue
			}
			sstpDialerLog.Warn("lease lost, cancelling in-flight cycle", "pairId", pairId)
			cancel()
			return
		case <-cycleCtx.Done():
			return
		}
	}
}

// renewLeaseWithRetry attempts a lease renew; on failure retries exactly
// once after HeartbeatRetryDelay (cancellable via ctx). Returns true while
// ownership is retained, false once the lease is confirmed lost.
func (d *SstpDialer) renewLeaseWithRetry(ctx context.Context, resource, pairId string) bool {
	ok, _, err := d.coordinator.TryAcquireOrRenewLease(resource, d.nodeID, d.cfg.LeaseDuration)
	if d.stats != nil {
		d.stats.TrackLeaseAcquisition(resource, ok && err == nil)
	}
	if ok && err == nil {
		return true
	}
	sstpDialerLog.Debug("heartbeat renew blip, retrying once", "pairId", pairId, "error", err)

	t := time.NewTimer(d.cfg.HeartbeatRetryDelay)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
		return false
	}

	ok, _, err = d.coordinator.TryAcquireOrRenewLease(resource, d.nodeID, d.cfg.LeaseDuration)
	if d.stats != nil {
		d.stats.TrackLeaseAcquisition(resource, ok && err == nil)
	}
	return ok && err == nil
}

// pushWhilePollHeld performs a SECOND, parallel SSTP POST to flush queued
// outbound SETs while the pair's primary long-poll cycle is held open by
// the peer (Q7.2, #166). It carries returnEvents=false so the peer returns
// immediately. On 4xx it pauses ONLY the outbound direction (Q12.3); on
// 5xx/transport it does not pause (the primary owns backoff). The held
// primary is unaffected.
//
// Concurrency is bounded to at most one in-flight secondary push per pair:
// if a push is already running, this call returns ClassOK without opening a
// third parallel request.
func (d *SstpDialer) pushWhilePollHeld(ctx context.Context, stream *model.StreamStateRecord, fencingToken int64) goSetSstp.Classification {
	pairId := stream.PairId

	if !d.outbound.AcquireSecondPushSlot(pairId) {
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}
	}
	defer d.outbound.ReleaseSecondPushSlot(pairId)

	outJtis := d.outbound.ClaimOutbound(pairId, d.cfg.BackfillBatch)
	if len(outJtis) == 0 {
		// Nothing to push (or everything already in flight in the primary
		// cycle): do not open a second POST.
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}
	}

	events := d.outbound.ResolveEvents(pairId, outJtis)
	if len(events) == 0 {
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}
	}

	var rsaKey *rsa.PrivateKey
	var kid string
	if stream.GetRouteMode() != model.RouteModeForward {
		rsaKey, kid = d.outbound.LoadSigningKey(stream.StreamConfiguration.Id, stream.StreamConfiguration.Iss)
	}

	returnEvents := goSetSstp.BoolPtr(false)
	cls, acked := d.deliver(ctx, stream, events, rsaKey, kid, returnEvents)

	switch cls.Class {
	case goSetSstp.ClassOK, goSetSstp.ClassPerJTI:
		d.outbound.AckOutbound(stream, acked, events, fencingToken)
	case goSetSstp.ClassRequestError:
		// 4xx on second push pauses ONLY outbound; the held primary
		// long-poll (inbound) continues uninterrupted (Q12.3).
		d.outbound.ReleaseOutbound(pairId, events)
		d.outbound.PauseOutbound(stream, fmt.Sprintf("SSTP-CLIENT: 4xx on push-while-poll-held for pair=%s", pairId))
	case goSetSstp.ClassWeirdResponse:
		d.outbound.ReleaseOutbound(pairId, events)
		d.outbound.PauseOutbound(stream, fmt.Sprintf("SSTP-CLIENT: weird response on push-while-poll-held for pair=%s", pairId))
	default: // ClassTransient / ClassTransport: do not pause; primary owns backoff.
		d.outbound.ReleaseOutbound(pairId, events)
		sstpDialerLog.Warn("push-while-poll-held transport/transient failure",
			"pairId", pairId, "class", cls.Class.String())
	}
	return cls
}

// deliver performs one SSTP HTTP cycle over the configured HTTPClient by
// calling pkg/goSetSstp.Exchange (ADR-0067 single-cycle). Returns the
// classifier's verdict and the peer's ack list (empty when the peer
// returned no explicit ack — the §2.3 success-without-detail case is
// handled by AckOutbound).
//
// AC 1 parity: this slice keeps today's inline http.Client + Authorization
// header construction. Slice 2b (issue #242) routes it through the
// credential-chain resolver so TxAlias-configured TLS posture and OAuth
// credentials apply.
func (d *SstpDialer) deliver(ctx context.Context, stream *model.StreamStateRecord, events []*model.EventRecord, key *rsa.PrivateKey, kid string, returnEvents *bool) (goSetSstp.Classification, []string) {
	method := stream.SstpMethod
	if method == nil || method.EndpointUrl == "" {
		return goSetSstp.Classification{Class: goSetSstp.ClassRequestError}, nil
	}

	msg := goSetSstp.Message{
		ReturnEvents: returnEvents,
		Sets:         buildSstpSets(stream, events, key, kid),
	}

	auth := method.AuthorizationHeader
	if auth != "" && !strings.Contains(strings.ToLower(auth), "bearer") && !strings.Contains(auth, " ") {
		auth = "Bearer " + auth
	}

	result := goSetSstp.Exchange(ctx, msg, goSetSstp.DialerConfig{
		EndpointURL:   method.EndpointUrl,
		Authorization: auth,
		HTTPClient:    d.cfg.HTTPClient,
	})

	cls := goSetSstp.ClassifyResult(result)
	var acked []string
	if result.Message != nil {
		acked = result.Message.Ack
	}
	return cls, acked
}

// buildSstpSets renders each outbound event to its on-wire SET string:
// forwarded verbatim in RouteModeForward, or signed with the pair's issuer
// key otherwise. Missing key or sign failure skips the JTI (AC 1 parity —
// slice 2c consolidates sign failure = error).
func buildSstpSets(stream *model.StreamStateRecord, events []*model.EventRecord, key *rsa.PrivateKey, kid string) map[string]string {
	if len(events) == 0 {
		return nil
	}
	cfg := stream.StreamConfiguration
	forward := cfg.RouteMode == model.RouteModeForward
	sets := make(map[string]string, len(events))
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if forward {
			sets[ev.Jti] = ev.Original
			continue
		}
		if key == nil {
			continue
		}
		token := &ev.Event
		token.Issuer = cfg.Iss
		token.Audience = cfg.Aud
		token.IssuedAt = jwt.NewNumericDate(time.Now())
		token.Kid = kid
		signed, err := token.JWS(jwt.SigningMethodRS256, key)
		if err != nil {
			continue
		}
		sets[ev.Jti] = signed
	}
	return sets
}

