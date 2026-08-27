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
	"crypto"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/services"
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

// dialerStatsHolder boxes SstpDialerStats so it can live in an
// atomic.Pointer (which requires a concrete type). The field is set once at
// wire time via SetStats and read on the pair hot-path.
type dialerStatsHolder struct {
	stats SstpDialerStats
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
	// eventRouter.SleepCtx; tests inject a deterministic implementation.
	Sleep func(ctx context.Context, d time.Duration) bool
	// Jitter returns the takeover jitter to wait before the first
	// connection. Defaults to a uniform draw in
	// [sstpTakeoverJitterMin, sstpTakeoverJitterMax].
	Jitter func() time.Duration

	// HTTPClient is the fallback outbound client used by SSTP cycles when
	// ResolveClient is unset (tests) or returns an error. Production wires
	// ResolveClient to the credential-chain resolver so per-pair TLS/OAuth
	// posture applies; HTTPClient is a safety net (default 60s timeout).
	HTTPClient *http.Client

	// ResolveClient invokes the transmitter credential-selection chain
	// (Security-Protocol-Architecture §5) to obtain the per-cycle
	// (*http.Client, Authorization header, close func). Wired by the
	// composition root (application.go) to sa.ResolveTransmitterClient.
	// When nil, the dialer falls back to HTTPClient + the raw per-pair
	// bearer from SstpMethod.AuthorizationHeader.
	ResolveClient func(ctx context.Context, stream *model.StreamStateRecord) (*http.Client, string, func(), error)

	// BackfillBatch is the claim/drain batch size (mirrors the router's
	// backfillBatch). 0 ⇒ 100 (the router's own default).
	BackfillBatch int

	// EventValidationDefault is the server-wide event_validation default
	// (I2SIG_STREAM_EVENT_VALIDATION) an SSTP pair with no per-stream mode
	// inherits on its inbound half (spec #247 #254). Wired by the composition
	// root from the StreamService; the zero value resolves to NONE, which is
	// the pre-#247 dialer behavior.
	EventValidationDefault model.EventValidationMode
}

// sstpPendingFeedback is the request-side feedback a pair loop owes its peer on
// the NEXT SSTP request: literal acks for inbound SETs it ingested, and per-JTI
// setErrs for inbound SETs it rejected.
//
// Acks and setErrs travel together because they are the same decision seen from
// two sides — every inbound JTI ends up in exactly one of them — and because
// both are cleared by the same event (a peer-accepted exchange) and preserved
// by the same failures (4xx / transport / weird), so splitting them into two
// carried values would be two chances to get that lifecycle wrong.
type sstpPendingFeedback struct {
	// Acks are the JTIs successfully verified AND ingested (US 5 literal-ack
	// semantics: only what we actually accepted is acked).
	Acks []string

	// SetErrs are the per-JTI errors for inbound SETs this side rejected.
	// Reporting them is what stops an event-validation rejection from becoming
	// an infinite resend loop: a payload that fails validation fails identically
	// on resend, so the peer must be told to clear it rather than left to infer
	// a missing ack.
	SetErrs map[string]goSetSstp.SetErr
}

// clearedOutbound returns the JTIs to clear from the pair's outbound buffer —
// everything the peer acked, plus every DETERMINISTIC per-JTI rejection — and the
// stream-fatal setErr, if the peer sent one, for the caller to act on.
//
// A deterministic rejection must clear the SET on the same terms as an ack.
// Outbound bookkeeping is literal-ack — anything sent-but-unacked is released for
// retry — so a SET the peer rejects on event-validation grounds would otherwise be
// claimed, signed, POSTed, rejected, released and re-claimed on every cycle,
// forever, without the buffer ever draining that JTI.
//
// It is NOT every rejection, because clearing is permanent: a peer that rejects
// with a retryable code (ProblemSignatureInvalid / ProblemUnknownKID / jwtCrypto —
// what our own acceptor emits while a signing key rotates or its JWKS cache is
// briefly stale) would otherwise have those SETs deleted, silently, with the pair
// still enabled. goSetSstp.PartitionSetErrs applies the ADR-0040 verdicts: park
// (clear), retry (leave pending), or stream-fatal (stop the direction).
//
// Each rejection is logged WARN — that log is the operator's only view of what a
// peer refused, since a cleared SET is discarded immediately after.
func clearedOutbound(pairId string, acked []string, setErrs map[string]goSetSstp.SetErr) ([]string, *goSetSstp.SetErr) {
	if len(setErrs) == 0 {
		return acked, nil
	}
	disposition := goSetSstp.PartitionSetErrs(setErrs)

	for _, jti := range disposition.Retry {
		se := setErrs[jti]
		sstpDialerLog.Warn("SSTP-CLIENT: peer rejected outbound SET with a retryable code, holding it for resend",
			"pairId", pairId, "jti", jti, "err", se.Err, "description", se.Description)
	}
	for _, jti := range disposition.Unrecognized {
		se := setErrs[jti]
		sstpDialerLog.Warn("SSTP-CLIENT: peer rejected outbound SET with an unrecognized code, holding it rather than discarding it",
			"pairId", pairId, "jti", jti, "err", se.Err, "description", se.Description)
	}
	for _, jti := range disposition.Fatal {
		se := setErrs[jti]
		sstpDialerLog.Error("SSTP-CLIENT: peer reports the stream is dead, holding outbound SET",
			"pairId", pairId, "jti", jti, "err", se.Err, "description", se.Description)
	}

	cleared := make([]string, 0, len(acked)+len(disposition.Clear))
	cleared = append(cleared, acked...)
	seen := make(map[string]struct{}, len(acked))
	for _, jti := range acked {
		seen[jti] = struct{}{}
	}
	for _, jti := range disposition.Clear {
		se := setErrs[jti]
		sstpDialerLog.Warn("SSTP-CLIENT: peer rejected outbound SET, clearing it",
			"pairId", pairId, "jti", jti, "err", se.Err, "description", se.Description)
		if _, dup := seen[jti]; dup {
			// A peer that both acks and setErrs one JTI is malformed; clearing it
			// once is right either way.
			continue
		}
		cleared = append(cleared, jti)
	}

	var fatal *goSetSstp.SetErr
	if len(disposition.Fatal) > 0 {
		fatalErr := disposition.FatalErr
		fatal = &fatalErr
	}
	return cleared, fatal
}

// addSetErr records a per-JTI rejection, allocating the map on first use.
func (f *sstpPendingFeedback) addSetErr(jti string, se goSetSstp.SetErr) {
	if f.SetErrs == nil {
		f.SetErrs = map[string]goSetSstp.SetErr{}
	}
	f.SetErrs[jti] = se
}

// empty reports whether there is nothing owed to the peer — the idle guard's
// question, which pre-#254 was simply len(pendingAcks) == 0.
func (f sstpPendingFeedback) empty() bool {
	return len(f.Acks) == 0 && len(f.SetErrs) == 0
}

// merge folds other into f, de-duplicating acks. Used to fold feedback produced
// off the primary cycle (pushWhilePollHeld) back into the pair loop's carried
// value. A JTI can never land in both Acks and SetErrs — runInboundHalf puts
// each inbound JTI in exactly one — so no cross-field reconciliation is needed.
func (f *sstpPendingFeedback) merge(other sstpPendingFeedback) {
	if len(other.Acks) > 0 {
		seen := make(map[string]struct{}, len(f.Acks))
		for _, jti := range f.Acks {
			seen[jti] = struct{}{}
		}
		for _, jti := range other.Acks {
			if _, dup := seen[jti]; dup {
				continue
			}
			seen[jti] = struct{}{}
			f.Acks = append(f.Acks, jti)
		}
	}
	for jti, se := range other.SetErrs {
		f.addSetErr(jti, se)
	}
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
		c.Sleep = eventRouter.SleepCtx
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

// sstpBackoffJitterFraction is the ±25% jitter applied to every backoff delay
// on the sleep-now side (PRD #49 slice 2c AC 4, US 5 thundering-herd fix).
// Matches enterprise's sstpconnector/retry.go JitterFraction so both sides
// of a Signals family deployment share one reconnect-jitter shape (ADR-0040).
const sstpBackoffJitterFraction = 0.25

// nextSstpBackoff advances the exponential-backoff ladder, capped by
// maxDelay. The stored ladder value is UN-jittered so the exponential growth
// is monotonic; jitter is applied by jitteredSstpBackoff on the sleep-now
// value returned to the caller.
//
// Duplicated inline (rather than reused from eventRouter) so the dialer
// stays self-contained after the loop relocation.
func nextSstpBackoff(current time.Duration, factor float64, maxDelay time.Duration) time.Duration {
	next := time.Duration(float64(current) * factor)
	if next > maxDelay {
		next = maxDelay
	}
	return next
}

// jitteredSstpBackoff returns d with ±25% uniform jitter applied (PRD #49
// slice 2c AC 4). Formula matches enterprise's sstpconnector/retry.go so
// both sides of a Signals family deployment draw from the same jitter shape:
//
//	factor := 1 - jf + 2*jf*rand.Float64()   // uniform in [1-jf, 1+jf]
//	delay  := d * factor
//
// so the delay is uniformly distributed in [d*(1-jf), d*(1+jf)] and two
// independent draws almost never collide, spreading thundering-herd after
// a cluster-wide blip.
func jitteredSstpBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	factor := 1 - sstpBackoffJitterFraction + 2*sstpBackoffJitterFraction*rand.Float64()
	return time.Duration(float64(d) * factor)
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
	// stats is late-bindable: application.go constructs the dialer BEFORE
	// InitializePrometheus wires the stats handler. Reads are on the pair
	// hot-path (per-cycle + per-heartbeat), so use an atomic pointer to
	// avoid a mutex on those paths. Nil pointer ⇒ no reporting.
	stats atomic.Pointer[dialerStatsHolder]
	cfg   SstpDialerConfig

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

	// deferredMu guards deferred.
	deferredMu sync.Mutex
	// deferred holds inbound feedback produced OUTSIDE the primary cycle — today
	// only by pushWhilePollHeld, which runs in its own goroutine while the pair
	// loop carries its pending feedback as a plain value it cannot safely mutate
	// from there. The pair loop drains this into that value at the top of each
	// cycle, so a SET ingested (or rejected) on a second push is still acked or
	// setErr'd, one cycle later at worst.
	//
	// Without it the second push's feedback was discarded: the peer never learned
	// we had taken those SETs, so its outbound never cleared them and it resent
	// them every cycle forever (code-review finding on spec #247 #254).
	deferred map[string]sstpPendingFeedback
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
	d := &SstpDialer{
		coordinator: coord,
		nodeID:      nodeID,
		cfg:         cfg,
		running:     map[string]*sstpPairLoop{},
		deferred:    map[string]sstpPendingFeedback{},
	}
	if stats != nil {
		d.stats.Store(&dialerStatsHolder{stats: stats})
	}
	return d
}

// deferFeedback records feedback owed to a peer that was produced off the
// primary cycle, for the pair loop to carry on its next request.
func (d *SstpDialer) deferFeedback(pairId string, fb sstpPendingFeedback) {
	if fb.empty() {
		return
	}
	d.deferredMu.Lock()
	defer d.deferredMu.Unlock()
	carried := d.deferred[pairId]
	carried.merge(fb)
	d.deferred[pairId] = carried
}

// takeDeferredFeedback removes and returns the feedback deferred for a pair.
// Taking rather than reading is what makes the hand-off exactly-once: the pair
// loop now owns it and applies the normal preserve-on-failure lifecycle, so a
// failed exchange retries it instead of this store accumulating a second copy.
func (d *SstpDialer) takeDeferredFeedback(pairId string) sstpPendingFeedback {
	d.deferredMu.Lock()
	defer d.deferredMu.Unlock()
	fb, ok := d.deferred[pairId]
	if !ok {
		return sstpPendingFeedback{}
	}
	delete(d.deferred, pairId)
	return fb
}

// dropDeferredFeedback discards a removed pair's deferred feedback so the store
// does not outlive the pair it belongs to.
func (d *SstpDialer) dropDeferredFeedback(pairId string) {
	d.deferredMu.Lock()
	defer d.deferredMu.Unlock()
	delete(d.deferred, pairId)
}

// SetStats late-binds the stats sink. Safe to call after per-pair goroutines
// have started (reads use an atomic pointer). Passing nil unsets any prior
// binding.
func (d *SstpDialer) SetStats(stats SstpDialerStats) {
	if stats == nil {
		d.stats.Store(nil)
		return
	}
	d.stats.Store(&dialerStatsHolder{stats: stats})
}

// statsSink returns the current stats sink or nil if none is wired.
func (d *SstpDialer) statsSink() SstpDialerStats {
	h := d.stats.Load()
	if h == nil {
		return nil
	}
	return h.stats
}

// Bind late-binds the router's narrow outbound surface and starts any
// per-pair goroutines that were queued via RegisterPair before Bind ran.
// Safe to call exactly once — a second Bind is a silent no-op after the
// first replaces outbound / drains pending.
//
// Pending drain pre-installs a placeholder running entry per pair under
// d.mu BEFORE releasing the lock, so an UnregisterPair racing against the
// drain window observes running[pairId], cancels it, and the goroutine
// never opens a peer connection for a pair the caller already removed.
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
	// Pre-install loops so UnregisterPair, if racing, can find and cancel.
	parent := d.outbound.Ctx()
	loops := make([]*sstpPairLoop, 0, len(pending))
	ctxs := make([]context.Context, 0, len(pending))
	for _, pairId := range pending {
		if _, ok := d.running[pairId]; ok {
			// Already spawned (duplicate pending entry) — skip.
			loops = append(loops, nil)
			ctxs = append(ctxs, nil)
			continue
		}
		ctx, cancel := context.WithCancel(parent)
		loop := &sstpPairLoop{cancel: cancel, done: make(chan struct{})}
		d.running[pairId] = loop
		loops = append(loops, loop)
		ctxs = append(ctxs, ctx)
	}
	d.mu.Unlock()

	for i, pairId := range pending {
		if loops[i] == nil {
			continue
		}
		d.spawnPair(ctxs[i], pairId, loops[i])
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

// startPair is the internal starter used by RegisterPair (post-Bind). It
// allocates the per-pair context and running-map entry under d.mu, then
// hands off to spawnPair to launch the goroutine outside the lock.
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

	d.spawnPair(ctx, pairId, loop)
}

// spawnPair launches the per-pair goroutine after the caller has installed
// the running-map entry. Used by both startPair (RegisterPair path) and
// Bind (pending-drain path).
func (d *SstpDialer) spawnPair(ctx context.Context, pairId string, loop *sstpPairLoop) {
	go func() {
		defer close(loop.done)
		// If the pair was already cancelled (e.g. UnregisterPair fired
		// against a placeholder loop from Bind before this goroutine was
		// scheduled), exit immediately without opening a peer connection.
		if ctx.Err() != nil {
			d.mu.Lock()
			if cur, ok := d.running[pairId]; ok && cur == loop {
				delete(d.running, pairId)
			}
			d.mu.Unlock()
			return
		}
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
//
// The running-map entry is KEPT until the goroutine confirms exit (or the
// 2s timeout fires). Removing it before the wait would let an immediate
// RegisterPair spawn a second goroutine that races the first for the
// pair's cluster lease.
func (d *SstpDialer) UnregisterPair(pairId string) {
	d.mu.Lock()
	loop, ok := d.running[pairId]
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
	// The pair is going away, so nothing will ever carry its deferred feedback.
	d.dropDeferredFeedback(pairId)
	if !ok {
		return
	}
	loop.cancel()
	// Best-effort wait so a UnregisterPair immediately followed by a
	// RegisterPair does not race the old goroutine's cleanup. The goroutine
	// self-cleans its entry in d.running on exit (startPair's defer).
	timedOut := false
	select {
	case <-loop.done:
	case <-time.After(2 * time.Second):
		sstpDialerLog.Warn("UnregisterPair: goroutine did not exit within 2s", "pairId", pairId)
		timedOut = true
	}
	if timedOut {
		// The goroutine is still alive; drop the entry so a subsequent
		// RegisterPair is not silently swallowed as a duplicate. The old
		// goroutine's own self-clean at exit is guarded on the loop
		// pointer matching, so it will not clobber a newly-spawned entry.
		d.mu.Lock()
		if cur, ok := d.running[pairId]; ok && cur == loop {
			delete(d.running, pairId)
		}
		d.mu.Unlock()
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
		if s := d.statsSink(); s != nil {
			s.TrackLeaseAcquisition(resource, acquired && err == nil)
		}
		if err != nil {
			sstpDialerLog.Error("lease acquisition error", "pairId", pairId, "error", err)
		}

		if !acquired {
			sstpDialerLog.Debug("lease not held, waiting...", "pairId", pairId)
			// Cancellable delay via the configured Sleep (eventRouter.SleepCtx by
			// default) rather than time.After: this runs every loop iteration while
			// another node holds the lease, and an unstopped timer per spin is exactly
			// the leak Go 1.27's synchronous timer channels make visible.
			if !d.cfg.Sleep(ctx, d.cfg.HeartbeatInterval+d.cfg.LeaseDuration/2) {
				return
			}
			continue
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
	if s := d.statsSink(); s != nil {
		s.IncLeasesHeld()
		defer s.DecLeasesHeld()
	}

	resource := fmt.Sprintf("sstp-client:%s", pairId)

	// cycleCtx parents every outbound HTTP cycle. Cancelled on lease loss
	// (heartbeat) or shutdown (parent ctx) so in-flight requests abort.
	cycleCtx, cycleCancel := context.WithCancel(parentCtx)
	defer cycleCancel()

	// The fencing token is strictly monotonic per resource (ClusterCoordinator
	// contract): every successful acquire/renew increments it. Downstream
	// ack ownership checks (eventService.AckEvent) compare against the
	// stored expected token, so a stale value silently no-ops all acks
	// after the first heartbeat renew. Publish it atomically so the
	// heartbeat can update it in place while the cycle reads it.
	var currentFencingToken atomic.Int64
	currentFencingToken.Store(fencingToken)

	go d.heartbeat(cycleCtx, cycleCancel, resource, pairId, &currentFencingToken)

	delay := d.cfg.BaseDelay

	// pending carries the feedback owed to the peer: the JTIs of inbound
	// response-carried SETs we have successfully ingested via HandleInboundEvent
	// but not yet echoed back in an SSTP request's Ack field (PRD #49 slice 2c
	// AC 1), plus the per-JTI setErrs for SETs we rejected on event-validation
	// grounds (spec #247 #254). The pair-loop owns it so request-side carriage
	// survives across cycles: appended after each inbound half, cleared on the
	// next cycle whose Exchange the peer accepted (200 → ClassOK / ClassPerJTI).
	// On transport / 4xx / weird responses it is preserved so the feedback is
	// retried on the next successful exchange — never lost mid-flight.
	var pending sstpPendingFeedback

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

		// Fold in any feedback a second push produced while an earlier cycle was
		// in flight. Drained here — before the primary goroutine starts and while
		// nothing else touches `pending` — so the merge needs no lock of its own
		// and a second push landing mid-cycle is simply carried one cycle later.
		pending.merge(d.takeDeferredFeedback(pairId))

		// Run the primary cycle concurrently so the loop can react to a new
		// outbound SET arriving while the peer holds this cycle's connection
		// as a long-poll (push-while-poll-held, Q7.2, #166).
		outcome, resumeDelay, exit, updatedPending := d.runPrimaryCycleWithSecondPush(cycleCtx, &streamCopy, currentFencingToken.Load(), &delay, pending)
		_ = outcome
		pending = updatedPending
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
// shutdown cancels both. Returns the primary cycle's outcome verbatim plus
// the updated pending-inbound-acks list (AC 1) — the primary owns the ack
// list; the second push carries no Ack (returnEvents=false request, so the
// peer already has no state that needs an ack echoed on that side POST).
func (d *SstpDialer) runPrimaryCycleWithSecondPush(ctx context.Context, stream *model.StreamStateRecord, fencingToken int64, delay *time.Duration, pending sstpPendingFeedback) (goSetSstp.Classification, time.Duration, bool, sstpPendingFeedback) {
	pairId := stream.PairId
	type cycleResult struct {
		cls     goSetSstp.Classification
		delay   time.Duration
		exit    bool
		pending sstpPendingFeedback
	}
	done := make(chan cycleResult, 1)
	go func() {
		cls, dly, exit, updated := d.runCycle(ctx, stream, fencingToken, delay, pending)
		done <- cycleResult{cls: cls, delay: dly, exit: exit, pending: updated}
	}()

	// secondPushWg tracks in-flight second-push goroutines so we do not
	// leak them past this cycle: we wait for them before returning.
	var secondPushWg sync.WaitGroup
	defer secondPushWg.Wait()

	wakeup := d.outbound.WakeCh(pairId)
	for {
		select {
		case res := <-done:
			return res.cls, res.delay, res.exit, res.pending
		case <-ctx.Done():
			// Lease loss / shutdown: primary observes ctx and returns
			// (exit=true); wait for it so we return its result and never
			// leak it.
			res := <-done
			return res.cls, res.delay, res.exit, res.pending
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
			// Skip the goroutine spawn entirely when the second-push slot is
			// already held — otherwise a bursty wake stream (thousands of
			// subject-filter wakes/sec) queues thousands of no-op goroutines
			// into secondPushWg and the outer function cannot return until
			// each one is scheduled and drained, delaying failover for the
			// wakeup burst's duration. pushWhilePollHeld re-checks the slot
			// itself — this is a fast reject to prevent goroutine backlog.
			if !d.outbound.AcquireSecondPushSlot(pairId) {
				continue
			}
			d.outbound.ReleaseSecondPushSlot(pairId)
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
// the caller should wait before the next cycle (0 = immediate), exit=true
// when the loop should terminate (stream disabled, ctx done, sign failure,
// weird response), and the updated pending feedback (acks + setErrs) to carry
// into the next cycle (AC 1, #254).
//
// delay carries the running exponential-backoff value across transport /
// transient retries; it is reset to BaseDelay on ClassOK/ClassPerJTI. Sleep
// delays returned to the caller are jittered ±25% (AC 4).
//
// pending carries the acks (and, per #254, the setErrs) owed to the peer from
// earlier cycles, echoed in this request. They are discharged only on a
// peer-accepted (200) response; on 4xx / transport / sign-failure the same
// value is preserved so the feedback is retried on the next successful
// exchange. This cycle's own inbound half (verified via goSetSstp.VerifySET,
// fed to HandleInboundEvent WITHOUT re-parse — AC 2) becomes the returned
// feedback so it rides the NEXT request.
func (d *SstpDialer) runCycle(ctx context.Context, stream *model.StreamStateRecord, fencingToken int64, delay *time.Duration, pending sstpPendingFeedback) (goSetSstp.Classification, time.Duration, bool, sstpPendingFeedback) {
	pairId := stream.PairId

	// Gather the outbound JTIs to flush this cycle. Drain the buffer first
	// (claim in-flight); the ClaimOutbound surface method already falls
	// back to the pending list when the buffer is empty (Q13).
	outJtis := d.outbound.ClaimOutbound(pairId, d.cfg.BackfillBatch)

	events := d.outbound.ResolveEvents(pairId, outJtis)

	// Idle guard: no outbound events AND nothing owed to the peer means there
	// is nothing to say this cycle. Idle a short cycle rather than open a
	// keep-alive request that would only add load without carrying state. When
	// pending feedback IS non-empty we still POST (empty Sets, non-empty Ack /
	// setErrs) so the peer can clear its outbound (AC 1, and #254 so a
	// validation rejection is reported rather than resent forever). When events
	// is non-empty we always POST (normal outbound cycle).
	if len(events) == 0 && pending.empty() {
		*delay = d.cfg.BaseDelay
		return goSetSstp.Classification{Class: goSetSstp.ClassOK}, d.cfg.BaseDelay, false, pending
	}

	var signingKey crypto.Signer
	var kid string
	if len(events) > 0 && stream.GetRouteMode() != model.RouteModeForward {
		signingKey, kid = d.outbound.LoadSigningKey(stream.StreamConfiguration.Id, stream.StreamConfiguration.Iss, stream.StreamConfiguration.SigningAlg)
	}

	// AC 1: carry the pending feedback in the request. Non-empty feedback alone
	// is enough to justify a request (the idle guard above ensures we do
	// not POST when both events AND the feedback are empty).
	cls, acked, received, signErr := d.deliver(ctx, stream, events, signingKey, kid, nil, pending)

	if ctx.Err() != nil {
		// Cancelled in flight: release the claim so the next owner
		// re-drains and retries these events. Feedback preserved.
		d.outbound.ReleaseOutbound(pairId, events)
		return cls, 0, true, pending
	}

	// AC 5: signing failure is an error, not a skip. Halt the dial cycle
	// (release the claim, pause outbound so an operator investigates the
	// broken key material, exit the loop) rather than send an unsigned SET.
	// Signing runs BEFORE Exchange, so nothing has been sent — the pending
	// feedback is preserved verbatim (no request reached the peer, nothing owed
	// has been discharged).
	if signErr != nil {
		d.outbound.ReleaseOutbound(pairId, events)
		reason := fmt.Sprintf("SSTP-CLIENT: signing failure on pair=%s: %s", pairId, signErr.Error())
		sstpDialerLog.Error("egress signing failure — halting dial cycle",
			"pairId", pairId, "error", signErr)
		d.outbound.PauseOutbound(stream, reason)
		return cls, 0, true, pending
	}

	switch cls.Class {
	case goSetSstp.ClassOK, goSetSstp.ClassPerJTI:
		// AC 2: ingest response-carried SETs via VerifySET → HandleInboundEvent
		// without re-parse. Any JTI whose verify or HandleEvent fails is NOT
		// added to newAcks, so the peer's outbound will resend it on a
		// subsequent cycle (US 5 literal-ack semantics: only what we
		// actually accepted is acked).
		newFeedback := d.runInboundHalf(stream, received)
		cleared, fatal := clearedOutbound(stream.PairId, acked, cls.SetErrs)
		ackedCount := d.outbound.AckOutbound(stream, cleared, events, fencingToken)
		*delay = d.cfg.BaseDelay

		// AC 1: the peer accepted the request, so the feedback we just echoed is
		// consumed. What carries forward is only this cycle's inbound half
		// (which rides the NEXT request's Ack / setErrs).
		updatedPending := newFeedback

		// A stream-fatal setErr (binding-revoked) says every subsequent send is
		// rejected the same way. Pause outbound and exit rather than spend the
		// next cycles draining the queue into a dead stream; the SETs stay
		// pending, so a resume replays them.
		if fatal != nil {
			reason := fmt.Sprintf("SSTP-CLIENT: peer reports stream dead on pair=%s: %s: %s",
				stream.PairId, fatal.Err, fatal.Description)
			d.outbound.PauseOutbound(stream, reason)
			return cls, 0, true, updatedPending
		}

		// If we acked everything we sent, drain more immediately;
		// otherwise idle a short cycle to avoid re-sending unacked SETs.
		if len(events) > 0 && ackedCount >= len(events) {
			return cls, 0, false, updatedPending
		}
		if len(events) == 0 && len(received) == 0 {
			// Purely idle cycle — sleep the base delay to avoid busy-loop.
			return cls, d.cfg.BaseDelay, false, updatedPending
		}
		return cls, d.cfg.BaseDelay, false, updatedPending

	case goSetSstp.ClassRequestError:
		// 4xx: pause ONLY the outbound (client) direction of the pair.
		// Release the claim so a later resume re-drains and retries.
		// Pending feedback preserved so it retries after resume.
		d.outbound.ReleaseOutbound(pairId, events)
		reason := fmt.Sprintf("SSTP-CLIENT: 4xx request error on pair=%s", pairId)
		d.outbound.PauseOutbound(stream, reason)
		return cls, 0, true, pending

	case goSetSstp.ClassTransient, goSetSstp.ClassTransport:
		// 5xx / connection failure: back off per POLL_RETRY_*, do NOT
		// pause (Q25). Release the claim so the retried cycle re-drains.
		// Pending feedback preserved for the retry.
		d.outbound.ReleaseOutbound(pairId, events)
		next := *delay
		if cls.NextDelay > 0 {
			next = cls.NextDelay
		}
		// AC 4: jitter the sleep-now value; the stored ladder is unjittered
		// so exponential growth stays monotonic.
		jittered := jitteredSstpBackoff(next)
		sstpDialerLog.Warn("transport/transient failure, backing off",
			"pairId", pairId, "class", cls.Class.String(), "delay", jittered)
		*delay = nextSstpBackoff(*delay, d.cfg.BackoffFactor, d.cfg.MaxDelay)
		return cls, jittered, false, pending

	default: // ClassWeirdResponse
		d.outbound.ReleaseOutbound(pairId, events)
		reason := fmt.Sprintf("SSTP-CLIENT: weird response on pair=%s", pairId)
		d.outbound.PauseOutbound(stream, reason)
		return cls, 0, true, pending
	}
}

// runInboundHalf verifies each response-carried SET via goSetSstp.VerifySET
// and hands the verified token to HandleInboundEvent WITHOUT re-parse
// (PRD #49 slice 2c AC 2). Returns the feedback owed to the peer on the next
// request: the JTIs of SETs that BOTH verified AND ingested successfully
// (AC 1, US 5 literal semantics), plus per-JTI setErrs for SETs this side
// rejected on event-validation grounds (spec #247 #254).
//
// A per-JTI verify or ingest failure is logged and dropped from the ack list
// WITHOUT a setErr, so the peer's outbound will resend on the next cycle until
// we either accept it or operator intervention resolves the trust-root
// mismatch. An event-validation rejection is the opposite case — deterministic
// on resend — so it is reported as a setErr instead of left to be retried.
func (d *SstpDialer) runInboundHalf(stream *model.StreamStateRecord, received map[string]string) sstpPendingFeedback {
	if len(received) == 0 {
		return sstpPendingFeedback{}
	}
	// AC 2: config comes from today's business-stream trust settings —
	// JWKS-backed; ExpectedIssuer / ExpectedAudiences from the pair's inbound
	// direction. AllowedAlgs is left nil so VerifySET applies the
	// {RS256, ES256, EdDSA} default (Seam 2 r3 / ADR-0066).
	cfg := d.outbound.InboundVerifyConfig(stream)
	rxSid := ""
	if stream.SstpInbound != nil {
		rxSid = stream.SstpInbound.Id
	}
	// Event validation (spec #247 #254). The pair is ONE bidirectional record
	// (ADR COM-0018), so the same event_validation field the acceptor reads
	// governs this leg too — the dialer's inbound half IS a receiver, and an
	// operator's policy must not depend on which side dialed.
	policy, validators := sstpInboundValidationPolicy(stream,
		services.ResolveEventValidationMode(stream, d.cfg.EventValidationDefault),
		d.validationStats())
	cfg.Validators = validators
	// If JWKS resolution failed (async load pending, IssuerJWKSUrl
	// unreachable, inbound record not yet cached), every VerifySET below
	// would reject with ErrBadSignature and log a per-JTI warn — the
	// dialer would still return empty acks (so the peer resends and the
	// SETs are not lost), but the log surface saturates. Short-circuit
	// with a single warn and drop the batch unacked; a later cycle whose
	// JWKS has arrived processes the resend normally.
	if cfg.RequireSignature && cfg.JWKS == nil {
		sstpDialerLog.Warn("inbound JWKS unavailable — deferring verify, peer will resend",
			"pairId", stream.PairId, "count", len(received))
		return sstpPendingFeedback{}
	}
	feedback := sstpPendingFeedback{Acks: make([]string, 0, len(received))}
	for jti, raw := range received {
		verified, vErr := goSetSstp.VerifySET(raw, cfg)
		if vErr != nil {
			sstpDialerLog.Warn("inbound response SET failed verify — dropping",
				"pairId", stream.PairId, "jti", jti, "error", vErr)
			continue
		}
		if verified.Token == nil {
			// Defensive: a nil Token from VerifySET violates its contract,
			// but skipping is safer than a panic under an unexpected shape.
			sstpDialerLog.Warn("VerifySET returned nil Token — skipping ingest",
				"pairId", stream.PairId, "jti", jti)
			continue
		}
		if vsErr := policy.applySstpInbound(jti, verified.Validation); vsErr != nil {
			// Rejected before ingest: the SET never reaches the event router,
			// exactly as on the acceptor path.
			feedback.addSetErr(jti, *vsErr)
			continue
		}
		if iErr := d.outbound.HandleInboundEvent(verified.Token, verified.Raw, rxSid); iErr != nil {
			sstpDialerLog.Warn("HandleInboundEvent failed — dropping ack for JTI",
				"pairId", stream.PairId, "jti", jti, "error", iErr)
			continue
		}
		feedback.Acks = append(feedback.Acks, jti)
	}
	return feedback
}

// validationStats returns the Prometheus handler behind the dialer's stats sink,
// or nil when none is wired (tests, or before InitializePrometheus late-binds
// it). Mirrors statsFor on the handler side: the event-validation counter is a
// concrete-handler concern, so it is narrowed here rather than widening the
// lease-oriented SstpDialerStats interface every test fake implements.
func (d *SstpDialer) validationStats() *PrometheusHandler {
	if h, ok := d.statsSink().(*PrometheusHandler); ok {
		return h
	}
	return nil
}

// heartbeat renews the lease every HeartbeatInterval. A single renew
// failure is retried once after a short pause before the lease is declared
// lost (Q14.c) — one-shot Mongo blips do not trigger takeover churn. On a
// confirmed loss it cancels cycleCtx, aborting any in-flight cycle (Q14.a).
// currentFencingToken is updated with the fresh token on every successful
// renew so downstream ack ownership checks (eventService.AckEvent) see the
// live token rather than the initial acquire's value.
func (d *SstpDialer) heartbeat(cycleCtx context.Context, cancel context.CancelFunc, resource, pairId string, currentFencingToken *atomic.Int64) {
	ticker := time.NewTicker(d.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if d.renewLeaseWithRetry(cycleCtx, resource, pairId, currentFencingToken) {
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
// ownership is retained, false once the lease is confirmed lost. On success
// stores the fresh fencing token into currentFencingToken so subsequent
// AckOutbound/AckEvent calls carry the live value.
func (d *SstpDialer) renewLeaseWithRetry(ctx context.Context, resource, pairId string, currentFencingToken *atomic.Int64) bool {
	ok, token, err := d.coordinator.TryAcquireOrRenewLease(resource, d.nodeID, d.cfg.LeaseDuration)
	if s := d.statsSink(); s != nil {
		s.TrackLeaseAcquisition(resource, ok && err == nil)
	}
	if ok && err == nil {
		currentFencingToken.Store(token)
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

	ok, token, err = d.coordinator.TryAcquireOrRenewLease(resource, d.nodeID, d.cfg.LeaseDuration)
	if s := d.statsSink(); s != nil {
		s.TrackLeaseAcquisition(resource, ok && err == nil)
	}
	if ok && err == nil {
		currentFencingToken.Store(token)
		return true
	}
	return false
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

	var signingKey crypto.Signer
	var kid string
	if stream.GetRouteMode() != model.RouteModeForward {
		signingKey, kid = d.outbound.LoadSigningKey(stream.StreamConfiguration.Id, stream.StreamConfiguration.Iss, stream.StreamConfiguration.SigningAlg)
	}

	returnEvents := goSetSstp.BoolPtr(false)
	// The second push carries NO Ack — the primary owns pendingAcks
	// bookkeeping (AC 1). Running Acks through both cycles risks the peer
	// clearing an outbound entry twice and any concurrent list mutation
	// race between the two goroutines. Empty Ack here is deliberate.
	cls, acked, received, signErr := d.deliver(ctx, stream, events, signingKey, kid, returnEvents, sstpPendingFeedback{})

	if signErr != nil {
		// AC 5: signing failure halts even on the second-push path — never
		// send an unsigned SET. Pause outbound and log; the primary loop
		// will observe the pause on its next RefreshPair and exit.
		d.outbound.ReleaseOutbound(pairId, events)
		reason := fmt.Sprintf("SSTP-CLIENT: signing failure on push-while-poll-held for pair=%s: %s", pairId, signErr.Error())
		sstpDialerLog.Error("egress signing failure on second push — halting",
			"pairId", pairId, "error", signErr)
		d.outbound.PauseOutbound(stream, reason)
		return goSetSstp.Classification{Class: goSetSstp.ClassRequestError}
	}

	switch cls.Class {
	case goSetSstp.ClassOK, goSetSstp.ClassPerJTI:
		// Second-push acks: the peer's returned Ack is its "we received
		// these" acknowledgement for the SETs we just sent. Use it verbatim
		// (no ack-all fallback, AC 3), plus any JTI the peer rejected
		// deterministically — such a rejection clears the SET on the same terms
		// as an ack, while a retryable one stays pending for a later cycle.
		cleared, fatal := clearedOutbound(pairId, acked, cls.SetErrs)
		d.outbound.AckOutbound(stream, cleared, events, fencingToken)
		// A peer whose acceptor opportunistically ships queued outbound SETs
		// on any 200 response (permitted by §2.1 semantics — returnEvents=false
		// forbids long-poll waiting, not the return of already-queued SETs)
		// would otherwise have its Sets silently dropped. Ingest+ack them so
		// they land in the pair's inbound stream rather than being resent.
		if len(received) > 0 {
			// The feedback for those SETs cannot ride this response — the request
			// is already sent — and this goroutine may not touch the pair loop's
			// carried value. Hand it to the deferred store so the loop echoes it
			// on its next request; dropping it left the peer resending the same
			// SETs forever, which is precisely the loop the setErr carriage
			// exists to break.
			d.deferFeedback(pairId, d.runInboundHalf(stream, received))
		}
		// A stream-fatal setErr pauses ONLY outbound, like the 4xx case below:
		// every subsequent send is rejected the same way, so stop pushing rather
		// than drain the queue into a dead stream. The held primary long-poll
		// (inbound) is untouched, and the SETs stay pending for a resume.
		if fatal != nil {
			d.outbound.PauseOutbound(stream, fmt.Sprintf(
				"SSTP-CLIENT: peer reports stream dead on push-while-poll-held for pair=%s: %s: %s",
				pairId, fatal.Err, fatal.Description))
		}
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

// deliver performs one SSTP HTTP cycle by calling pkg/goSetSstp.Exchange
// (ADR-0067 single-cycle). Returns the classifier's verdict, the peer's ack
// list, the response-carried SETs (jti → compact SET string) for the caller
// to verify + ingest via the inbound half (AC 2), and a signing error if
// egress signing failed (AC 5 — signing failure is an ERROR that halts the
// dial cycle, never a silent skip).
//
// Signing runs BEFORE Exchange: on signErr != nil no HTTP request is issued,
// so the caller's rollback is trivial (release the claim + pause + exit).
// This is the single egress-signing site the AC consolidates onto — the
// legacy "HTTP adapter also signs" split is retired here.
//
// feedback carries the caller's pending inbound feedback (AC 1 request-side
// Ack carriage plus #254 setErrs): the JTIs of previously-ingested response
// SETs to echo back so the peer clears them from its outbound, and the per-JTI
// errors for response SETs this side rejected.
//
// The HTTP client + Authorization header come from the credential-chain
// resolver (PRD 49 slice 2b, AC 2): when d.cfg.ResolveClient is wired
// (production path), the per-cycle client honors PeerServerAlias transport
// posture and the per-pair bearer wins the Authorization header (AC 3
// precedence). When ResolveClient is unset (tests) or errors, the dialer
// falls back to d.cfg.HTTPClient + the raw per-pair bearer.
func (d *SstpDialer) deliver(ctx context.Context, stream *model.StreamStateRecord, events []*model.EventRecord, key crypto.Signer, kid string, returnEvents *bool, feedback sstpPendingFeedback) (goSetSstp.Classification, []string, map[string]string, error) {
	method := stream.SstpMethod
	if method == nil || method.EndpointUrl == "" {
		return goSetSstp.Classification{Class: goSetSstp.ClassRequestError}, nil, nil, nil
	}

	// AC 5: egress signing is the SINGLE consolidated site. Sign FIRST so a
	// failure short-circuits before any HTTP work happens; the caller then
	// halts the dial cycle rather than sending an unsigned SET.
	sets, signErr := buildSstpSets(stream, events, key, kid)
	if signErr != nil {
		return goSetSstp.Classification{Class: goSetSstp.ClassRequestError}, nil, nil, signErr
	}

	msg := goSetSstp.Message{
		ReturnEvents: returnEvents,
		Sets:         sets,
		Ack:          feedback.Acks,
		SetErrs:      feedback.SetErrs,
	}

	client := d.cfg.HTTPClient
	auth := method.AuthorizationHeader
	closeClient := func() {}
	if d.cfg.ResolveClient != nil {
		if resolved, resolvedAuth, resolvedClose, err := d.cfg.ResolveClient(ctx, stream); err == nil {
			client = resolved
			// The resolver is authoritative for auth (SSTP branch already
			// picks the per-pair bearer per AC 3). Empty means "client
			// injects Authorization itself" (OAuth transport).
			auth = resolvedAuth
			if resolvedClose != nil {
				closeClient = resolvedClose
			}
		} else {
			sstpDialerLog.Warn("credential-chain resolver failed; falling back to inline HTTP client",
				"pairId", stream.PairId, "error", err)
		}
	}
	defer closeClient()

	// Prefix "Bearer " only when auth is a raw token — i.e., no scheme prefix.
	// A token that happens to contain the substring "bearer" or a space is
	// still a raw token; only a leading "bearer " (case-insensitive) or a
	// leading token with a space (another scheme) means the caller already
	// supplied a scheme. Use HasPrefix, not Contains, per RFC 7235.
	if auth != "" {
		lower := strings.ToLower(auth)
		hasScheme := strings.HasPrefix(lower, "bearer ") ||
			strings.HasPrefix(lower, "basic ") ||
			strings.HasPrefix(lower, "digest ")
		if !hasScheme {
			auth = "Bearer " + auth
		}
	}

	result := goSetSstp.Exchange(ctx, msg, goSetSstp.DialerConfig{
		EndpointURL:   method.EndpointUrl,
		Authorization: auth,
		HTTPClient:    client,
	})

	cls := goSetSstp.ClassifyResult(result)
	var acked []string
	var received map[string]string
	if result.Message != nil {
		acked = result.Message.Ack
		received = result.Message.Sets
	}
	return cls, acked, received, nil
}

// buildSstpSets renders each outbound event to its on-wire SET string:
// forwarded verbatim in RouteModeForward, or signed with the pair's issuer
// key otherwise (AC 5 — consolidated egress-signing site).
//
// PRD #49 slice 2c AC 5: a signing failure returns an error rather than
// silently skipping the JTI. Missing key material for a publish-mode pair
// is likewise an error — sending an unsigned SET violates ADR-0067's
// verify-at-ingest invariant, so the dial cycle halts (caller's contract)
// rather than dropping SETs onto the wire with no signature. Forward-mode
// pairs bypass signing entirely (Event.Original is on-wire verbatim), so
// they can never trip this error.
func buildSstpSets(stream *model.StreamStateRecord, events []*model.EventRecord, key crypto.Signer, kid string) (map[string]string, error) {
	if len(events) == 0 {
		return nil, nil
	}
	cfg := stream.StreamConfiguration
	forward := cfg.RouteMode == model.RouteModeForward
	if !forward && key == nil {
		return nil, fmt.Errorf("sstp: no signing key for stream %s (issuer %s)", cfg.Id, cfg.Iss)
	}
	sets := make(map[string]string, len(events))
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if forward {
			sets[ev.Jti] = ev.Original
			continue
		}
		token := &ev.Event
		token.Issuer = cfg.Iss
		token.Audience = cfg.Aud
		token.IssuedAt = jwt.NewNumericDate(time.Now())
		token.Kid = kid
		signed, err := token.JWS(goSet.SigningMethodOrRS256(cfg.SigningAlg), key)
		if err != nil {
			// AC 5: signing failure is an ERROR — halt the dial cycle
			// rather than send an unsigned SET (or drop it silently).
			return nil, fmt.Errorf("sstp: sign JTI %s: %w", ev.Jti, err)
		}
		sets[ev.Jti] = signed
	}
	return sets, nil
}
