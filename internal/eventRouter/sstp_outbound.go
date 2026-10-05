// SSTP outbound surface + dialer hooks (PRD #49 slice 2a).
//
// SstpOutbound is the narrow exported-in-repo surface the relocated SSTP
// dialer (internal/server) consumes to speak to router-owned per-pair state:
// the outbound EventPollBuffer, the in-flight claim set, the second-push
// slot, the source-of-truth pair record, and the issuer-key cache. It keeps
// buffer / claim / in-flight / lease bookkeeping in the router — which
// already owns it via routeEventToSstpPairsLocked, RemoveStream, and
// UpdateStreamState — while the dialer stays a pure loop over
// pkg/goSetSstp.Exchange (ADR-0025, ADR-0067 loop-relocation pin).
//
// SstpDialerHooks is the inverse hook: the router calls RegisterPair /
// UnregisterPair as pairs come and go, so the dialer starts / stops per-pair
// goroutines out of the router. Nil is legal (unit-test routers that do not
// wire a dialer simply skip the callback and no SSTP dialer goroutine
// starts — the AC-3 production-wiring pin lives in internal/server).
package eventRouter

import (
	"context"
	"crypto"
	"errors"
	"os"
	"strconv"
	"sync"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SstpOutbound is the narrow per-pair facade the relocated dialer consumes.
// Methods are keyed on PairId so the dialer never touches router internals
// directly. Implemented by *router.
type SstpOutbound interface {
	// WakeCh returns the pair's outbound-buffer wake channel. A Wakeup()
	// swaps the notifier channel, so callers should re-arm each iteration.
	// Nil when the pair is unknown (removed).
	WakeCh(pairId string) <-chan struct{}

	// RefreshPair returns the current source-of-truth record for pairId;
	// ok=false when the pair has been removed. The runner re-reads this
	// each cycle so a rotated bearer / changed endpoint / pause applied
	// via UpdateStreamState (which mutates the map) is observed within
	// one cycle (Finding #9 / #8).
	RefreshPair(pairId string) (model.StreamStateRecord, bool)

	// ClaimOutbound drains up to max outbound JTIs from the pair's buffer,
	// falling back to the pending list when the buffer is empty (recovery
	// after takeover relies on persisted outbound events, Q13). Returned
	// JTIs are claimed in-flight for the pair; callers MUST later ack them
	// (AckOutbound) or release them (ReleaseOutbound / ReleaseJtis). Returns
	// nil when no outbound work exists.
	ClaimOutbound(pairId string, max int) []string

	// ResolveEvents turns claimed JTIs into event records to flush, dropping
	// any whose event record was deleted between claim and resolve. Callers
	// receive the resolved events; the dropped JTIs have their claim
	// released so a vanished event never holds a permanent claim (Finding
	// mentioned in resolveSstpEventsByJti / releaseUnresolvedSstpClaims).
	ResolveEvents(pairId string, claimed []string) []*model.EventRecord

	// AckOutbound acks the peer-acknowledged JTIs among sent: removes them
	// from the buffer (Finding #1 — copy-only GetEvents would otherwise
	// re-hand them out), acks them in the provider, releases their claim,
	// and increments the outbound eventsOut counter (tfr=SSTP, stream_id=
	// txSid) per acked event (Q46). Any sent-but-unacked JTI has its claim
	// released so it is re-drained on a later cycle. When acked is empty
	// the entire sent set is treated as accepted (§2.3 success-without-
	// detail). Returns the number of acked (and counted) events.
	AckOutbound(stream *model.StreamStateRecord, acked []string, sent []*model.EventRecord, fencingToken int64) int

	// ReleaseOutbound releases the in-flight claim on every JTI in events
	// WITHOUT removing them from the buffer, so a failed-delivery SET is
	// re-drained (and retried) on a later cycle.
	ReleaseOutbound(pairId string, events []*model.EventRecord)

	// ReleaseJtis is the JTI-slice variant of ReleaseOutbound. Used when the
	// caller only has JTIs (e.g. dropping a claimed-but-unresolvable JTI).
	ReleaseJtis(pairId string, jtis []string)

	// PausePair pauses the pair — both its outbound and inbound halves — via
	// the single transition point. The two logical streams share one HTTP
	// exchange, so a pause stops both, as it does a push or poll stream's one
	// status (#303). The pause is written back into the source-of-truth map so
	// the runner's next-cycle RefreshPair observes it (Finding #9).
	PausePair(stream *model.StreamStateRecord, reason string)

	// PauseForSigningKey is the dialing end's key-unavailable pause (#312),
	// taken when the pair could not sign what it would send: no active signing
	// key for its iss and signing_alg, or cause, the error signing with the key
	// it had. Nothing has been sent. It pauses the pair (both halves) with a
	// reason naming the issuer and algorithm and the KeyUnavailableSince marker,
	// writes the pause into the source-of-truth map so the loop's next
	// RefreshPair exits, and logs one ERROR. The background key check resumes
	// the pair, and with it the dial loop, when the key is back, and disables it
	// after the retry limit.
	PauseForSigningKey(stream *model.StreamStateRecord, cause error)

	// LoadSigningKey returns the issuer's private signing key + kid,
	// consulting the router's issuer-key cache (or loading it once and
	// caching). RouteModeForward pairs skip this call — the dialer forwards
	// Event.Original verbatim.
	LoadSigningKey(streamID, issuer, alg string) (crypto.Signer, string)

	// AcquireSecondPushSlot reserves one of the pair's K push-while-poll-held
	// slots (I2SIG_SSTP_PUSH_INFLIGHT, #339; Q7.2 fixed K at one), returning
	// false when K pushes are already in flight for the pair. A coalesced
	// call returns without opening another parallel request.
	AcquireSecondPushSlot(pairId string) bool

	// ReleaseSecondPushSlot releases a slot acquired by
	// AcquireSecondPushSlot. Safe to call from a defer.
	ReleaseSecondPushSlot(pairId string)

	// BackfillBatch is the router-configured claim/drain batch size,
	// I2SIG_PUSH_BACKFILL_BATCH (with the legacy alias). The relocated
	// dialer uses it as the max on ClaimOutbound so recovery-after-takeover
	// and the primary drain use the same batch size as push and poll.
	BackfillBatch() int

	// SignConcurrency is the router-configured I2SIG_SIGN_CONCURRENCY: how
	// many SETs the dialer re-signs side by side when it builds one outbound
	// SSTP message (ADR 0036). The same knob sizes the poll transmitter's and
	// the SSTP responder's signing pools.
	SignConcurrency() int

	// Ctx returns the router's shutdown context. The dialer parents every
	// cycle context on it so router.Shutdown() cancels in-flight cycles
	// (Q14.a shutdown handoff).
	Ctx() context.Context

	// InboundVerifyConfig returns the JWKS-backed verify config for the pair's
	// inbound direction (rec.SstpInbound), used by the dialer's response-SET
	// ingest half (PRD #49 slice 2c AC 2). ExpectedIssuer / ExpectedAudiences
	// come from rec.SstpInbound.Iss / Aud; the JWKS comes from the router's
	// StreamService.GetIssuerJwksForReceiver keyed on rec.SstpInbound.Id.
	// A nil rec (or one without SstpInbound) returns a bare config whose nil
	// JWKS forces goSetSstp.VerifySET into its ErrBadSignature path — a pair
	// without a configured inbound trust root never accepts a response SET.
	InboundVerifyConfig(rec *model.StreamStateRecord) goSetSstp.VerifyConfig

	// HandleInboundEvent hands a verified inbound SET to the router's ingest
	// path (persist-then-route, HandleEvent) using the pair's rx-side SID.
	// The dialer calls this after goSetSstp.VerifySET on a response-carried
	// SET so the router's ingest never re-parses (PRD #49 slice 2c AC 2:
	// verified via VerifySET at ingest and fed to router.HandleEvent via
	// VerifiedSET.Token without re-parse).
	HandleInboundEvent(token *goSet.SecurityEventToken, raw string, sid string) error
	// HandleInboundEvents is the batch form of HandleInboundEvent for the SETs
	// one response carried: they are persisted in one bulk write and fanned out
	// with one pending-list write per matching outbound stream. raws is
	// index-aligned with tokens and so is the returned slice; a nil entry means
	// the SET may be acked.
	HandleInboundEvents(tokens []*goSet.SecurityEventToken, raws []string, sid string) []error
}

// SstpDialerHooks is the hook interface the router calls when SSTP-client
// pairs are added or removed. Implemented in internal/server by the
// SstpDialer, which starts a per-pair goroutine on RegisterPair and stops
// it on UnregisterPair. Nil is legal — test routers that do not need the
// dialer skip these callbacks and no SSTP dialer goroutine ever runs.
type SstpDialerHooks interface {
	// RegisterPair is called after initSstpClientStreamLocked has seeded
	// sstpClientStreams[pairId] and sstpBuffers[pairId]. The dialer looks
	// up the pair via SstpOutbound (RefreshPair, WakeCh) and starts its
	// loop for the pair.
	RegisterPair(pairId string)

	// UnregisterPair is called from RemoveStream. The dialer signals the
	// per-pair goroutine to exit; the goroutine also self-exits when its
	// next RefreshPair returns ok=false, so UnregisterPair is a fast-path
	// (immediate stop) rather than the only stop signal.
	UnregisterPair(pairId string)
}

// SstpOutbound is implemented by *router. The methods below are thin
// facades over pre-existing router helpers (drainSstpBuffer, handleSstpAcks,
// releaseSstpClaims, resolveSstpEventsByJti, releaseUnresolvedSstpClaims,
// pauseSstpPair, refreshSstpClientStream, acquireSstpSecondPushSlot,
// releaseSstpSecondPushSlot, checkAndLoadKey, claimSstpJtis) so the
// migration preserves behavior verbatim (AC 1) while the loop itself moves
// to internal/server.

func (r *router) WakeCh(pairId string) <-chan struct{} {
	r.mu.RLock()
	buf := r.sstpBuffers[pairId]
	r.mu.RUnlock()
	if buf == nil {
		return nil
	}
	return buf.WakeupCh()
}

func (r *router) RefreshPair(pairId string) (model.StreamStateRecord, bool) {
	return r.refreshSstpClientStream(pairId)
}

func (r *router) ClaimOutbound(pairId string, max int) []string {
	r.mu.RLock()
	buf := r.sstpBuffers[pairId]
	pair, ok := r.sstpClientStreams[pairId]
	r.mu.RUnlock()
	if buf == nil || !ok {
		return nil
	}
	// Back-pressure (#336): a pair whose peer-acked SETs are still queued for
	// their coalesced ack write at the in-flight bound writes them before it
	// claims more.
	if ack := r.sstpAcker(pairId); ack != nil && ack.size() >= r.inFlightMax() {
		_ = ack.flush()
	}
	outJtis := r.drainSstpBuffer(pairId, buf, max)
	if len(outJtis) > 0 {
		return outJtis
	}
	// Buffer empty: pull the pending list directly from the provider
	// (recovery after takeover relies on persisted outbound events, Q13)
	// and claim those too. The direct pull avoids racing the buffer's
	// async channel drain.
	//
	// Use a fresh Background context (not r.ctx). r.ctx is cancelled on
	// router.Shutdown, but the dialer pair-loop's own cycle context has
	// not necessarily been cancelled yet — passing r.ctx here would make
	// this final drain silently return 0 events during a graceful
	// shutdown, adding delivery latency until the next takeover. The
	// call is ReturnImmediately, so it will not block on the provider.
	//
	// The read reaches past the JTIs already claimed by a push or cycle still
	// in flight: the store returns pending JTIs oldest first, so reading only
	// max of them came back all-claimed, and empty, while later pending SETs
	// waited for the primary long-poll (#347).
	r.mu.RLock()
	claimed := len(r.sstpInFlight[pairId])
	r.mu.RUnlock()
	pending, _ := r.pendingJtis(context.Background(), pair.StreamConfiguration.Id, model.PollParameters{
		MaxEvents:         int32(max + claimed),
		ReturnImmediately: true,
	})
	return r.claimSstpJtis(pairId, pending, max)
}

func (r *router) ResolveEvents(pairId string, claimed []string) []*model.EventRecord {
	events := r.resolveSstpEventsByJti(claimed)
	r.releaseUnresolvedSstpClaims(pairId, claimed, events)
	return events
}

func (r *router) AckOutbound(stream *model.StreamStateRecord, acked []string, sent []*model.EventRecord, fencingToken int64) int {
	r.mu.RLock()
	buf := r.sstpBuffers[stream.PairId]
	r.mu.RUnlock()
	return r.handleSstpAcks(stream, buf, acked, sent, fencingToken)
}

func (r *router) ReleaseOutbound(pairId string, events []*model.EventRecord) {
	r.releaseSstpEventClaims(pairId, events)
}

func (r *router) ReleaseJtis(pairId string, jtis []string) {
	r.releaseSstpClaims(pairId, jtis)
}

func (r *router) PausePair(stream *model.StreamStateRecord, reason string) {
	r.pauseSstpPair(stream, reason)
}

func (r *router) LoadSigningKey(streamID, issuer, alg string) (crypto.Signer, string) {
	return r.checkAndLoadKey(streamID, issuer, alg)
}

func (r *router) AcquireSecondPushSlot(pairId string) bool {
	return r.acquireSstpSecondPushSlot(pairId)
}

func (r *router) ReleaseSecondPushSlot(pairId string) {
	r.releaseSstpSecondPushSlot(pairId)
}

func (r *router) BackfillBatch() int {
	return r.backfillBatch
}

func (r *router) SignConcurrency() int {
	return r.signConcurrency
}

func (r *router) Ctx() context.Context {
	return r.ctx
}

// InboundVerifyConfig builds the JWKS-backed verify config for the pair's
// inbound direction from the source-of-truth StreamStateRecord (PRD #49 slice
// 2c AC 2). ExpectedIssuer / ExpectedAudiences come from rec.SstpInbound; the
// JWKS is resolved via StreamService.GetIssuerJwksForReceiver keyed on the
// inbound-side SID — the same resolver the SSTP-server handler already uses
// so the two ingest halves share one trust vocabulary. AllowedAlgs is left
// nil so goSetSstp.VerifySET applies its {RS256, ES256, EdDSA} default (Seam
// 2 r3 / ADR-0066).
func (r *router) InboundVerifyConfig(rec *model.StreamStateRecord) goSetSstp.VerifyConfig {
	cfg := goSetSstp.VerifyConfig{RequireSignature: true}
	if rec == nil || rec.SstpInbound == nil {
		return cfg
	}
	cfg.ExpectedIssuer = rec.SstpInbound.Iss
	cfg.ExpectedAudiences = rec.SstpInbound.Aud
	cfg.JWKS = r.streamService.GetIssuerJwksForReceiver(r.ctx, rec.SstpInbound.Id)
	return cfg
}

// HandleInboundEvent delegates to the router's HandleEvent ingest path (PRD
// #49 slice 2c AC 2). The dialer already holds a *goSet.SecurityEventToken
// straight out of goSetSstp.VerifiedSET.Token, so no second parse happens
// here — the surface just carries the already-verified token into the
// standard ingest pipeline with the rx-side SID so eventsIn counters carry
// stream_id=rxSid (Q46), matching the SSTP-server runner's ingest.
func (r *router) HandleInboundEvent(token *goSet.SecurityEventToken, raw string, sid string) error {
	return r.HandleEvent(token, raw, sid)
}

// HandleInboundEvents delegates to the router's batch ingest path, HandleEvents.
func (r *router) HandleInboundEvents(tokens []*goSet.SecurityEventToken, raws []string, sid string) []error {
	return r.HandleEvents(tokens, raws, sid)
}

// Compile-time assertion: the router satisfies SstpOutbound. This is the
// contract the relocated dialer in internal/server consumes.
var _ SstpOutbound = (*router)(nil)

// initSstpClientStreamLocked registers an SSTP pair's client side: it seeds
// the source-of-truth map + outbound buffer, then (if a dialer hook is wired)
// invokes RegisterPair so the relocated dialer starts the per-pair loop
// (PRD #49 slice 2a). Caller must hold r.mu.
//
// This is the sole seam through which UpdateStreamState hands a new
// SSTP-client pair to the dialer. A test router that does not wire
// SstpDialerHooks silently skips the RegisterPair call — the pair is still
// tracked and can be manipulated (refreshed, paused, drained) via
// SstpOutbound, but no dialer goroutine starts.
//
// Finding #9: r.sstpClientStreams[pairId] is the SINGLE source of truth for
// the pair's live config (endpoint, bearer, status). The dialer re-reads
// the map under r.mu each cycle via SstpOutbound.RefreshPair so a rotated
// bearer / changed endpoint / pause applied via UpdateStreamState is
// observed within one cycle.
func (r *router) initSstpClientStreamLocked(state *model.StreamStateRecord, jtis []string) {
	pairId := state.PairId
	r.sstpClientStreams[pairId] = *state
	buf := buffer.CreateEventPollBuffer(jtis, r.pollDefaultTimeoutSecs, r.pollMaxTimeoutSecs)
	r.sstpBuffers[pairId] = buf
	if r.sstpDialer != nil {
		r.sstpDialer.RegisterPair(pairId)
	}
}

// refreshSstpClientStream returns the current source-of-truth record for the
// pair from r.sstpClientStreams under r.mu. ok=false means the pair has been
// removed (RemoveStream / Finding #8) and the dialer's loop should exit. The
// returned value is a copy, safe to read without further locking (Finding #9).
func (r *router) refreshSstpClientStream(pairId string) (model.StreamStateRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.sstpClientStreams[pairId]
	return rec, ok
}

// drainSstpBuffer reads up to max JTIs currently resident in the buffer (the
// synchronous portion — events whose async channel-drain has completed) that
// are NOT already claimed in flight for the pair, and claims the survivors.
// EventPollBuffer.GetEvents only COPIES (it does not remove), so without the
// claim filter a SET already in flight in the primary long-poll cycle would
// be re-handed-out to a concurrent push-while-poll-held second push and
// re-sent (NEW Finding #2). Returns nil when the buffer is empty or every
// resident JTI is already claimed. Caller MUST later ack (via AckOutbound) or
// release (via ReleaseJtis / ReleaseOutbound) the returned JTIs.
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
	return r.claimSstpJtis(pairId, candidates, len(candidates))
}

// resolveSstpEventsByJti turns a slice of JTIs into the event records to
// flush, in the claimed order, skipping any that have since been deleted.
// One GetEventRecords read serves the whole batch (ADR 0036).
func (r *router) resolveSstpEventsByJti(jtis []string) []*model.EventRecord {
	if len(jtis) == 0 {
		return nil
	}
	byJti := make(map[string]*model.EventRecord, len(jtis))
	for _, rec := range r.eventService.GetEventRecords(r.ctx, jtis) {
		byJti[rec.Jti] = rec
	}
	events := make([]*model.EventRecord, 0, len(jtis))
	for _, jti := range jtis {
		if rec := byJti[jti]; rec != nil {
			events = append(events, rec)
		}
	}
	return events
}

// releaseUnresolvedSstpClaims releases the claim on any claimed JTI that did
// NOT resolve to an event record (deleted between claim and resolve), so a
// vanished event never holds a permanent claim that would block an unrelated
// re-add.
func (r *router) releaseUnresolvedSstpClaims(pairId string, claimed []string, resolved []*model.EventRecord) {
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

// releaseSstpEventClaims releases the in-flight claim on every JTI in events.
func (r *router) releaseSstpEventClaims(pairId string, events []*model.EventRecord) {
	if len(events) == 0 {
		return
	}
	jtis := make([]string, len(events))
	for i, ev := range events {
		jtis[i] = ev.Jti
	}
	r.releaseSstpClaims(pairId, jtis)
}

// claimSstpJtis filters candidate JTIs to those NOT already claimed in-flight
// for the pair, marks the survivors as claimed, and returns them. The primary
// long-poll cycle and a concurrent push-while-poll-held second push both call
// this before delivering, so a SET already in flight in one is never re-sent
// by the other (NEW Finding #2). Claims are cleared by AckOutbound (on
// peer-ack) or ReleaseJtis / ReleaseOutbound (on delivery failure). The
// events collection / pending list remains the durable source of truth, so
// this in-memory claim is purely a same-node dedup and is safe across
// takeover. It claims at most max of the candidates.
func (r *router) claimSstpJtis(pairId string, candidates []string, max int) []string {
	if len(candidates) == 0 || max <= 0 {
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
		if len(out) >= max {
			break
		}
	}
	return out
}

// releaseSstpClaims drops the in-flight claim on the given JTIs WITHOUT
// removing them from the buffer, so a failed-delivery SET is re-drained
// (and retried) on a later cycle. Called from the delivery-failure paths.
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

// handleSstpAcks acks the peer-acknowledged JTIs that we actually sent this
// cycle: it removes each acked JTI from the pair's outbound buffer
// (eventBuf.AckEvents — NEW Finding #1: without this the buffer's copy-only
// GetEvents re-drains and re-sends an already-acked SET forever), acks it in
// the provider, clears its in-flight claim, and increments the outbound
// eventsOut counter (tfr=SSTP, stream_id=txSid) per acked event (Q46). A peer
// ack is honored only for JTIs in the sent set — a stray ack for something we
// did not send is ignored, so an un-sent SET is never removed.
//
// PRD #49 slice 2c AC 3 — literal SSTP ack semantics. An omitted or empty
// ack list confirms NOTHING: every sent SET has its in-flight claim released
// so it is re-drained and retried on a later cycle. The historical
// "success-without-detail ⇒ ack-all-sent" fallback is REMOVED with no
// compatibility knob; delivery loss is no longer masked by an empty response
// ack (US 5). Any sent-but-NOT-acked JTI likewise has its claim released so
// it is re-drained on a later cycle. Returns the number of acked (and
// counted) events.
func (r *router) handleSstpAcks(stream *model.StreamStateRecord, eventBuf *buffer.EventPollBuffer, acked []string, sent []*model.EventRecord, fencingToken int64) int {
	pairId := stream.PairId
	if len(sent) == 0 {
		return 0
	}

	sentByJti := make(map[string]*model.EventRecord, len(sent))
	for _, ev := range sent {
		sentByJti[ev.Jti] = ev
	}

	// AC 3: literal ack semantics — no ack-all-sent fallback. An empty ack
	// list falls through to the loop below and acks zero JTIs; every sent
	// SET is then released for a later retry via the tail unacked-release
	// block. This is the enforcement site for the "empty ack confirms
	// nothing" invariant (US 5).
	ackSet := acked

	ackedJtis := make([]string, 0, len(ackSet))
	count := 0
	for _, jti := range ackSet {
		if sentByJti[jti] == nil {
			continue // ack for a JTI we did not send this cycle — ignore.
		}
		ackedJtis = append(ackedJtis, jti)
		count++
	}

	// Finding #1: ack the confirmed-delivered SETs in the provider, remove
	// them from the outbound buffer so GetEvents (copy-only) never re-hands
	// them out, and clear their in-flight claim. The provider ack is queued on
	// the pair's coalescing acker (#336) and the rest follows once it is
	// written, so the claim holds the SET until its ack is durable: a
	// concurrent cycle cannot re-send it meanwhile. A failed or fenced ack
	// releases the claim and the SET, still pending, is retried.
	if len(ackedJtis) > 0 {
		events := make(map[string]sstpAckedSet, len(ackedJtis))
		for _, jti := range ackedJtis {
			events[jti] = sstpAckedSet{ev: sentByJti[jti], buf: eventBuf}
		}
		ack := r.sstpAckerFor(stream, fencingToken)
		ack.addPending(events)
		_ = ack.complete(ackedJtis, nil)
	}

	// Release the in-flight claim on any sent-but-unacked SET so it is
	// re-drained and retried on a later cycle (it stays in the buffer /
	// pending list).
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

// pauseSstpPair pauses the pair — both halves, Status and InboundStatus — via
// the single transition point. The pair's two logical streams share one HTTP
// exchange, so pausing it pauses both (#303).
func (r *router) pauseSstpPair(stream *model.StreamStateRecord, reason string) {
	r.updateStream(stream, model.StreamStatePause, reason)
	// Finding #9: write the pause back into the source-of-truth map so the
	// dialer's next-cycle RefreshPair observes it (and the cycle exits)
	// rather than reverting to the stale enabled status held in the map.
	r.mu.Lock()
	if rec, ok := r.sstpClientStreams[stream.PairId]; ok {
		rec.SetStatus(stream.Status, stream.ErrorMsg)
		r.sstpClientStreams[stream.PairId] = rec
	}
	r.mu.Unlock()
}

// maxSstpPushInFlight caps the derived I2SIG_SSTP_PUSH_INFLIGHT default. The
// batches share the pair's one transport and its in-flight set, so past a few
// the link, not the round trip, is the limit.
const maxSstpPushInFlight = 4

// sstpPushInFlight resolves I2SIG_SSTP_PUSH_INFLIGHT: K, how many
// push-while-poll-held batches one SSTP-client pair keeps in flight (#339,
// ADR 0044). The default is how many full claims (backfillBatch each) fit in
// the in-flight set, clamped to [1, maxSstpPushInFlight] — 2 with the
// defaults (256 / 100). 1 reproduces the single second-push slot (Q7.2).
func sstpPushInFlight(inFlightMax, backfillBatch int) int {
	if val := os.Getenv("I2SIG_SSTP_PUSH_INFLIGHT"); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			return i
		}
		eventLogger.Warn("Ignoring invalid I2SIG_SSTP_PUSH_INFLIGHT (want a positive integer)", "value", val)
	}
	k := 1
	if backfillBatch > 0 {
		k = inFlightMax / backfillBatch
	}
	if k < 1 {
		k = 1
	}
	if k > maxSstpPushInFlight {
		k = maxSstpPushInFlight
	}
	return k
}

// acquireSstpSecondPushSlot reserves one of the pair's K push-while-poll-held
// slots (#339; Q7.2 had one), returning false when all K are held.
//
// The counters live under sstpSlotMu rather than r.mu: the dialer probes a
// slot on every wake (a burst of subject-filter wakes is thousands per
// second), and taking the router's write lock for each probe stalled every
// ingest, match and drain sharing r.mu. sstpPushInFlightMax is set once at
// construction, so reading it here needs no lock.
func (r *router) acquireSstpSecondPushSlot(pairId string) bool {
	r.sstpSlotMu.Lock()
	defer r.sstpSlotMu.Unlock()
	k := r.sstpPushInFlightMax
	if k < 1 {
		k = 1
	}
	if r.sstpSecondPushInFlight[pairId] >= k {
		return false
	}
	r.sstpSecondPushInFlight[pairId]++
	return true
}

// releaseSstpSecondPushSlot releases one push-while-poll-held slot.
func (r *router) releaseSstpSecondPushSlot(pairId string) {
	r.sstpSlotMu.Lock()
	defer r.sstpSlotMu.Unlock()
	if n := r.sstpSecondPushInFlight[pairId]; n > 1 {
		r.sstpSecondPushInFlight[pairId] = n - 1
		return
	}
	delete(r.sstpSecondPushInFlight, pairId)
}

// sstpPairAcker is one SSTP-client pair's coalescing acker (#336), bound to
// the fencing token of the dialer tenure that created it.
type sstpPairAcker struct {
	*acker
	token int64

	mu     sync.Mutex
	events map[string]sstpAckedSet
}

// sstpAckedSet is a peer-acked SET waiting for its coalesced ack write: its
// sent record (for the eventsOut counter) and the outbound buffer it leaves.
type sstpAckedSet struct {
	ev  *model.EventRecord
	buf *buffer.EventPollBuffer
}

// addPending records the sent records of JTIs about to be queued, for the
// eventsOut counter once their ack is written.
func (p *sstpPairAcker) addPending(events map[string]sstpAckedSet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for jti, ev := range events {
		p.events[jti] = ev
	}
}

func (p *sstpPairAcker) takePending(jtis []string) []sstpAckedSet {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sstpAckedSet, 0, len(jtis))
	for _, jti := range jtis {
		if set, ok := p.events[jti]; ok {
			out = append(out, set)
		}
		delete(p.events, jti)
	}
	return out
}

// sstpAcker returns the pair's acker, or nil.
func (r *router) sstpAcker(pairId string) *acker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p := r.sstpAckers[pairId]; p != nil {
		return p.acker
	}
	return nil
}

// sstpAckerFor returns the pair's acker for fencingToken, creating it on
// first use. An acker left from an earlier tenure is closed, which writes its
// queued acks under their own token (refused, and so retried, if that tenure
// has ended).
func (r *router) sstpAckerFor(stream *model.StreamStateRecord, fencingToken int64) *sstpPairAcker {
	pairId := stream.PairId
	sid := stream.StreamConfiguration.Id
	r.mu.Lock()
	if r.sstpAckers == nil {
		r.sstpAckers = map[string]*sstpPairAcker{}
	}
	cur := r.sstpAckers[pairId]
	if cur != nil && cur.token == fencingToken {
		r.mu.Unlock()
		return cur
	}
	p := &sstpPairAcker{token: fencingToken, events: map[string]sstpAckedSet{}}
	p.acker = newAcker(r.ctx, ackerConfig{
		sid:       sid,
		transport: "sstp",
		window:    r.ackCoalesceWindow,
		max:       r.inFlightMax(),
		apply: func(ctx context.Context, jtis []string) error {
			err := r.eventService.AckEvents(ctx, jtis, sid, fencingToken)
			if err != nil && !errors.Is(err, services.ErrStaleFencingToken) {
				// Not acked: the SETs stay pending and are redelivered, so WARN
				// (the DAO logs the store failure itself).
				eventLogger.Warn("SSTP: Error acking outbound events", "sid", sid, "count", len(jtis), "error", err)
			}
			return err
		},
		onApplied: func(jtis []string, err error) {
			sets := p.takePending(jtis)
			if err == nil {
				byBuf := map[*buffer.EventPollBuffer][]string{}
				for _, set := range sets {
					if set.ev != nil {
						r.IncrementCounter(stream, &set.ev.Event, false)
						if set.buf != nil {
							byBuf[set.buf] = append(byBuf[set.buf], set.ev.Jti)
						}
					}
				}
				for buf, bufJtis := range byBuf {
					buf.AckEvents(bufJtis)
				}
			}
			r.releaseSstpClaims(pairId, jtis)
		},
	})
	r.sstpAckers[pairId] = p
	r.mu.Unlock()
	if cur != nil {
		_ = cur.close()
	}
	return p
}
