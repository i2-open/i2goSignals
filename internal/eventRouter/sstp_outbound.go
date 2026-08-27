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

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
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

	// PauseOutbound pauses ONLY the outbound (client) direction of the pair
	// by setting the record's Status to paused via the single transition
	// point. The inbound side (InboundStatus) is owned by the SSTP-server
	// runner and is untouched here (Q12.3). The pause is written back into
	// the source-of-truth map so the runner's next-cycle RefreshPair
	// observes it (Finding #9).
	PauseOutbound(stream *model.StreamStateRecord, reason string)

	// LoadSigningKey returns the issuer's private signing key + kid,
	// consulting the router's issuer-key cache (or loading it once and
	// caching). RouteModeForward pairs skip this call — the dialer forwards
	// Event.Original verbatim.
	LoadSigningKey(streamID, issuer, alg string) (crypto.Signer, string)

	// AcquireSecondPushSlot reserves the single in-flight push-while-poll-
	// held slot for pairId (Q7.2 concurrency bound), returning false when a
	// second push is already in flight for the pair. A coalesced call
	// returns without opening a third parallel request.
	AcquireSecondPushSlot(pairId string) bool

	// ReleaseSecondPushSlot releases the second-push slot acquired by
	// AcquireSecondPushSlot. Safe to call from a defer.
	ReleaseSecondPushSlot(pairId string)

	// BackfillBatch is the router-configured claim/drain batch size,
	// I2SIG_PUSH_BACKFILL_BATCH (with the legacy alias). The relocated
	// dialer uses it as the max on ClaimOutbound so recovery-after-takeover
	// and the primary drain use the same batch size as push and poll.
	BackfillBatch() int

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
// pauseSstpOutbound, refreshSstpClientStream, acquireSstpSecondPushSlot,
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
	pending, _ := r.eventService.GetEventIds(context.Background(), pair.StreamConfiguration.Id, model.PollParameters{
		MaxEvents:         int32(max),
		ReturnImmediately: true,
	})
	return r.claimSstpJtis(pairId, pending)
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

func (r *router) PauseOutbound(stream *model.StreamStateRecord, reason string) {
	r.pauseSstpOutbound(stream, reason)
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
	return r.claimSstpJtis(pairId, candidates)
}

// resolveSstpEventsByJti turns a slice of JTIs into the event records to
// flush, skipping any that have since been deleted.
func (r *router) resolveSstpEventsByJti(jtis []string) []*model.EventRecord {
	if len(jtis) == 0 {
		return nil
	}
	events := make([]*model.EventRecord, 0, len(jtis))
	for _, jti := range jtis {
		rec := r.eventService.GetEventRecord(r.ctx, jti)
		if rec == nil {
			continue
		}
		events = append(events, rec)
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
// takeover.
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
	sid := stream.StreamConfiguration.Id
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
		ev := sentByJti[jti]
		if ev == nil {
			continue // ack for a JTI we did not send this cycle — ignore.
		}
		_ = r.eventService.AckEvent(r.ctx, jti, sid, fencingToken)
		r.IncrementCounter(stream, &ev.Event, false)
		ackedJtis = append(ackedJtis, jti)
		count++
	}

	// Finding #1: remove the confirmed-delivered SETs from the outbound
	// buffer so GetEvents (copy-only) never re-hands them out, and clear
	// their in-flight claim.
	if len(ackedJtis) > 0 {
		if eventBuf != nil {
			eventBuf.AckEvents(ackedJtis)
		}
		r.releaseSstpClaims(pairId, ackedJtis)
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

// pauseSstpOutbound pauses ONLY the outbound (client) direction of the pair
// by setting the record's Status to paused via the single transition point.
// The inbound side (InboundStatus) is owned by the SSTP-server runner and is
// untouched here (Q12.3).
func (r *router) pauseSstpOutbound(stream *model.StreamStateRecord, reason string) {
	r.updateStream(stream, model.StreamStatePause, reason)
	// Finding #9: write the pause back into the source-of-truth map so the
	// dialer's next-cycle RefreshPair observes it (and the cycle exits)
	// rather than reverting to the stale enabled status held in the map.
	r.mu.Lock()
	if rec, ok := r.sstpClientStreams[stream.PairId]; ok {
		rec.Status = stream.Status
		rec.ErrorMsg = stream.ErrorMsg
		r.sstpClientStreams[stream.PairId] = rec
	}
	r.mu.Unlock()
}

// acquireSstpSecondPushSlot reserves the single in-flight push-while-poll-
// held slot for a pair, returning false when one is already held (Q7.2
// concurrency bound).
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
