package eventRouter

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
)

// Poll-transmitter and SSTP-acceptor streams are leased (#365): the lease
// owner holds the stream's one queue and serves every request for it, its own
// and, through PeerTransport.Claim, those that reach another node.

// defaultClaimInflight is the I2SIG_CLUSTER_CLAIM_INFLIGHT default.
const defaultClaimInflight = 256

// claimWaitSlack is taken off the receiver's resolved wait for the WaitMs a
// non-owner sends, so the owner answers before the receiver's own deadline.
const claimWaitSlack = time.Second

var (
	peerClaimsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "peer_claims_total",
		Help:      "Claims this node answered for a peer as a poll-transmitter or SSTP-acceptor lease owner, by mode and result (served, empty, not_owner) (#365).",
	}, []string{"mode", "result"})
	peerClaimBudgetExhausted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "peer_claim_budget_exhausted_total",
		Help:      "Waiting Claim calls sent with returnImmediately because I2SIG_CLUSTER_CLAIM_INFLIGHT was used up for the owner (#365).",
	})
)

// ClaimCollectors returns the claim path's Prometheus collectors.
func ClaimCollectors() []prometheus.Collector {
	return []prometheus.Collector{peerClaimsTotal, peerClaimBudgetExhausted}
}

// claimInflightMax resolves I2SIG_CLUSTER_CLAIM_INFLIGHT. An unset or invalid
// value gives the default.
func claimInflightMax() int {
	if val := os.Getenv("I2SIG_CLUSTER_CLAIM_INFLIGHT"); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			return i
		}
		eventLogger.Warn("Ignoring invalid I2SIG_CLUSTER_CLAIM_INFLIGHT (want a positive integer)", "value", val, "default", defaultClaimInflight)
	}
	return defaultClaimInflight
}

// splitStreamResource returns a lease resource's kind and stream id.
func splitStreamResource(resource string) (cluster.LeaseKind, string) {
	kind, id, _ := cluster.ParseResource(resource)
	return kind, id
}

// isClaimServedResource reports whether resource is one of the two kinds a
// router with ServesClaims false never acquires.
func isClaimServedResource(resource string) bool {
	kind, _ := splitStreamResource(resource)
	return kind == cluster.PollTransmitter || kind == cluster.SstpServer
}

// claimResource returns the lease resource for a claim mode.
func claimResource(mode, sid string) string {
	if mode == peer.ModeSstpServer {
		return cluster.SstpServerResource(sid)
	}
	return cluster.PollTransmitterResource(sid)
}

// streamLease is one held poll-transmitter or sstp-server lease.
type streamLease struct {
	cancel context.CancelFunc
	// done closes when the renewal loop has returned.
	done chan struct{}
}

// adoptStreamLease starts the renewal loop for a lease just acquired. It is a
// no-op when the loop already runs.
func (r *router) adoptStreamLease(resource string) {
	r.streamLeasesMu.Lock()
	if r.streamLeases == nil {
		r.streamLeases = make(map[string]*streamLease)
	}
	if _, ok := r.streamLeases[resource]; ok {
		r.streamLeasesMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	sl := &streamLease{cancel: cancel, done: make(chan struct{})}
	r.streamLeases[resource] = sl
	r.streamLeasesMu.Unlock()

	hb := leaseHeartbeat{
		Coordinator:   r.coordinator,
		Manager:       r.leaseRenewer(),
		Resource:      resource,
		NodeId:        r.nodeId,
		Interval:      leaseRenewInterval,
		LeaseDuration: leaseTTL,
		OnLost:        func() { r.loseStreamLease(resource, sl) },
	}
	go func() {
		defer close(sl.done)
		hb.run(ctx)
	}()
}

// loseStreamLease is the renewal loop's answer to a refused renewal: the node
// drops the queue, ends its waiting claims with an empty answer (closing the
// buffer wakes them), and removes the stream's gauge series.
func (r *router) loseStreamLease(resource string, sl *streamLease) {
	r.streamLeasesMu.Lock()
	if cur, ok := r.streamLeases[resource]; ok && cur == sl {
		delete(r.streamLeases, resource)
	}
	r.streamLeasesMu.Unlock()
	sl.cancel()
	eventLogger.Warn("ROUTER: stream lease lost; dropping the stream's queue", "resource", resource)
	r.leases.forget(resource)
	r.leaseOwners.forget(resource)
	r.dropOwnerQueue(resource)
}

// dropOwnerQueue removes the buffer and queue held for resource's stream.
func (r *router) dropOwnerQueue(resource string) {
	kind, id := splitStreamResource(resource)
	var buf *buffer.EventPollBuffer
	r.mu.Lock()
	switch kind {
	case cluster.PollTransmitter:
		buf = r.pollBuffers[id]
		delete(r.pollBuffers, id)
	case cluster.SstpServer:
		buf = r.sstpServerBuffers[id]
		delete(r.sstpServerBuffers, id)
	}
	r.mu.Unlock()
	if buf != nil {
		buf.Close()
	}
	r.dropQueue(id)
	pollClaimedGauge.DeleteLabelValues(id)
}

// releaseStreamLease stops the renewal loop for resource and gives the lease
// back, when this node holds it (stream removed, or shutdown).
func (r *router) releaseStreamLease(resource string) {
	r.streamLeasesMu.Lock()
	sl, ok := r.streamLeases[resource]
	delete(r.streamLeases, resource)
	r.streamLeasesMu.Unlock()
	if !ok {
		return
	}
	sl.cancel()
	// A renewal in flight would re-take the lease after the release below.
	<-sl.done
	r.leaseOwners.forget(resource)
	_, id := splitStreamResource(resource)
	r.releaseLease(resource, id)
}

// releaseAllStreamLeases gives back every poll-transmitter and sstp-server
// lease this node holds.
func (r *router) releaseAllStreamLeases() {
	r.streamLeasesMu.Lock()
	resources := make([]string, 0, len(r.streamLeases))
	for resource := range r.streamLeases {
		resources = append(resources, resource)
	}
	r.streamLeasesMu.Unlock()
	for _, resource := range resources {
		r.releaseStreamLease(resource)
	}
}

// ensureOwnerQueue makes sure this node, as resource's owner, holds the
// stream's buffer, building it with one pending read when it has none. It
// returns false when the stream is not known here. Never called with r.mu
// held.
func (r *router) ensureOwnerQueue(resource string) bool {
	known, _ := r.ensureOwnerQueueSeeded(resource)
	return known
}

// ensureOwnerQueueSeeded is ensureOwnerQueue that also reports whether this
// call built the buffer from a pending read. A fan-out whose rows were written
// before that read must not queue them a second time.
func (r *router) ensureOwnerQueueSeeded(resource string) (known, seeded bool) {
	kind, id := splitStreamResource(resource)
	var bufs map[string]*buffer.EventPollBuffer
	r.mu.RLock()
	switch kind {
	case cluster.PollTransmitter:
		if _, known := r.pollStreams[id]; !known {
			r.mu.RUnlock()
			return false, false
		}
		bufs = r.pollBuffers
	case cluster.SstpServer:
		bufs = r.sstpServerBuffers
	default:
		r.mu.RUnlock()
		return false, false
	}
	_, held := bufs[id]
	r.mu.RUnlock()
	if held {
		return true, false
	}

	jtis, _ := r.pendingJtis(r.ctx, id, model.PollParameters{
		MaxEvents:         0,
		ReturnImmediately: true,
		TimeoutSecs:       10,
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	if kind == cluster.PollTransmitter {
		if _, known := r.pollStreams[id]; !known {
			return false, false
		}
	}
	if _, held := bufs[id]; !held {
		bufs[id] = buffer.CreateEventPollBuffer(jtis, r.pollDefaultTimeoutSecs, r.pollMaxTimeoutSecs)
		return true, true
	}
	return true, false
}

// heldBuffer returns the buffer this node holds for a claim mode's stream.
func (r *router) heldBuffer(mode, sid string) (*buffer.EventPollBuffer, *model.StreamStateRecord) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var buf *buffer.EventPollBuffer
	var rec model.StreamStateRecord
	var known bool
	if mode == peer.ModeSstpServer {
		buf = r.sstpServerBuffers[sid]
		rec, known = r.sstpServerStreams[sid]
	} else {
		buf = r.pollBuffers[sid]
		rec, known = r.pollStreams[sid]
	}
	if !known {
		return buf, nil
	}
	return buf, &rec
}

// HoldsQueue reports whether this node holds a delivery queue or a poll or
// SSTP-acceptor buffer for sid. It resolves no owner and takes no lease. Only
// the lease owner of a claim-served stream should hold one (#365).
func (r *router) HoldsQueue(sid string) bool {
	if _, ok := r.queues.Load(sid); ok {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pollBuffers[sid] != nil || r.sstpServerBuffers[sid] != nil
}

// pollBufferFor resolves sid's poll-transmitter owner and returns the buffer
// this node holds for it, or nil when another node (or no node) owns it.
func (r *router) pollBufferFor(sid string) *buffer.EventPollBuffer {
	if _, self := r.resolveOwner(cluster.PollTransmitterResource(sid)); !self {
		return nil
	}
	buf, _ := r.heldBuffer(peer.ModePoll, sid)
	return buf
}

// sstpServerBufferFor resolves the acceptor owner of the pair whose tx stream
// is txSid and returns the outbound buffer this node holds for it, or nil when
// another node (or no node) owns it.
func (r *router) sstpServerBufferFor(txSid string) *buffer.EventPollBuffer {
	if _, self := r.resolveOwner(cluster.SstpServerResource(txSid)); !self {
		return nil
	}
	buf, _ := r.heldBuffer(peer.ModeSstpServer, txSid)
	return buf
}

// claimLocal runs req on this node's own queue: it applies the
// acknowledgements and cleared setErrs in one write, waits at most WaitMs for
// a first reference, and claims up to MaxEvents (never more than
// backfillBatch). forPeer is set when the answer goes to another node, which
// cannot see the queue: the owner then applies the subject filter and stamps
// the hand-out time itself. The claim token is returned for a local caller
// that must release the claim. NotOwner is set when this node holds no buffer
// for the stream.
func (r *router) claimLocal(ctx context.Context, req peer.ClaimRequest, forPeer bool) (peer.ClaimResponse, string) {
	buf, state := r.heldBuffer(req.Mode, req.Sid)
	if buf == nil {
		return peer.ClaimResponse{NotOwner: true}, ""
	}
	sid := req.Sid
	q := r.queueFor(sid)
	if len(req.AckJtis) > 0 || len(req.SetErrJtis) > 0 {
		inbound, n, err := q.AckWire(ctx, req.AckJtis, req.SetErrJtis)
		if err != nil {
			eventLogger.Warn("ROUTER: Error acknowledging claimed events", "sid", sid, "mode", req.Mode, "count", len(req.AckJtis)+len(req.SetErrJtis), "error", err)
		}
		// A wire JTI equals its inbound JTI on a Forward stream and for a
		// reference the queue does not hold.
		drop := make([]string, 0, len(req.AckJtis)+len(req.SetErrJtis)+len(inbound))
		drop = append(drop, req.AckJtis...)
		drop = append(drop, req.SetErrJtis...)
		drop = append(drop, inbound...)
		q.ackBuffered(buf, drop)
		if req.Mode == peer.ModePoll {
			for i := int64(0); i < n; i++ {
				r.IncrementCounter(state, nil, false)
			}
		}
	}
	if req.MaxEvents <= 0 {
		return peer.ClaimResponse{}, ""
	}
	maxEvents := req.MaxEvents
	if r.backfillBatch > 0 && maxEvents > int32(r.backfillBatch) {
		maxEvents = int32(r.backfillBatch)
	}

	// Opportunistically prefetch pending JTIs if the buffer is empty.
	if buf.Cnt() == 0 {
		jtis, _ := r.pendingJtis(r.ctx, sid, model.PollParameters{
			MaxEvents:         int32(r.backfillBatch),
			ReturnImmediately: true,
		})
		if len(jtis) > 0 {
			eventLogger.Debug("ROUTER: Prefetched events", "sid", sid, "mode", req.Mode, "count", len(jtis))
			buf.AddEvents(jtis)
		}
	}

	var wait time.Duration
	if !req.ReturnImmediately && req.WaitMs > 0 {
		wait = time.Duration(req.WaitMs) * time.Millisecond
	}
	// The batch is claimed (#337): an overlapping request on this stream,
	// local or through Claim, skips these JTIs and gets the next disjoint
	// slice, and an unacked one is served again once the claim expires.
	token, jtis, more := q.ClaimEvents(ctx, buf, maxEvents, wait, r.pollClaimTTL)
	if req.Mode == peer.ModePoll {
		pollClaimedGauge.WithLabelValues(sid).Set(float64(q.ClaimedCnt()))
	}
	if len(jtis) == 0 {
		return peer.ClaimResponse{MoreAvailable: more}, token
	}

	if forPeer && req.Mode == peer.ModePoll && r.subjectFilterService != nil && state != nil {
		// SSF §8.1.3 delivery-time subject filtering: the owner discards a
		// filtered-out SET (acked, never returned), as the local poll does.
		keep := make([]string, 0, len(jtis))
		var discards []string
		for _, rec := range r.eventService.GetEventRecords(r.ctx, jtis) {
			if !r.subjectFilterService.Allows(r.ctx, state, rec) {
				discards = append(discards, rec.Jti)
			}
		}
		if len(discards) > 0 {
			drop := make(map[string]bool, len(discards))
			for _, jti := range discards {
				drop[jti] = true
			}
			for _, jti := range jtis {
				if !drop[jti] {
					keep = append(keep, jti)
				}
			}
			r.discardPolledEvents(sid, discards, buf)
			jtis = keep
		}
	}

	refs := make([]interfaces.PendingRef, 0, len(jtis))
	ackJtis := make([]string, 0, len(jtis))
	for i, ackJti := range q.AckJtisOf(jtis, state) {
		if ackJti == "" {
			// Its stored row could not be read (#363, S2): nothing is derived;
			// the SET is not handed out and is served again once its claim
			// expires.
			continue
		}
		ackJtis = append(ackJtis, ackJti)
		refs = append(refs, interfaces.PendingRef{Jti: jtis[i], AckJti: ackJti})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Jti < refs[j].Jti })
	if forPeer && len(ackJtis) > 0 {
		q.MarkHandedOut(ackJtis, time.Now())
	}
	return peer.ClaimResponse{Refs: refs, MoreAvailable: more}, token
}

// claimInflightCounter returns the in-flight count of waiting Claim calls to
// owner.
func (r *router) claimInflightCounter(owner string) *atomic.Int64 {
	if v, ok := r.claimInflight.Load(owner); ok {
		return v.(*atomic.Int64)
	}
	v, _ := r.claimInflight.LoadOrStore(owner, new(atomic.Int64))
	return v.(*atomic.Int64)
}

// claimRemote sends req to owner under the I2SIG_CLUSTER_CLAIM_INFLIGHT
// budget. A call with WaitMs 0 is never counted. With the budget for owner
// used up the request goes with ReturnImmediately, and an empty answer is
// held here for the receiver's resolved wait, so a receiver cannot spin.
func (r *router) claimRemote(ctx context.Context, owner string, req peer.ClaimRequest) (peer.ClaimResponse, error) {
	req.ClientId = r.nodeId
	if req.ReturnImmediately || req.WaitMs <= 0 || req.MaxEvents <= 0 {
		return r.peers.Claim(ctx, owner, req)
	}
	limit := r.claimInflightMax
	if limit <= 0 {
		limit = defaultClaimInflight
	}
	ctr := r.claimInflightCounter(owner)
	if ctr.Add(1) > int64(limit) {
		ctr.Add(-1)
		peerClaimBudgetExhausted.Inc()
		hold := time.Duration(req.WaitMs)*time.Millisecond + claimWaitSlack
		req.ReturnImmediately = true
		req.WaitMs = 0
		resp, err := r.peers.Claim(ctx, owner, req)
		if err == nil && !resp.NotOwner && len(resp.Refs) == 0 {
			timer := time.NewTimer(hold)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
			}
		}
		return resp, err
	}
	defer ctr.Add(-1)
	return r.peers.Claim(ctx, owner, req)
}

// claimFor serves req for the stream resource names: on this node when it
// owns the stream, otherwise through one Claim to owner. NotOwner, or an
// error from the call, forgets the cached owner and resolves once more; a
// second NotOwner or error, or an empty owner, ends with an empty answer and
// the acknowledgements unapplied. local reports whether this node's own queue
// answered, and token is then its claim token.
func (r *router) claimFor(ctx context.Context, resource, owner string, self bool, req peer.ClaimRequest) (resp peer.ClaimResponse, token string, local bool) {
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			if ctx.Err() != nil {
				break
			}
			r.leaseOwners.forget(resource)
			owner, self = r.resolveOwner(resource)
		}
		if self {
			resp, token = r.claimLocal(ctx, req, false)
			if !resp.NotOwner {
				return resp, token, true
			}
			continue
		}
		if owner == "" {
			break
		}
		answer, err := r.claimRemote(ctx, owner, req)
		if err == nil && !answer.NotOwner {
			return answer, "", false
		}
		eventLogger.Debug("ROUTER: Claim not served by owner", "sid", req.Sid, "mode", req.Mode, "owner", owner, "notOwner", answer.NotOwner, "error", err)
	}
	return peer.ClaimResponse{}, "", false
}

// claimWaitMs is the WaitMs a request sends: the receiver's resolved
// long-poll time less one second, never below 0; 0 with returnImmediately.
func (r *router) claimWaitMs(timeoutSecs int, returnImmediately bool) int64 {
	if returnImmediately {
		return 0
	}
	ms := r.resolvedWait(timeoutSecs).Milliseconds() - claimWaitSlack.Milliseconds()
	if ms < 0 {
		return 0
	}
	return ms
}

// resolvedWait mirrors the poll buffer's resolveTimeoutSecs with the router's
// resolved I2SIG_POLL_DEFAULT_TIMEOUT and I2SIG_POLL_MAX_TIMEOUT.
func (r *router) resolvedWait(timeoutSecs int) time.Duration {
	secs := timeoutSecs
	if secs <= 0 {
		secs = r.pollDefaultTimeoutSecs
	} else if r.pollMaxTimeoutSecs > 0 && secs > r.pollMaxTimeoutSecs {
		secs = r.pollMaxTimeoutSecs
	}
	return time.Duration(secs) * time.Second
}

// claimMaxEvents is the MaxEvents a request sends: the receiver's maxEvents
// when greater than zero, otherwise backfillBatch.
func (r *router) claimMaxEvents(maxEvents int32) int32 {
	if maxEvents > 0 {
		return maxEvents
	}
	return int32(r.backfillBatch)
}

// signClaimedRefs renders the references a peer owner claimed for this node
// to their on-wire SETs: one read for the bodies, each re-signed with its
// AckJti (forwarded verbatim in forward mode). The non-owner stores no
// outbound copy and holds no queue. A reference whose record is gone is
// skipped; it lapses with its claim. Any signing failure returns no sets.
func (r *router) signClaimedRefs(state *model.StreamStateRecord, refs []interfaces.PendingRef, forward bool, key crypto.Signer, kid string) (map[string]string, error) {
	jtis := make([]string, len(refs))
	ackOf := make(map[string]string, len(refs))
	for i, ref := range refs {
		jtis[i] = ref.Jti
		ack := ref.AckJti
		if ack == "" {
			ack = ref.Jti
		}
		ackOf[ref.Jti] = ack
	}
	byJti := make(map[string]*model.EventRecord, len(jtis))
	for _, rec := range r.eventService.GetEventRecords(r.ctx, jtis) {
		byJti[rec.Jti] = rec
	}
	sets := make(map[string]string, len(refs))
	work := make([]*model.EventRecord, 0, len(refs))
	for _, jti := range jtis {
		rec := byJti[jti]
		if rec == nil {
			continue
		}
		if forward {
			sets[ackOf[jti]] = rec.Original
			continue
		}
		work = append(work, rec)
	}
	if len(work) == 0 {
		return sets, nil
	}
	cfg := state.StreamConfiguration
	method := goSet.SigningMethodOrRS256(cfg.SigningAlg)
	signed := SignSets(work, r.signConcurrency, func(rec *model.EventRecord) (string, error) {
		token := rec.Event
		token.ID = ackOf[rec.Jti]
		token.Issuer = cfg.Iss
		token.Audience = cfg.Aud
		token.IssuedAt = jwt.NewNumericDate(time.Now())
		token.Kid = kid
		return token.JWS(method, key)
	})
	for i, rec := range work {
		if signed[i].Err != nil {
			return nil, fmt.Errorf("signing JTI %s: %w", rec.Jti, signed[i].Err)
		}
		sets[ackOf[rec.Jti]] = signed[i].JWS
	}
	return sets, nil
}

// refJtis returns the inbound JTIs of refs.
func refJtis(refs []interfaces.PendingRef) []string {
	out := make([]string, len(refs))
	for i, ref := range refs {
		out[i] = ref.Jti
	}
	return out
}
