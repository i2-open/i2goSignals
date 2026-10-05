package eventRouter

import (
	"context"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

// The router is the receiving side of the PeerTransport (#358).
var _ peer.Handler = (*router)(nil)

// HandleWake acts on a wake from a peer. A filter-change wake invalidates the
// stream's subject-filter match-result cache (issue #94); every other wake
// wakes the local buffer for its mode. A poll or sstp-server wake goes to
// the lease owner only and carries the batch's references (#365), which the
// owner holds in its queue and buffer; a wake whose AckJtis, or present
// EnqueuedAt, list is not the length of Jtis carries no usable references and
// is a reload (#363). The push and sstp-client lists are still ignored, so
// those wakes are a reload. Waking a stream with no
// resident buffer is a silent no-op, so a duplicate, stale or lost wake is
// harmless: the owner finds the rows on its next pending read.
func (r *router) HandleWake(msg peer.WakeMessage) {
	switch msg.Mode {
	case peer.ModePoll, peer.ModeSstpServer:
		if msg.Mode == peer.ModePoll && msg.Reason == ReasonFilterChange {
			if r.subjectFilterService != nil {
				r.subjectFilterService.InvalidateCache(msg.Sid)
			}
			return
		}
		r.acceptWakeRefs(msg)
	}
	switch msg.Mode {
	case peer.ModePoll:
		if msg.Reason == ReasonFilterChange {
			return
		}
		r.WakeTransmitter(msg.Sid, msg.Mode)
	case peer.ModePush:
		if msg.Reason == ReasonFilterChange {
			if r.subjectFilterService != nil {
				r.subjectFilterService.InvalidateCache(msg.Sid)
			}
			return
		}
		r.WakeTransmitter(msg.Sid, msg.Mode)
	case peer.ModeSstpClient:
		r.WakeSstpClient(msg.Sid)
	case peer.ModeSstpServer:
		r.WakeSstpServer(msg.Sid)
	default:
		eventLogger.Warn("ROUTER: ignoring wake with unknown mode", "sid", msg.Sid, "mode", msg.Mode)
	}
}

// acceptWakeRefs holds a poll or sstp-server wake's references in the queue
// and buffer this node holds for the stream; a node that holds none drops
// them. AckJtis must be index-aligned with Jtis, as must EnqueuedAt when it is
// present: a re-signed copy's acknowledgement JTI is derived (#363) and cannot
// be guessed, so a wake whose lists differ in length accepts nothing and is
// left to HandleWake's mode wake, a reload from the owner's pending read. An
// empty AckJti entry or a zero EnqueuedAt entry is the PendingRef convention
// for Jti and for the store's clock.
func (r *router) acceptWakeRefs(msg peer.WakeMessage) {
	if len(msg.Jtis) == 0 {
		return
	}
	if len(msg.AckJtis) != len(msg.Jtis) || (len(msg.EnqueuedAt) != 0 && len(msg.EnqueuedAt) != len(msg.Jtis)) {
		eventLogger.Warn("ROUTER: wake reference lists differ in length; reloading from pending",
			"sid", msg.Sid, "mode", msg.Mode, "jtis", len(msg.Jtis), "ackJtis", len(msg.AckJtis), "enqueuedAt", len(msg.EnqueuedAt))
		return
	}
	buf, _ := r.heldBuffer(msg.Mode, msg.Sid)
	if buf == nil {
		return
	}
	refs := make([]interfaces.PendingRef, len(msg.Jtis))
	for i, jti := range msg.Jtis {
		ref := interfaces.PendingRef{Jti: jti, AckJti: msg.AckJtis[i]}
		if i < len(msg.EnqueuedAt) && msg.EnqueuedAt[i] > 0 {
			ref.EnqueuedAt = time.UnixMilli(msg.EnqueuedAt[i])
		}
		refs[i] = ref
	}
	r.queueFor(msg.Sid).accept(r.ctx, refs)
	buf.SubmitEvents(msg.Jtis)
}

// HandleClaim answers a claim from a peer by the owner rule (#365): a node
// that does not hold the stream's lease answers NotOwner and does nothing;
// the owner serves the claim from its own queue, applying the
// acknowledgements and cleared setErrs in its one write.
func (r *router) HandleClaim(ctx context.Context, req peer.ClaimRequest) peer.ClaimResponse {
	if !peer.ValidClaimMode(req.Mode) {
		peerClaimsTotal.WithLabelValues(req.Mode, "not_owner").Inc()
		return peer.ClaimResponse{NotOwner: true}
	}
	resource := claimResource(req.Mode, req.Sid)
	if !r.leases.StillOwner(resource) {
		peerClaimsTotal.WithLabelValues(req.Mode, "not_owner").Inc()
		return peer.ClaimResponse{NotOwner: true}
	}
	if !r.ensureOwnerQueue(resource) {
		peerClaimsTotal.WithLabelValues(req.Mode, "not_owner").Inc()
		return peer.ClaimResponse{NotOwner: true}
	}
	resp, _ := r.claimLocal(ctx, req, true)
	result := "empty"
	switch {
	case resp.NotOwner:
		result = "not_owner"
	case len(resp.Refs) > 0:
		result = "served"
	}
	peerClaimsTotal.WithLabelValues(req.Mode, result).Inc()
	return resp
}
