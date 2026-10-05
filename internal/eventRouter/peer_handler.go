package eventRouter

import (
	"context"

	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
)

// The router is the receiving side of the PeerTransport (#358).
var _ peer.Handler = (*router)(nil)

// HandleWake acts on a wake from a peer. A filter-change wake invalidates the
// stream's subject-filter match-result cache (issue #94); every other wake
// wakes the local buffer for its mode. The reference lists are ignored until
// #363, so every wake is a reload. Waking a stream with no resident buffer is
// a silent no-op, so a duplicate, stale or lost wake is harmless.
func (r *router) HandleWake(msg peer.WakeMessage) {
	switch msg.Mode {
	case peer.ModePush, peer.ModePoll:
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

// HandleClaim answers a claim from a peer. Until #365 this node serves no
// claims, so it answers NotOwner and does nothing.
func (r *router) HandleClaim(_ context.Context, _ peer.ClaimRequest) peer.ClaimResponse {
	return peer.ClaimResponse{NotOwner: true}
}
