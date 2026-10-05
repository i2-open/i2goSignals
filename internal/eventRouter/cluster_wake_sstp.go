package eventRouter

import (
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
)

const (
	// sstpWakeClientMode / sstpWakeServerMode are the "mode" component of the
	// cluster HMAC token (and of the request body) for the two SSTP wake-up
	// routes. Kept distinct from the push/poll modes so a token minted for one
	// route never validates against another.
	sstpWakeClientMode = peer.ModeSstpClient
	sstpWakeServerMode = peer.ModeSstpServer

	sstpWakeClientPath = peer.WakeSstpClientPath
	sstpWakeServerPath = peer.WakeSstpServerPath
)

// broadcastSstpClientWake sends POST /_cluster/wake-sstp-client to every active
// cluster node (except this one) so the sstp-client:<pairId> lease owner drains a
// pending outbound event into the next outbound cycle (Q11.2). Broadcast (not
// point-to-point) is acceptable for the current cluster size, and is idempotent on
// the receiving side.
func (r *router) broadcastSstpClientWake(pairId string) {
	r.broadcastSstpWake(sstpWakeClientPath, sstpWakeClientMode, pairId)
}

// broadcastSstpWake fans a wake-up to all active cluster nodes other than the
// local node. The id is the pair's PairId (client) or tx-side SID (server); mode
// distinguishes the two routes for the cluster auth token and for coalescing on
// the receiver.
func (r *router) broadcastSstpWake(path, mode, id string) {
	// Coalesce locally so a burst of outbound events for the same pair does not
	// fan out a storm of identical broadcasts within the window; a suppressed
	// wake arms one trailing broadcast so the burst's tail is not lost (#347).
	key := path + ":" + id
	if !r.outboundWakes.Admit(key, func() { r.sendSstpWake(path, mode, id) }) {
		return
	}
	r.sendSstpWake(path, mode, id)
}

// sendSstpWake sends the wake to every active node other than this one
// through the PeerTransport (an empty owner). The reference lists stay empty
// until #363, so every wake is a reload.
func (r *router) sendSstpWake(path, mode, id string) {
	if err := r.peers.Wake(r.ctx, "", peer.WakeMessage{Sid: id, Mode: mode}); err != nil {
		eventLogger.Warn("ROUTER: SSTP wake-up call failed", "path", path, "id", id, "error", err)
	}
}

// SSTP cluster wake-up local handlers (PRD #154 slice 10, issue #167).
//
// These methods wake the in-memory SSTP buffers of the local node in response to
// an inbound /_cluster/wake-sstp-client or /_cluster/wake-sstp-server call from a
// peer. They are the local-side counterparts to the broadcast triggers fired by
// HandleEvent; the broadcast/auth/HTTP plumbing lives in the server layer and in
// the PeerTransport. Both are idempotent: waking a pair with no resident
// buffer is a silent no-op, so duplicate or stale wake-ups are harmless (Q11.1,
// Q11.2).

// WakeSstpClient wakes the SSTP-client outbound buffer for pairId so the lease
// owner drains a pending outbound event into the next outbound cycle (Q11.2).
func (r *router) WakeSstpClient(pairId string) {
	r.mu.RLock()
	buf, ok := r.sstpBuffers[pairId]
	r.mu.RUnlock()
	if !ok {
		return
	}
	eventLogger.Debug("Waking SSTP client", "pairId", pairId)
	buf.Wakeup()
}

// WakeSstpServer wakes the SSTP-server long-poll buffer for txSid so a held
// long-poll on this node returns the outbound event immediately (Q11.1).
func (r *router) WakeSstpServer(txSid string) {
	r.mu.RLock()
	buf, ok := r.sstpServerBuffers[txSid]
	r.mu.RUnlock()
	if !ok {
		return
	}
	eventLogger.Debug("Waking SSTP server", "txSid", txSid)
	buf.Wakeup()
}
