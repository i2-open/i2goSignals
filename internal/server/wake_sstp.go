package server

import (
	"net/http"
)

// SSTP cluster wake-up endpoints (PRD #154 slice 10, issue #167).
//
// Two routes mirror the existing /_cluster/wake-transmitter pattern but are kept
// separate for telemetry separation (Q11.1, Q11.2):
//
//   - POST /_cluster/wake-sstp-client — broadcast to all cluster_nodes when a node
//     receives an inbound event whose target SSTP-client pair is owned (via the
//     sstp-client:<PairId> lease) by a different node, so the owner drains the
//     pending event into the next outbound cycle.
//   - POST /_cluster/wake-sstp-server — broadcast to all cluster_nodes when a node
//     receives an outbound event matching an SSTP-server pair, so a long-poll held
//     on the receiver side returns the event immediately.
//
// Both reuse the wake-transmitter authentication (SPIFFE mTLS peer cert, else the
// I2SIG_CLUSTER_INTERNAL_TOKEN shared-HMAC bearer token) and the same coalescing
// window, so duplicate wake-ups are idempotent no-ops.

const (
	// sstpWakeClientMode / sstpWakeServerMode are the "mode" component of the
	// cluster HMAC token (and of the request body) for each SSTP wake-up route.
	// They are kept distinct from the push/poll modes so a token minted for one
	// route never validates against another.
	sstpWakeClientMode = "sstp-client"
	sstpWakeServerMode = "sstp-server"
)

// WakeSstpClient handles inbound /_cluster/wake-sstp-client calls. The body's sid
// field carries the pair's PairId. After authenticating and coalescing, it wakes
// the local SSTP-client outbound buffer so the lease owner drains a pending
// outbound event into the next cycle (Q11.2).
func (sa *SignalsApplication) WakeSstpClient(w http.ResponseWriter, r *http.Request) {
	sa.handleSstpWake(w, r, sstpWakeClientMode, sa.EventRouter.WakeSstpClient)
}

// WakeSstpServer handles inbound /_cluster/wake-sstp-server calls. The body's sid
// field carries the pair's tx-side SID. After authenticating and coalescing, it
// wakes the local SSTP-server long-poll buffer so a held long-poll returns the
// outbound event immediately (Q11.1).
func (sa *SignalsApplication) WakeSstpServer(w http.ResponseWriter, r *http.Request) {
	sa.handleSstpWake(w, r, sstpWakeServerMode, sa.EventRouter.WakeSstpServer)
}

// handleSstpWake authenticates an SSTP wake-up request and coalesces it
// before calling wake with the target id (pairId or txSid from the body's sid
// field). A rejected request gets 400/401. An accepted one gets 202: the first
// of a burst wakes at once, the rest share one trailing wake at the end of the
// coalescing window (idempotency, issue #167; trailing edge, #347).
func (sa *SignalsApplication) handleSstpWake(w http.ResponseWriter, r *http.Request, mode string, wake func(id string)) {
	req, ok := decodeWakeRequest(w, r)
	if !ok || !authenticateCluster(w, r, req.Sid, mode) {
		return
	}
	id := req.Sid
	// An sstp-server wake to the acceptor's lease owner carries the batch's
	// references (#365); it is applied at once rather than coalesced.
	req.Mode = mode
	if mode == sstpWakeServerMode && sa.applyRefWake(req) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	// The mode keeps SSTP keys distinct from push/poll keys for the same id.
	fire := func() { wake(id) }
	if clusterWakes.Admit(id+":"+mode, fire) {
		fire()
	}
	w.WriteHeader(http.StatusAccepted)
}
