package server

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
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
	id, ok := sa.authorizeSstpWake(w, r, sstpWakeClientMode)
	if !ok {
		return
	}
	sa.EventRouter.WakeSstpClient(id)
	w.WriteHeader(http.StatusAccepted)
}

// WakeSstpServer handles inbound /_cluster/wake-sstp-server calls. The body's sid
// field carries the pair's tx-side SID. After authenticating and coalescing, it
// wakes the local SSTP-server long-poll buffer so a held long-poll returns the
// outbound event immediately (Q11.1).
func (sa *SignalsApplication) WakeSstpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := sa.authorizeSstpWake(w, r, sstpWakeServerMode)
	if !ok {
		return
	}
	sa.EventRouter.WakeSstpServer(id)
	w.WriteHeader(http.StatusAccepted)
}

// authorizeSstpWake parses, authenticates, and coalesces an SSTP wake-up request.
// It returns the target id (pairId or txSid from the body's sid field) and true
// when the caller should proceed to wake the local buffer. On a rejected request
// it writes the appropriate status (400/401) and returns ok=false. A duplicate
// within the coalescing window writes 202 directly and returns ok=false so the
// wake is not re-dispatched (idempotency, issue #167).
func (sa *SignalsApplication) authorizeSstpWake(w http.ResponseWriter, r *http.Request, mode string) (string, bool) {
	var req WakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return "", false
	}
	if req.Sid == "" {
		http.Error(w, "invalid sid", http.StatusBadRequest)
		return "", false
	}

	// --- Authentication (identical to WakeTransmitter) ---
	// SPIFFE peer cert first; HMAC shared secret otherwise.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if !isPeerSpiffeAuthenticated(r.TLS) {
			serverLog.Warn("CLUSTER: invalid SPIFFE peer certificate", "remote", r.RemoteAddr, "mode", mode)
			w.WriteHeader(http.StatusUnauthorized)
			return "", false
		}
		serverLog.Debug("CLUSTER: SPIFFE peer authenticated", "remote", r.RemoteAddr, "mode", mode)
	} else {
		secret := os.Getenv("I2SIG_CLUSTER_INTERNAL_TOKEN")
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 7 ||
			!authSupport.ValidateClusterToken(secret, authHeader[7:], req.Sid, mode, 30*time.Second) {
			w.WriteHeader(http.StatusUnauthorized)
			return "", false
		}
	}

	// --- Coalescing / idempotency ---
	// Reuse the wake-transmitter recentWakes map; the mode keeps SSTP keys
	// distinct from push/poll keys for the same id.
	key := req.Sid + ":" + mode
	recentWakesMu.Lock()
	lastWake, exists := recentWakes[key]
	if exists && time.Since(lastWake) < 250*time.Millisecond {
		recentWakesMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		return "", false
	}
	recentWakes[key] = time.Now()
	recentWakesMu.Unlock()

	return req.Sid, true
}
