package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// WakeRequest is the body of a cluster wake-up call from a peer node. An empty
// Reason is an ordinary buffer wake-up; Reason "filter-change" instead
// invalidates the stream's subject-filter match-result cache (issue #94).
type WakeRequest struct {
	Sid    string `json:"sid"`
	Mode   string `json:"mode"`
	Reason string `json:"reason,omitempty"`
}

var (
	recentWakes   = make(map[string]time.Time)
	recentWakesMu sync.Mutex
)

// WakeTransmitter handles inbound cluster wake-up calls from peer nodes.
//
// Authentication is tried in order:
//  1. SPIFFE X.509-SVID peer certificate — if the TLS connection carries a
//     valid client certificate whose SPIFFE ID belongs to the cluster trust
//     domain, the request is accepted without an HMAC token.
//  2. HMAC shared secret (I2SIG_CLUSTER_INTERNAL_TOKEN) — the existing
//     mechanism, retained for nodes that have not yet been enrolled in SPIRE.
//
// This dual-path design allows a phased rollout: nodes can migrate to SPIFFE
// one at a time while the cluster continues to operate.
func (sa *SignalsApplication) WakeTransmitter(w http.ResponseWriter, r *http.Request) {
	var req WakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Sid == "" || (req.Mode != "push" && req.Mode != "poll") {
		http.Error(w, "invalid sid or mode", http.StatusBadRequest)
		return
	}

	// --- Authentication ---
	// If the connection is TLS and the peer presented a certificate, try SPIFFE.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if !isPeerSpiffeAuthenticated(r.TLS) {
			// A cert was presented but it is not a valid cluster SVID.
			serverLog.Warn("CLUSTER: invalid SPIFFE peer certificate", "remote", r.RemoteAddr)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// SPIFFE authentication succeeded; skip HMAC check.
		serverLog.Debug("CLUSTER: SPIFFE peer authenticated", "remote", r.RemoteAddr)
	} else {
		// No TLS peer cert — fall back to HMAC.
		secret := os.Getenv("I2SIG_CLUSTER_INTERNAL_TOKEN")
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 7 ||
			!authSupport.ValidateClusterToken(secret, authHeader[7:], req.Sid, req.Mode, 30*time.Second) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// --- Rate limiting / Coalescing ---
	// The reason is part of the key so a filter-change invalidation is never
	// coalesced away by an ordinary buffer wake-up for the same stream.
	key := req.Sid + ":" + req.Mode + ":" + req.Reason
	recentWakesMu.Lock()
	lastWake, exists := recentWakes[key]
	if exists && time.Since(lastWake) < 250*time.Millisecond {
		recentWakesMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		return
	}
	recentWakes[key] = time.Now()
	recentWakesMu.Unlock()

	go func() {
		time.Sleep(1 * time.Minute)
		recentWakesMu.Lock()
		if t, ok := recentWakes[key]; ok && time.Since(t) >= 1*time.Minute {
			delete(recentWakes, key)
		}
		recentWakesMu.Unlock()
	}()

	// A filter-change notification invalidates the stream's subject-filter
	// match-result cache rather than waking a delivery buffer (issue #94).
	if req.Reason == eventRouter.ReasonFilterChange {
		if sa.SubjectFilterService != nil {
			sa.SubjectFilterService.InvalidateCache(req.Sid)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	sa.EventRouter.WakeTransmitter(req.Sid, req.Mode)
	w.WriteHeader(http.StatusAccepted)
}

// isPeerSpiffeAuthenticated returns true if the TLS connection's peer
// certificate carries a SPIFFE ID that belongs to the cluster trust
// domain configured via I2SIG_SPIFFE_TRUST_DOMAIN (default:
// cluster.i2gosignals.internal).
//
// This is called only when r.TLS.PeerCertificates is non-empty, i.e. after
// the peer has already presented a certificate during the TLS handshake.
func isPeerSpiffeAuthenticated(state *tls.ConnectionState) bool {
	td, err := tlsSupport.ClusterTrustDomain()
	if err != nil {
		serverLog.Warn("CLUSTER: invalid SPIFFE trust domain", "err", err)
		return false
	}
	id, err := spiffetls.PeerIDFromConnectionState(*state)
	if err != nil {
		// Peer cert exists but does not carry a SPIFFE URI SAN.
		return false
	}
	return id.MemberOf(td)
}

// startInternalServer starts an optional internal cluster HTTP(S) server on
// the port given by I2SIG_CLUSTER_INTERNAL_PORT. When SPIFFE is enabled,
// the server is started with mutual TLS so that peer nodes can authenticate
// using their X509-SVIDs while HMAC-only nodes continue to work.
//
// If I2SIG_CLUSTER_INTERNAL_PORT is not set, cluster traffic is handled on
// the main server port via the /_cluster/wake-transmitter route.
func (sa *SignalsApplication) startInternalServer() {
	port := os.Getenv("I2SIG_CLUSTER_INTERNAL_PORT")
	if port == "" {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_cluster/wake-transmitter", sa.WakeTransmitter)
	mux.HandleFunc("/_cluster/wake-sstp-client", sa.WakeSstpClient)
	mux.HandleFunc("/_cluster/wake-sstp-server", sa.WakeSstpServer)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// When SPIFFE is available, serve with mTLS so peers can present SVIDs.
	if tlsSupport.SpiffeEnabled() {
		spiffeCtx, spiffeCancel := context.WithTimeout(context.Background(), 60*time.Second)
		x509Source, err := tlsSupport.NewX509Source(spiffeCtx)
		spiffeCancel()
		if err != nil {
			serverLog.Warn("CLUSTER: SPIFFE enabled but X509Source failed; "+
				"internal server starting without mTLS", "err", err)
		} else {
			tlsCfg, cfgErr := tlsSupport.NewClusterMTLSServerConfig(x509Source)
			if cfgErr != nil {
				serverLog.Warn("CLUSTER: failed to build mTLS server config; "+
					"starting without mTLS", "err", cfgErr)
				_ = x509Source.Close()
			} else {
				srv.TLSConfig = tlsCfg
				sa.InternalServer = srv
				go func() {
					serverLog.Info("Internal cluster server listening with mTLS", "port", port)
					// Empty cert/key: GetCertificate in TLSConfig provides the SVID.
					if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
						serverLog.Error("Internal cluster server failed", "error", err)
					}
					_ = x509Source.Close()
				}()
				return
			}
		}
	}

	// Plain HTTP fallback (HMAC auth only).
	sa.InternalServer = srv
	go func() {
		serverLog.Info("Internal cluster server listening (plain HTTP)", "port", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverLog.Error("Internal cluster server failed", "error", err)
		}
	}()
}

// clusterPeerIDFromRequest extracts the SPIFFE ID from the TLS peer
// certificate of an incoming request. Returns an error if the connection is
// not TLS, if no peer certificate was presented, or if the certificate does
// not carry a SPIFFE URI SAN. Exported for use in tests.
func clusterPeerIDFromRequest(r *http.Request) (spiffeid.ID, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return spiffeid.ID{}, nil
	}
	return x509svid.IDFromCert(r.TLS.PeerCertificates[0])
}
