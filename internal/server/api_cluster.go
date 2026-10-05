package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// WakeRequest is the body of a cluster wake-up call from a peer node, the
// wire form of peer.WakeMessage. An empty Reason is an ordinary buffer
// wake-up; Reason "filter-change" instead invalidates the stream's
// subject-filter match-result cache (issue #94). Jtis, AckJtis and EnqueuedAt
// are index-aligned reference lists; senders leave them empty until #363, so
// every wake is a reload.
type WakeRequest struct {
	Sid        string   `json:"sid"`
	Mode       string   `json:"mode"`
	Reason     string   `json:"reason,omitempty"`
	Jtis       []string `json:"jtis,omitempty"`
	AckJtis    []string `json:"ackJtis,omitempty"`
	EnqueuedAt []int64  `json:"enqueuedAt,omitempty"`
}

// clusterWakes coalesces inbound cluster wake-ups per target, on both edges
// (#347): the first of a burst wakes the local buffer at once, and the rest
// share one trailing wake at the window's end.
var clusterWakes = eventRouter.NewWakeCoalescer(eventRouter.WakeCoalesceWindow)

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
	req, ok := decodeWakeRequest(w, r)
	if !ok {
		return
	}
	if req.Mode != "push" && req.Mode != "poll" {
		http.Error(w, "invalid sid or mode", http.StatusBadRequest)
		return
	}
	if !authenticateCluster(w, r, req.Sid, req.Mode) {
		return
	}

	// The reason is part of the coalescing key so a filter-change invalidation
	// is never coalesced away by an ordinary buffer wake-up for the same stream.
	key := req.Sid + ":" + req.Mode + ":" + req.Reason
	wake := func() { sa.applyWake(req) }
	if clusterWakes.Admit(key, wake) {
		wake()
	}
	w.WriteHeader(http.StatusAccepted)
}

// applyWake acts on an authenticated wake-transmitter request. A filter-change
// notification invalidates the stream's subject-filter match-result cache
// rather than waking a delivery buffer (issue #94).
func (sa *SignalsApplication) applyWake(req WakeRequest) {
	if req.Reason == eventRouter.ReasonFilterChange {
		if sa.SubjectFilterService != nil {
			sa.SubjectFilterService.InvalidateCache(req.Sid)
		}
		return
	}
	sa.EventRouter.WakeTransmitter(req.Sid, req.Mode)
}

// ClaimStream handles POST /_cluster/claim from a peer node (#358): the
// caller asks this node, as the stream's lease owner, to apply
// acknowledgements and claim the next references. It decodes the body,
// authenticates it like the wake endpoints (SPIFFE peer certificate, else
// the HMAC token over sid and mode), and writes the router's answer with
// status 200. The router's HandleClaim runs under the request's context, so a
// caller that gives up ends it.
func (sa *SignalsApplication) ClaimStream(w http.ResponseWriter, r *http.Request) {
	var req peer.ClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Sid == "" || !peer.ValidClaimMode(req.Mode) {
		http.Error(w, "invalid sid or mode", http.StatusBadRequest)
		return
	}
	if !authenticateCluster(w, r, req.Sid, req.Mode) {
		return
	}
	resp := peer.ClaimResponse{NotOwner: true}
	if h, ok := sa.EventRouter.(peer.ClaimHandler); ok {
		resp = h.HandleClaim(r.Context(), req)
	}
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
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
	mux.HandleFunc(eventRouter.StreamChangedPath, sa.StreamChanged)
	mux.HandleFunc("POST "+peer.ClaimPath, sa.ClaimStream)

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
