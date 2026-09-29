package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Stream-table reconciliation (#349, #350). See docs/Cluster.md "Stream-table
// reconciliation".

const (
	// clusterGCWindow is how long a node may go unseen, and a lease may stay
	// expired, before the stream-table sync purges its row: three lease TTLs
	// (30s each), so a node that is merely slow to heartbeat, or a lease
	// between tenures, is never purged.
	clusterGCWindow = 90 * time.Second

	// streamChangedSyncTimeout bounds the store read a stream-changed call
	// triggers.
	streamChangedSyncTimeout = 10 * time.Second
)

// syncStreamTable reconciles this node with the store: the receivers first,
// then the router's outbound streams (new ones start, ones gone from the store
// stop and release their leases), then, when the store read succeeded, the
// stale cluster rows. It runs from the periodic background sync and on every
// stream-changed call from a peer; syncMu serializes the two.
func (sa *SignalsApplication) syncStreamTable() {
	sa.syncMu.Lock()
	defer sa.syncMu.Unlock()

	sa.InitializeReceivers()

	table, ok := sa.EventRouter.(eventRouter.StreamTable)
	if !ok {
		for _, state := range sa.StreamService.GetStateMap(context.Background()) {
			sa.EventRouter.UpdateStreamState(&state)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), streamChangedSyncTimeout)
	defer cancel()
	states, err := table.SyncStreamTable(ctx)
	if err != nil {
		// Nothing was removed; without the store's streams the GC cannot tell
		// a deleted stream's lease from a live one, so it waits too.
		return
	}
	sa.purgeClusterRows(states)
}

// purgeClusterRows deletes the cluster_nodes rows of nodes unseen for the GC
// window, and the cluster_leases rows expired for the GC window whose stream
// or pair is no longer in the store. A lease of an unknown kind is kept.
func (sa *SignalsApplication) purgeClusterRows(states map[string]model.StreamStateRecord) {
	reaper, ok := sa.Coordinator.(cluster.Reaper)
	if !ok {
		return
	}
	cutoff := time.Now().UTC().Add(-clusterGCWindow)

	if n, err := reaper.PurgeStaleNodes(cutoff); err != nil {
		serverLog.Warn("CLUSTER: purge of stale cluster nodes failed; retrying on the next sync", "error", err)
	} else if n > 0 {
		serverLog.Info("CLUSTER: purged stale cluster nodes", "count", n)
	}

	live := make(map[string]bool, len(states)*2)
	for id, state := range states {
		live[id] = true
		if state.PairId != "" {
			live[state.PairId] = true
		}
		if state.SstpInbound != nil && state.SstpInbound.Id != "" {
			live[state.SstpInbound.Id] = true
		}
	}
	keep := func(resource string) bool {
		_, id, known := cluster.ResourceId(resource)
		return !known || live[id]
	}
	if n, err := reaper.PurgeExpiredLeases(cutoff, keep); err != nil {
		serverLog.Warn("CLUSTER: purge of deleted streams' leases failed; retrying on the next sync", "error", err)
	} else if n > 0 {
		serverLog.Info("CLUSTER: purged leases of deleted streams", "count", n)
	}
}

// StreamChanged handles POST /_cluster/stream-changed: a peer created or
// deleted a stream. After authenticating, it reconciles the stream table at
// once and answers 202 when done. Unlike the wake-up routes it is never
// coalesced: a create and a quick delete of the same stream must both be seen,
// and a redundant sync is harmless.
func (sa *SignalsApplication) StreamChanged(w http.ResponseWriter, r *http.Request) {
	sid, ok := authenticateClusterCall(w, r, eventRouter.StreamChangedMode)
	if !ok {
		return
	}
	serverLog.Debug("CLUSTER: stream-changed from a peer; reconciling the stream table", "sid", sid)
	sa.syncStreamTable()
	w.WriteHeader(http.StatusAccepted)
}

// authenticateClusterCall parses a {"sid","mode"} cluster call and
// authenticates it: a SPIFFE peer certificate, else the
// I2SIG_CLUSTER_INTERNAL_TOKEN HMAC bearer bound to sid and mode. It returns
// the sid, or writes 400/401 and returns ok=false.
func authenticateClusterCall(w http.ResponseWriter, r *http.Request, mode string) (string, bool) {
	var req WakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return "", false
	}
	if req.Sid == "" {
		http.Error(w, "invalid sid", http.StatusBadRequest)
		return "", false
	}

	// SPIFFE peer cert first; HMAC shared secret otherwise.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if !isPeerSpiffeAuthenticated(r.TLS) {
			serverLog.Warn("CLUSTER: invalid SPIFFE peer certificate", "remote", r.RemoteAddr, "mode", mode)
			w.WriteHeader(http.StatusUnauthorized)
			return "", false
		}
		serverLog.Debug("CLUSTER: SPIFFE peer authenticated", "remote", r.RemoteAddr, "mode", mode)
		return req.Sid, true
	}
	secret := os.Getenv("I2SIG_CLUSTER_INTERNAL_TOKEN")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 7 ||
		!authSupport.ValidateClusterToken(secret, authHeader[7:], req.Sid, mode, 30*time.Second) {
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	return req.Sid, true
}

// notifyStreamChanged tells the other nodes that stream sid was created or
// deleted here, so each reconciles its stream table now. It waits for the
// peers (each bounded at 2s) so that when the create or delete answers, the
// cluster already serves the new state; a peer that misses it catches up on
// its periodic sync.
func notifyStreamChanged(sa SsfApplicationInterface, sid string) {
	if table, ok := sa.GetEventRouter().(eventRouter.StreamTable); ok {
		table.BroadcastStreamChanged(sid)
	}
}
