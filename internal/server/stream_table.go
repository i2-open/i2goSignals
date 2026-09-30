package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
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

	// streamTableSyncTimeout bounds the store read of one periodic
	// stream-table sync.
	streamTableSyncTimeout = 10 * time.Second

	// streamChangedReadTimeout bounds the one-stream store read a
	// stream-changed call makes, well inside the peer's call bound.
	streamChangedReadTimeout = 1500 * time.Millisecond

	// streamChangedStopTimeout bounds how long a stream-changed call waits
	// for this node's push runner on a removed or held stream to stop, inside
	// the peer's holder window.
	streamChangedStopTimeout = 4 * time.Second
)

// syncStreamTable reconciles this node with the store: the receivers first,
// then the router's outbound streams (new ones start, ones gone from the store
// stop and release their leases), then, when the store read succeeded, the
// stale cluster rows. It runs from the periodic background sync; syncMu
// serializes it with a stream-changed call's one-stream reconcile and with a
// local delete.
func (sa *SignalsApplication) syncStreamTable() {
	sa.syncMu.Lock()
	defer sa.syncMu.Unlock()

	sa.InitializeReceivers()

	table, ok := sa.EventRouter.(eventRouter.StreamTable)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), streamTableSyncTimeout)
	defer cancel()
	states, err := table.SyncStreamTable(ctx)
	if err != nil {
		// Nothing was removed; without the store's streams the GC cannot tell
		// a deleted stream's lease from a live one, so it waits too.
		return
	}
	sa.purgeClusterRows(states)
}

// streamTableLocker is implemented by an application that reconciles its
// stream table in the background.
type streamTableLocker interface {
	lockStreamTable() (unlock func())
}

// lockStreamTable holds off stream-table syncs until unlock is called. A
// local delete takes it so that no sync re-adds the stream between the
// router's RemoveStream and the store's delete (#350). An application with no
// background sync gets a no-op.
func lockStreamTable(sa SsfApplicationInterface) (unlock func()) {
	if l, ok := sa.(streamTableLocker); ok {
		return l.lockStreamTable()
	}
	return func() {}
}

func (sa *SignalsApplication) lockStreamTable() (unlock func()) {
	sa.syncMu.Lock()
	return sa.syncMu.Unlock
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

// StreamChanged handles POST /_cluster/stream-changed: a peer created,
// updated, re-statused or deleted a stream. After authenticating, it
// reconciles that one stream and answers 202 when done — the ack the peer
// waits for when this node holds the stream's lease — or 503 when the store
// could not be read, so the peer retries. When the stream was removed, or is
// stored as not enabled, done means this node's push runner for it has
// stopped: the call waits up to streamChangedStopTimeout for that, and answers
// 503 if it has not. An SSTP pair's pause is reconcile-only: its client runner
// stops on its own status check, not here. The full store scan and the
// cluster-row purge stay on the periodic sync, so the call stays inside the
// peer's bound however large the store (#349). The sender coalesces repeated
// calls for one stream that a peer has not yet acked; a redundant reconcile
// is harmless.
func (sa *SignalsApplication) StreamChanged(w http.ResponseWriter, r *http.Request) {
	sid, ok := authenticateClusterCall(w, r, eventRouter.StreamChangedMode)
	if !ok {
		return
	}
	serverLog.Debug("CLUSTER: stream-changed from a peer; reconciling the stream", "sid", sid)
	reconciled, held := sa.reconcileStream(sid)
	if !reconciled {
		// Not reconciled: no ack, so the peer retries.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if held {
		if table, ok := sa.EventRouter.(eventRouter.StreamTable); ok {
			ctx, cancel := context.WithTimeout(r.Context(), streamChangedStopTimeout)
			stopped := table.AwaitPushStopped(ctx, sid)
			cancel()
			if !stopped {
				serverLog.Warn("CLUSTER: stream-changed: the stream's push runner has not stopped yet; the peer retries", "sid", sid)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

// reconcileStream brings this node in line with the store for stream sid: a
// stream in the store is applied to the router and the receivers, one gone
// from the store is removed from both. held reports that the stream was
// removed or is stored as not enabled, so its push runner is stopping. A
// store read that fails changes nothing and reports reconciled false; the
// periodic sync catches up. syncMu is held only for this one stream's work,
// not while the caller waits for the runner to stop.
func (sa *SignalsApplication) reconcileStream(sid string) (reconciled, held bool) {
	sa.syncMu.Lock()
	defer sa.syncMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), streamChangedReadTimeout)
	defer cancel()
	state, err := sa.StreamService.GetStreamState(ctx, sid)
	switch {
	case errors.Is(err, interfaces.ErrNotFound):
		sa.CloseReceiver(sid)
		sa.EventRouter.RemoveStream(sid)
		return true, true
	case err != nil:
		serverLog.Warn("CLUSTER: stream-changed could not read the stream; the periodic sync catches up", "sid", sid, "error", err)
		return false, false
	default:
		sa.reconcileReceiver(state)
		sa.EventRouter.UpdateStreamState(state)
		return true, state.Status != model.StreamStateEnabled
	}
}

// authenticateClusterCall parses a {"sid","mode"} cluster call and
// authenticates it: a SPIFFE peer certificate, else the
// I2SIG_CLUSTER_INTERNAL_TOKEN HMAC bearer bound to sid and mode. It returns
// the sid, or writes 400/401 and returns ok=false.
func authenticateClusterCall(w http.ResponseWriter, r *http.Request, mode string) (string, bool) {
	req, ok := decodeWakeRequest(w, r)
	if !ok || !authenticateCluster(w, r, req.Sid, mode) {
		return "", false
	}
	return req.Sid, true
}

// decodeWakeRequest reads a cluster call's body; a body without a sid is a 400.
func decodeWakeRequest(w http.ResponseWriter, r *http.Request) (WakeRequest, bool) {
	var req WakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return req, false
	}
	if req.Sid == "" {
		http.Error(w, "invalid sid", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// authenticateCluster checks a peer node's call for sid and mode: a SPIFFE
// peer certificate first, the HMAC shared secret otherwise. It writes 401 on
// failure.
func authenticateCluster(w http.ResponseWriter, r *http.Request, sid, mode string) bool {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if !isPeerSpiffeAuthenticated(r.TLS) {
			serverLog.Warn("CLUSTER: invalid SPIFFE peer certificate", "remote", r.RemoteAddr, "mode", mode)
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		serverLog.Debug("CLUSTER: SPIFFE peer authenticated", "remote", r.RemoteAddr, "mode", mode)
		return true
	}
	secret := os.Getenv("I2SIG_CLUSTER_INTERNAL_TOKEN")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 7 ||
		!authSupport.ValidateClusterToken(secret, authHeader[7:], sid, mode, 30*time.Second) {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

// notifyStreamChanged tells the other nodes that stream sid was created,
// updated, re-statused or deleted here, so each reconciles its stream table
// now. It waits only for the node holding the stream's lease, whose runner a
// change affects, and only for the router's holder window: when the request
// answers, the runner serving the stream has the new state (or has stopped,
// for a delete or hold). Every other peer is told in the background, and one
// that never acks catches up on its periodic sync.
func notifyStreamChanged(sa SsfApplicationInterface, sid string) {
	if table, ok := sa.GetEventRouter().(eventRouter.StreamTable); ok {
		table.BroadcastStreamChanged(sid)
	}
}
