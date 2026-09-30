package eventRouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Stream-table reconciliation (#349, #350).
//
// Every node keeps its own in-memory table of the outbound streams it serves.
// A stream created, updated or deleted through another node only changes the
// shared store, so each node reconciles its table against the store: on the periodic
// background sync, and at once when a peer says a stream changed
// (POST /_cluster/stream-changed). See docs/Cluster.md "Stream-table
// reconciliation".

const (
	// StreamChangedMode is the "mode" component of the cluster HMAC token (and
	// of the request body) for the stream-changed notification, distinct from
	// the wake-up modes so a token minted for one route never validates on
	// another.
	StreamChangedMode = "stream-changed"
	// StreamChangedPath is the internal route a peer is told on.
	StreamChangedPath = "/_cluster/stream-changed"

	// streamChangedTimeout bounds one stream-changed call to a peer, so a dead
	// peer does not hold a round for the router client's full 5s.
	streamChangedTimeout = 2 * time.Second
	// streamChangedRetryInterval is the pause between broadcast rounds that
	// retry the peers that have not acked.
	streamChangedRetryInterval = time.Second
	// streamChangedAckWindow bounds how long a broadcast (and so the stream
	// request that waits for it) retries an unacked peer; a peer still unacked
	// after that catches up on its periodic sync. The window is shorter than
	// the coordinator's active-node window, so a peer that has just died is
	// retried for all of it.
	streamChangedAckWindow = 15 * time.Second
)

// StreamTable is the router's stream-table reconciliation surface. It is a
// separate interface, not part of EventRouter, so the router test doubles that
// embed or fake EventRouter need not implement it; callers check for it with a
// type assertion.
type StreamTable interface {
	// StreamIds lists the outbound streams this router currently serves.
	StreamIds() []string
	// SyncStreamTable reconciles the router's streams with the store: every
	// stream in the store is (re)applied through UpdateStreamState, and every
	// stream the router served that the store no longer has is removed (its
	// runner stops and releases its lease). It returns the store's streams. On
	// a store error nothing is removed and the error is returned.
	SyncStreamTable(ctx context.Context) (map[string]model.StreamStateRecord, error)
	// BroadcastStreamChanged tells every other active node that stream sid was
	// created, updated, re-statused or deleted, so each reconciles now rather
	// than on its next periodic sync. It retries a peer until it acks, and
	// returns once every active peer has acked or refused the call, or
	// streamChangedAckWindow has passed.
	BroadcastStreamChanged(sid string)
}

var _ StreamTable = (*router)(nil)

func (r *router) StreamIds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]struct{}, len(r.pushStreams)+len(r.pollStreams)+len(r.sstpClientStreams)+len(r.sstpServerStreams))
	for sid := range r.pushStreams {
		seen[sid] = struct{}{}
	}
	for sid := range r.pollStreams {
		seen[sid] = struct{}{}
	}
	for sid := range r.sstpClientStreams {
		seen[sid] = struct{}{}
	}
	for sid := range r.sstpServerStreams {
		seen[sid] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for sid := range seen {
		ids = append(ids, sid)
	}
	return ids
}

func (r *router) SyncStreamTable(ctx context.Context) (map[string]model.StreamStateRecord, error) {
	// Snapshot what the router serves BEFORE reading the store. A local create
	// writes the store first and registers with the router second, so a stream
	// in this snapshot is already in the store unless it has been deleted; a
	// stream created after the snapshot is simply not considered for removal.
	known := r.StreamIds()

	states, err := r.streamService.LoadStateMap(ctx)
	if err != nil {
		eventLogger.Warn("ROUTER: stream-table sync could not read the store; nothing removed", "error", err)
		return nil, err
	}

	for _, state := range states {
		r.UpdateStreamState(&state)
	}
	for _, sid := range known {
		if _, ok := states[sid]; ok {
			continue
		}
		eventLogger.Info("ROUTER: stream no longer in the store; removing it", "sid", sid)
		r.RemoveStream(sid)
	}
	return states, nil
}

func (r *router) BroadcastStreamChanged(sid string) {
	if r.coordinator == nil {
		return
	}
	settled := map[string]bool{}  // acked, or refused and not retried
	lastErr := map[string]error{} // why each unsettled peer has not acked
	deadline := time.Now().Add(streamChangedAckWindow)
	retry := time.NewTimer(streamChangedRetryInterval)
	defer retry.Stop()
	for {
		nodes, err := r.coordinator.GetActiveNodes()
		if err != nil {
			eventLogger.Warn("ROUTER: cannot list peers for stream-changed; they catch up on their next sync", "sid", sid, "error", err)
			return
		}
		// Each round re-reads the active nodes, so a peer that has dropped out
		// of the cluster is no longer waited for, and one that joined is told.
		var pending []model.ClusterNode
		for _, node := range nodes {
			if node.Id != r.nodeId && node.Address != "" && !settled[node.Id] {
				pending = append(pending, node)
			}
		}
		if len(pending) == 0 {
			return
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, node := range pending {
			wg.Add(1)
			go func(node model.ClusterNode) {
				defer wg.Done()
				done, err := r.callStreamChanged(node.Address, sid)
				mu.Lock()
				defer mu.Unlock()
				if done {
					settled[node.Id] = true
				} else {
					lastErr[node.Id] = err
				}
			}(node)
		}
		wg.Wait()
		var missing []string
		for _, node := range pending {
			if !settled[node.Id] {
				missing = append(missing, node.Id+": "+lastErr[node.Id].Error())
			}
		}
		if len(missing) == 0 {
			// Every peer of this round acked; one more round catches a peer
			// that joined meanwhile, and otherwise returns at once.
			continue
		}
		if !time.Now().Add(streamChangedRetryInterval).Before(deadline) {
			eventLogger.Warn("ROUTER: peers did not acknowledge stream-changed; they catch up on their next sync", "sid", sid, "nodes", missing)
			return
		}
		retry.Reset(streamChangedRetryInterval)
		select {
		case <-r.ctx.Done():
			return
		case <-retry.C:
		}
	}
}

// callStreamChanged POSTs one stream-changed notification to a peer, with the
// shared-HMAC cluster bearer (SPIFFE mTLS, when configured, comes from the
// transport). done reports that the call needs no retry: the peer acked (202:
// it has reconciled the stream), or refused the call outright (a 4xx such as a
// token mismatch, which a retry cannot fix; logged here). Otherwise err says
// why the peer has not acked, and the broadcast retries.
func (r *router) callStreamChanged(address, sid string) (done bool, err error) {
	url := strings.TrimSuffix(address, "/") + StreamChangedPath
	ctx, cancel := context.WithTimeout(r.ctx, streamChangedTimeout)
	defer cancel()

	body, _ := json.Marshal(map[string]string{"sid": sid, "mode": StreamChangedMode})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		eventLogger.Warn("ROUTER: error creating stream-changed request", "url", url, "error", err)
		return true, err
	}
	req.Header.Set("Authorization", "Bearer "+authSupport.GenerateClusterToken(r.clusterSecret, sid, StreamChangedMode))
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		eventLogger.Debug("ROUTER: stream-changed call failed; retrying", "url", url, "sid", sid, "error", err)
		return false, err
	}
	defer httpSupport.HandleRespClose(resp)
	switch code := resp.StatusCode; {
	case code == http.StatusAccepted:
		eventLogger.Debug("ROUTER: stream-changed delivered", "url", url, "sid", sid)
		return true, nil
	case code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests:
		eventLogger.Warn("ROUTER: stream-changed call refused; the peer catches up on its next sync", "url", url, "sid", sid, "status", resp.Status)
		return true, fmt.Errorf("refused: %s", resp.Status)
	default:
		eventLogger.Debug("ROUTER: stream-changed call not acked; retrying", "url", url, "sid", sid, "status", resp.Status)
		return false, fmt.Errorf("not acked: %s", resp.Status)
	}
}
