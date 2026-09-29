package eventRouter

import (
	"bytes"
	"context"
	"encoding/json"
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
// A stream created or deleted through another node only changes the shared
// store, so each node reconciles its table against the store: on the periodic
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

	// streamChangedTimeout bounds one stream-changed call to a peer. The
	// create/delete request waits for the broadcast, so a dead peer must not
	// hold it for the router client's full 5s; the peer then catches up on its
	// next periodic sync.
	streamChangedTimeout = 2 * time.Second
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
	// created or deleted, so each reconciles now rather than on its next
	// periodic sync. It returns once every peer has answered or timed out.
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
	nodes, err := r.coordinator.GetActiveNodes()
	if err != nil {
		eventLogger.Warn("ROUTER: cannot list peers for stream-changed; they catch up on their next sync", "sid", sid, "error", err)
		return
	}
	var wg sync.WaitGroup
	for _, node := range nodes {
		if node.Id == r.nodeId || node.Address == "" {
			continue
		}
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			r.callStreamChanged(address, sid)
		}(node.Address)
	}
	wg.Wait()
}

// callStreamChanged POSTs one stream-changed notification to a peer, with the
// shared-HMAC cluster bearer (SPIFFE mTLS, when configured, comes from the
// transport). A failure is logged; the peer then reconciles on its next
// periodic sync.
func (r *router) callStreamChanged(address, sid string) {
	url := strings.TrimSuffix(address, "/") + StreamChangedPath
	ctx, cancel := context.WithTimeout(r.ctx, streamChangedTimeout)
	defer cancel()

	body, _ := json.Marshal(map[string]string{"sid": sid, "mode": StreamChangedMode})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		eventLogger.Warn("ROUTER: error creating stream-changed request", "url", url, "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+authSupport.GenerateClusterToken(r.clusterSecret, sid, StreamChangedMode))
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		eventLogger.Warn("ROUTER: stream-changed call failed; the peer catches up on its next sync", "url", url, "sid", sid, "error", err)
		return
	}
	defer httpSupport.HandleRespClose(resp)
	if resp.StatusCode != http.StatusAccepted {
		eventLogger.Warn("ROUTER: stream-changed call rejected", "url", url, "sid", sid, "status", resp.Status)
		return
	}
	eventLogger.Debug("ROUTER: stream-changed delivered", "url", url, "sid", sid)
}
