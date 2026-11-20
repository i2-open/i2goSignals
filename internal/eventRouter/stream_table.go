package eventRouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
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

	// streamChangedTimeout bounds one background stream-changed call to a
	// peer. It leaves room for a lease holder that waits for its runner to
	// stop before it acks, so a dead peer holds its notifier no longer.
	streamChangedTimeout = 5 * time.Second
	// streamChangedRetryInterval is the pause between calls to a lease holder
	// that has not acked, and the first backoff of a peer's notifier.
	streamChangedRetryInterval = time.Second
	// streamChangedHolderWindow bounds how long a broadcast (and so the stream
	// request that waits for it) waits for the node holding the stream's
	// lease to ack. A holder still unacked after that is told in the
	// background, like every other peer.
	streamChangedHolderWindow = 5 * time.Second
	// streamChangedMaxBackoff caps the backoff between a peer notifier's
	// retries.
	streamChangedMaxBackoff = 8 * time.Second
	// streamChangedGiveUp is how long a peer notifier keeps retrying one
	// stream before it gives up; the peer catches up on its periodic sync.
	streamChangedGiveUp = 60 * time.Second
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
	// than on its next periodic sync. It waits only for the node holding the
	// stream's lease, the one whose runner must act on the change: when that
	// is this node, until its stopping runner has exited; when it is a peer,
	// until the peer acks, retrying for up to streamChangedHolderWindow. Every
	// other peer, and a holder that has not acked, is told in the background.
	// With no holder it does not wait at all.
	BroadcastStreamChanged(sid string)
	// AwaitPushStopped waits until the push runner for sid that this node
	// retired last (a pause, a disable, a delete or a restart) has exited, and
	// reports whether it did before ctx ended.
	AwaitPushStopped(ctx context.Context, sid string) bool
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

	settled := ""
	holder := r.streamHolder(sid)
	switch {
	case holder == r.nodeId || (holder == "" && r.pushStopping(sid)):
		// The runner is on this node, and the request handler has already
		// applied the change to it: wait for a retired runner to exit. With no
		// holder, a runner retired here may just have released its lease.
		ctx, cancel := context.WithTimeout(r.ctx, streamChangedHolderWindow)
		stopped := r.AwaitPushStopped(ctx, sid)
		cancel()
		if !stopped {
			eventLogger.Warn("ROUTER: the stream's runner did not stop within the window; returning anyway", "sid", sid, "window", streamChangedHolderWindow)
		}
	case holder != "":
		for _, node := range nodes {
			if node.Id != holder {
				continue
			}
			if node.Address == "" {
				eventLogger.Warn("ROUTER: the stream's lease holder has no address; it catches up on its next sync", "sid", sid, "node", holder)
				settled = holder
			} else if r.tellHolder(node, sid) {
				settled = holder
			}
		}
	}

	for _, node := range nodes {
		if node.Id == r.nodeId || node.Address == "" || node.Id == settled {
			continue
		}
		r.notifyPeer(node.Id, sid)
	}
}

// announceStreamChanged tells every other active node, in the background
// only, that stream sid's status changed here. The push runner calls it for
// the status it writes itself (a recovery or key pause, its end, a disable),
// so a peer's copy of the stream follows without waiting for its periodic
// sync. Nothing waits for an ack.
func (r *router) announceStreamChanged(sid string) {
	if r.coordinator == nil || r.ctx == nil || r.ctx.Err() != nil {
		return
	}
	go func() {
		nodes, err := r.coordinator.GetActiveNodes()
		if err != nil {
			eventLogger.Warn("ROUTER: cannot list peers to announce a status change; they catch up on their next sync", "sid", sid, "error", err)
			return
		}
		for _, node := range nodes {
			if node.Id != r.nodeId && node.Address != "" {
				r.notifyPeer(node.Id, sid)
			}
		}
	}()
}

// streamHolder names the node whose runner serves stream sid: the unexpired
// owner of its push-transmitter lease, else of its SSTP-client lease (a
// pair's id is its sid). It is "" when neither lease is held, or the owner
// cannot be read.
func (r *router) streamHolder(sid string) string {
	for _, resource := range []string{cluster.PushTransmitter.Resource(sid), cluster.SstpClient.Resource(sid)} {
		owner, until, _, err := r.coordinator.GetLeaseOwner(resource)
		if err != nil {
			eventLogger.Debug("ROUTER: cannot read the stream's lease owner", "sid", sid, "resource", resource, "error", err)
			continue
		}
		if owner != "" && (until.IsZero() || until.After(time.Now())) {
			return owner
		}
	}
	return ""
}

// tellHolder calls the lease holder synchronously, retrying every
// streamChangedRetryInterval until it acks or refuses, or
// streamChangedHolderWindow has passed; each call may take the rest of the
// window. It reports whether the holder is settled: acked, or refused (which
// no retry can fix). A holder that never acks is logged and left to the
// background notifier.
func (r *router) tellHolder(node model.ClusterNode, sid string) bool {
	deadline := time.Now().Add(streamChangedHolderWindow)
	retry := time.NewTimer(streamChangedRetryInterval)
	defer retry.Stop()
	for {
		done, err := r.callStreamChanged(node.Address, sid, time.Until(deadline))
		if done {
			return true
		}
		if time.Until(deadline) < streamChangedRetryInterval {
			eventLogger.Warn("ROUTER: the stream's lease holder did not acknowledge stream-changed; telling it in the background",
				"sid", sid, "node", node.Id, "window", streamChangedHolderWindow, "error", err)
			return false
		}
		retry.Reset(streamChangedRetryInterval)
		select {
		case <-r.ctx.Done():
			return false
		case <-retry.C:
		}
	}
}

// peerNotifier is the background stream-changed sender for one peer. Its
// pending set holds the streams the peer has still to be told about; a stream
// changed again before the peer acked is coalesced into one entry, since the
// peer reads the store's latest state either way. Guarded by r.notifyMu.
type peerNotifier struct {
	pending map[string]*pendingNotice
}

// pendingNotice is one stream a peer has still to be told about. since is
// when it was first queued, for the give-up, so a stream that keeps changing
// still gives up on a peer that never acks; gen counts the times it was, so an
// ack for an earlier change does not clear a later one.
type pendingNotice struct {
	since time.Time
	gen   int
}

// notifyPeer queues a stream-changed call for sid to peer id, starting the
// peer's notifier when it has none. It never blocks on the network.
func (r *router) notifyPeer(id, sid string) {
	r.notifyMu.Lock()
	defer r.notifyMu.Unlock()
	if r.ctx == nil || r.ctx.Err() != nil {
		return
	}
	if r.peerNotifiers == nil {
		r.peerNotifiers = map[string]*peerNotifier{}
	}
	n, ok := r.peerNotifiers[id]
	if !ok {
		n = &peerNotifier{pending: map[string]*pendingNotice{}}
		r.peerNotifiers[id] = n
		go r.runPeerNotifier(id, n)
	}
	if p, queued := n.pending[sid]; queued {
		p.gen++
		return
	}
	n.pending[sid] = &pendingNotice{since: time.Now()}
}

// runPeerNotifier sends peer id its pending stream-changed calls, one at a
// time. A stream leaves the set when the peer acks it, or refuses it (a 4xx
// other than 408 or 429, which no retry can fix; logged at WARN), or after
// streamChangedGiveUp without an ack (WARN). While a call fails, the notifier
// backs off from streamChangedRetryInterval, doubling up to
// streamChangedMaxBackoff. It drops everything and exits when the peer is no
// longer active, and exits when the set is empty or the router shuts down.
func (r *router) runPeerNotifier(id string, n *peerNotifier) {
	backoff := streamChangedRetryInterval
	retry := time.NewTimer(backoff)
	defer retry.Stop()
	for {
		r.notifyMu.Lock()
		if len(n.pending) == 0 {
			delete(r.peerNotifiers, id)
			r.notifyMu.Unlock()
			return
		}
		batch := make(map[string]int, len(n.pending))
		for sid, p := range n.pending {
			batch[sid] = p.gen
		}
		r.notifyMu.Unlock()

		address, active, err := r.peerAddress(id)
		if err == nil && !active {
			r.notifyMu.Lock()
			eventLogger.Debug("ROUTER: peer is no longer active; dropping its stream-changed calls", "node", id, "count", len(n.pending))
			n.pending = map[string]*pendingNotice{}
			delete(r.peerNotifiers, id)
			r.notifyMu.Unlock()
			return
		}

		failed := false
		for sid, gen := range batch {
			var done bool
			var callErr error = err
			if err == nil {
				done, callErr = r.callStreamChanged(address, sid, streamChangedTimeout)
			}
			r.notifyMu.Lock()
			p := n.pending[sid]
			switch {
			case done && p.gen == gen:
				delete(n.pending, sid)
			case done:
				// Changed again while the call was out: tell the peer again.
			case time.Since(p.since) >= streamChangedGiveUp:
				eventLogger.Warn("ROUTER: peer did not acknowledge stream-changed; it catches up on its next sync",
					"node", id, "sid", sid, "after", streamChangedGiveUp, "error", callErr)
				delete(n.pending, sid)
			default:
				failed = true
			}
			r.notifyMu.Unlock()
			if r.ctx.Err() != nil {
				return
			}
		}
		if !failed {
			backoff = streamChangedRetryInterval
			continue
		}
		retry.Reset(backoff)
		select {
		case <-r.ctx.Done():
			return
		case <-retry.C:
		}
		backoff = min(backoff*2, streamChangedMaxBackoff)
	}
}

// peerAddress reports peer id's address and whether it is still an active
// node with one. A listing error is returned, and the peer kept.
func (r *router) peerAddress(id string) (address string, active bool, err error) {
	nodes, err := r.coordinator.GetActiveNodes()
	if err != nil {
		return "", true, fmt.Errorf("cannot list active nodes: %w", err)
	}
	for _, node := range nodes {
		if node.Id == id && node.Address != "" {
			return node.Address, true, nil
		}
	}
	return "", false, nil
}

// callStreamChanged POSTs one stream-changed notification to a peer, with the
// shared-HMAC cluster bearer (SPIFFE mTLS, when configured, comes from the
// transport). done reports that the call needs no retry: the peer acked (202:
// it has reconciled the stream), or refused the call outright (a 4xx such as a
// token mismatch, which a retry cannot fix; logged here, and err says so).
// Otherwise err says why the peer has not acked, and the caller retries. The
// call is bounded by timeout.
func (r *router) callStreamChanged(address, sid string, timeout time.Duration) (done bool, err error) {
	url := strings.TrimSuffix(address, "/") + StreamChangedPath
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
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
