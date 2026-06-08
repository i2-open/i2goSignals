package eventRouter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
)

const (
	// sstpWakeClientMode / sstpWakeServerMode are the "mode" component of the
	// cluster HMAC token (and of the request body) for the two SSTP wake-up
	// routes. Kept distinct from the push/poll modes so a token minted for one
	// route never validates against another.
	sstpWakeClientMode = "sstp-client"
	sstpWakeServerMode = "sstp-server"

	sstpWakeClientPath = "/_cluster/wake-sstp-client"
	sstpWakeServerPath = "/_cluster/wake-sstp-server"
)

// broadcastSstpClientWake sends POST /_cluster/wake-sstp-client to every active
// cluster node (except this one) so the sstp-client:<pairId> lease owner drains a
// pending outbound event into the next outbound cycle (Q11.2). Broadcast (not
// point-to-point) is acceptable for the current cluster size, and is idempotent on
// the receiving side.
func (r *router) broadcastSstpClientWake(pairId string) {
	r.broadcastSstpWake(sstpWakeClientPath, sstpWakeClientMode, pairId)
}

// broadcastSstpServerWake sends POST /_cluster/wake-sstp-server to every active
// cluster node (except this one) so a long-poll held on the receiver side returns
// the outbound event immediately (Q11.1). The SSTP-server side takes no lease, so
// any node may hold the long-poll — hence the broadcast.
func (r *router) broadcastSstpServerWake(txSid string) {
	r.broadcastSstpWake(sstpWakeServerPath, sstpWakeServerMode, txSid)
}

// broadcastSstpWake fans a wake-up to all active cluster nodes other than the
// local node. The id is the pair's PairId (client) or tx-side SID (server); mode
// distinguishes the two routes for the cluster auth token and for coalescing on
// the receiver.
func (r *router) broadcastSstpWake(path, mode, id string) {
	// Coalesce locally so a burst of outbound events for the same pair does not
	// fan out a storm of identical broadcasts within the window.
	key := path + ":" + id
	r.outboundWakesMu.Lock()
	lastWake, exists := r.recentOutboundWakes[key]
	if exists && time.Since(lastWake) < 250*time.Millisecond {
		r.outboundWakesMu.Unlock()
		return
	}
	r.recentOutboundWakes[key] = time.Now()
	r.outboundWakesMu.Unlock()

	nodes, err := r.coordinator.GetActiveNodes()
	if err != nil {
		eventLogger.Error("ROUTER: error listing active nodes for SSTP wake-up", "path", path, "error", err)
		return
	}
	for _, node := range nodes {
		if node.Id == r.nodeId || node.Address == "" {
			continue
		}
		r.callSstpWakeupAPI(node.Address, path, mode, id)
	}
}

// callSstpWakeupAPI POSTs a single SSTP wake-up to one peer's address, carrying the
// shared-HMAC cluster bearer token (SPIFFE mTLS, when configured, is supplied by
// the transport). Mirrors callWakeupAPI.
func (r *router) callSstpWakeupAPI(address, path, mode, id string) {
	url := strings.TrimSuffix(address, "/") + path

	reqBody, _ := json.Marshal(map[string]string{"sid": id, "mode": mode})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		eventLogger.Error("ROUTER: error creating SSTP wake-up request", "url", url, "error", err)
		return
	}

	token := authSupport.GenerateClusterToken(r.clusterSecret, id, mode)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		eventLogger.Error("ROUTER: SSTP wake-up call failed", "url", url, "error", err)
		return
	}
	defer httpSupport.HandleRespClose(resp)

	if resp.StatusCode != http.StatusAccepted {
		eventLogger.Warn("ROUTER: SSTP wake-up call rejected", "url", url, "status", resp.Status)
	} else {
		eventLogger.Debug("ROUTER: SSTP wake-up call successful", "url", url, "id", id)
	}
}

// SSTP cluster wake-up local handlers (PRD #154 slice 10, issue #167).
//
// These methods wake the in-memory SSTP buffers of the local node in response to
// an inbound /_cluster/wake-sstp-client or /_cluster/wake-sstp-server call from a
// peer. They are the local-side counterparts to the broadcast triggers fired by
// HandleEvent; the broadcast/auth/HTTP plumbing lives in the server layer and in
// callSstpWakeupAPI below. Both are idempotent: waking a pair with no resident
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
