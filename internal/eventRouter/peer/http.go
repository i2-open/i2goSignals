package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

var peerLog = logger.Sub("PEER")

// Cluster routes the HTTP adapter posts to.
const (
	WakeTransmitterPath = "/_cluster/wake-transmitter"
	WakeSstpClientPath  = "/_cluster/wake-sstp-client"
	WakeSstpServerPath  = "/_cluster/wake-sstp-server"
	ClaimPath           = "/_cluster/claim"
)

// claimSlack is added to a claim's WaitMs for its context deadline.
const claimSlack = 5 * time.Second

// WakePath returns the cluster route a wake of mode is posted to, or "" for
// an unknown mode.
func WakePath(mode string) string {
	switch mode {
	case ModePush, ModePoll:
		return WakeTransmitterPath
	case ModeSstpClient:
		return WakeSstpClientPath
	case ModeSstpServer:
		return WakeSstpServerPath
	}
	return ""
}

// wireRef is one reference of a claim answer on the wire. EnqueuedAt is Unix
// milliseconds, as on the wake.
type wireRef struct {
	Jti        string `json:"jti"`
	AckJti     string `json:"ackJti"`
	EnqueuedAt int64  `json:"enqueuedAt"`
}

type wireClaimResponse struct {
	Refs          []wireRef `json:"refs"`
	MoreAvailable bool      `json:"moreAvailable"`
	NotOwner      bool      `json:"notOwner"`
}

// MarshalJSON writes the /_cluster/claim answer body.
func (r ClaimResponse) MarshalJSON() ([]byte, error) {
	w := wireClaimResponse{Refs: make([]wireRef, 0, len(r.Refs)), MoreAvailable: r.MoreAvailable, NotOwner: r.NotOwner}
	for _, ref := range r.Refs {
		var ms int64
		if !ref.EnqueuedAt.IsZero() {
			ms = ref.EnqueuedAt.UnixMilli()
		}
		w.Refs = append(w.Refs, wireRef{Jti: ref.Jti, AckJti: ref.AckJti, EnqueuedAt: ms})
	}
	return json.Marshal(w)
}

// UnmarshalJSON reads the /_cluster/claim answer body.
func (r *ClaimResponse) UnmarshalJSON(b []byte) error {
	var w wireClaimResponse
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*r = ClaimResponse{MoreAvailable: w.MoreAvailable, NotOwner: w.NotOwner}
	if len(w.Refs) > 0 {
		r.Refs = make([]interfaces.PendingRef, 0, len(w.Refs))
	}
	for _, ref := range w.Refs {
		var at time.Time
		if ref.EnqueuedAt != 0 {
			at = time.UnixMilli(ref.EnqueuedAt)
		}
		r.Refs = append(r.Refs, interfaces.PendingRef{Jti: ref.Jti, AckJti: ref.AckJti, EnqueuedAt: at})
	}
	return nil
}

// httpTransport is the production adapter: it posts to a node's address
// (coordinator.GetNode) with the cluster bearer token over (sid, mode).
// SPIFFE mTLS, when configured, comes from the client's transport.
type httpTransport struct {
	coordinator   cluster.ClusterCoordinator
	client        *http.Client // wakes; carries the router's short timeout
	claimClient   *http.Client // claims; same transport, no client timeout
	clusterSecret string
	self          string
}

// NewHTTP returns the HTTP adapter. Wakes are sent on client; claims on a
// second client that shares client.Transport and has no client timeout, each
// call bounded by a context deadline of WaitMs plus 5 seconds.
func NewHTTP(coordinator cluster.ClusterCoordinator, client *http.Client, clusterSecret string, selfNodeId string) PeerTransport {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &httpTransport{
		coordinator:   coordinator,
		client:        client,
		claimClient:   &http.Client{Transport: client.Transport},
		clusterSecret: clusterSecret,
		self:          selfNodeId,
	}
}

func (t *httpTransport) nodeAddress(nodeId string) (string, error) {
	if t.coordinator == nil {
		return "", fmt.Errorf("%w: no coordinator", ErrPeerUnreachable)
	}
	node, err := t.coordinator.GetNode(nodeId)
	if err != nil || node == nil {
		return "", fmt.Errorf("%w: node %s not found: %v", ErrPeerUnreachable, nodeId, err)
	}
	if node.Address == "" {
		return "", fmt.Errorf("%w: node %s has no address", ErrPeerUnreachable, nodeId)
	}
	return node.Address, nil
}

func (t *httpTransport) Wake(ctx context.Context, ownerNode string, msg WakeMessage) error {
	path := WakePath(msg.Mode)
	if path == "" {
		return fmt.Errorf("peer: unknown wake mode %q", msg.Mode)
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if ownerNode != "" {
		address, err := t.nodeAddress(ownerNode)
		if err != nil {
			return err
		}
		return t.postWake(ctx, address, path, msg, body)
	}
	if t.coordinator == nil {
		return fmt.Errorf("%w: no coordinator", ErrPeerUnreachable)
	}
	nodes, err := t.coordinator.GetActiveNodes()
	if err != nil {
		return fmt.Errorf("peer: listing active nodes: %w", err)
	}
	var errs []error
	for _, node := range nodes {
		if node.Id == t.self || node.Address == "" {
			continue
		}
		if err := t.postWake(ctx, node.Address, path, msg, body); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *httpTransport) postWake(ctx context.Context, address, path string, msg WakeMessage, body []byte) error {
	url := strings.TrimSuffix(address, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+authSupport.GenerateClusterToken(t.clusterSecret, msg.Sid, msg.Mode))
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrPeerUnreachable, url, err)
	}
	defer httpSupport.HandleRespClose(resp)
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("peer: wake rejected by %s: %s", url, resp.Status)
	}
	peerLog.Debug("wake delivered", "url", url, "sid", msg.Sid, "mode", msg.Mode)
	return nil
}

func (t *httpTransport) Claim(ctx context.Context, ownerNode string, req ClaimRequest) (ClaimResponse, error) {
	address, err := t.nodeAddress(ownerNode)
	if err != nil {
		return ClaimResponse{}, err
	}
	wait := claimSlack
	if !req.ReturnImmediately && req.WaitMs > 0 {
		wait += time.Duration(req.WaitMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	body, err := json.Marshal(req)
	if err != nil {
		return ClaimResponse{}, err
	}
	url := strings.TrimSuffix(address, "/") + ClaimPath
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ClaimResponse{}, err
	}
	hreq.Header.Set("Authorization", "Bearer "+authSupport.GenerateClusterToken(t.clusterSecret, req.Sid, req.Mode))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := t.claimClient.Do(hreq)
	if err != nil {
		return ClaimResponse{}, fmt.Errorf("%w: %s: %v", ErrPeerUnreachable, url, err)
	}
	defer httpSupport.HandleRespClose(resp)
	if resp.StatusCode != http.StatusOK {
		return ClaimResponse{}, fmt.Errorf("peer: claim rejected by %s: %s", url, resp.Status)
	}
	var out ClaimResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ClaimResponse{}, fmt.Errorf("peer: decoding claim answer from %s: %w", url, err)
	}
	return out, nil
}
