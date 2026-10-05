package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const claimTestSecret = "claim-test-secret"

// claimRouter is a recordingRouter that answers claims through a function.
type claimRouter struct {
	*recordingRouter
	handle func(ctx context.Context, req peer.ClaimRequest) peer.ClaimResponse
}

func (c *claimRouter) HandleWake(peer.WakeMessage) {}

func (c *claimRouter) HandleClaim(ctx context.Context, req peer.ClaimRequest) peer.ClaimResponse {
	return c.handle(ctx, req)
}

func claimPost(t *testing.T, sa *SignalsApplication, req peer.ClaimRequest, token string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	hr := httptest.NewRequest(http.MethodPost, peer.ClaimPath, bytes.NewReader(body))
	if token != "" {
		hr.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	sa.ClaimStream(w, hr)
	return w
}

func TestClaimStream_AuthAndValidation(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", claimTestSecret)
	var seen peer.ClaimRequest
	sa := &SignalsApplication{EventRouter: &claimRouter{recordingRouter: &recordingRouter{}, handle: func(_ context.Context, req peer.ClaimRequest) peer.ClaimResponse {
		seen = req
		return peer.ClaimResponse{Refs: []interfaces.PendingRef{{Jti: "j1", AckJti: "a1", EnqueuedAt: time.UnixMilli(1000)}}, MoreAvailable: true}
	}}}
	req := peer.ClaimRequest{Sid: "s1", Mode: peer.ModePoll, MaxEvents: 3, ClientId: "node-b"}

	t.Run("no token is 401", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, claimPost(t, sa, req, "").Code)
	})
	t.Run("token for another mode is 401", func(t *testing.T) {
		w := claimPost(t, sa, req, authSupport.GenerateClusterToken(claimTestSecret, "s1", peer.ModeSstpServer))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("wrong secret is 401", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, claimPost(t, sa, req, authSupport.GenerateClusterToken("other", "s1", peer.ModePoll)).Code)
	})
	t.Run("bad mode is 400", func(t *testing.T) {
		bad := req
		bad.Mode = peer.ModePush
		assert.Equal(t, http.StatusBadRequest, claimPost(t, sa, bad, authSupport.GenerateClusterToken(claimTestSecret, "s1", peer.ModePush)).Code)
	})
	t.Run("missing sid is 400", func(t *testing.T) {
		bad := req
		bad.Sid = ""
		assert.Equal(t, http.StatusBadRequest, claimPost(t, sa, bad, authSupport.GenerateClusterToken(claimTestSecret, "", peer.ModePoll)).Code)
	})
	t.Run("bad json is 400", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, peer.ClaimPath, bytes.NewReader([]byte("{")))
		w := httptest.NewRecorder()
		sa.ClaimStream(w, hr)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("valid claim reaches the router", func(t *testing.T) {
		w := claimPost(t, sa, req, authSupport.GenerateClusterToken(claimTestSecret, "s1", peer.ModePoll))
		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, req, seen)
		var resp peer.ClaimResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Len(t, resp.Refs, 1)
		assert.Equal(t, "a1", resp.Refs[0].AckJti)
		assert.True(t, resp.MoreAvailable)
	})
}

// A router without a claim handler answers NotOwner.
func TestClaimStream_RouterWithoutHandlerIsNotOwner(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", claimTestSecret)
	sa := &SignalsApplication{EventRouter: &recordingRouter{}}
	w := claimPost(t, sa, peer.ClaimRequest{Sid: "s1", Mode: peer.ModeSstpServer}, authSupport.GenerateClusterToken(claimTestSecret, "s1", peer.ModeSstpServer))
	require.Equal(t, http.StatusOK, w.Code)
	var resp peer.ClaimResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.NotOwner)
}

// Cancelling the caller's claim ends the /_cluster/claim handler's request
// context: the HTTP adapter's claim, over a real listener, into a handler that
// blocks until its context ends.
func TestClaimStream_CallerCancelEndsHandlerContext(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", claimTestSecret)
	entered := make(chan struct{})
	ended := make(chan struct{})
	sa := &SignalsApplication{EventRouter: &claimRouter{recordingRouter: &recordingRouter{}, handle: func(ctx context.Context, _ peer.ClaimRequest) peer.ClaimResponse {
		close(entered)
		<-ctx.Done()
		close(ended)
		return peer.ClaimResponse{}
	}}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+peer.ClaimPath, sa.ClaimStream)
	owner := httptest.NewServer(mux)
	defer owner.Close()

	coord := &oneShotCoordinator{}
	tr := peer.NewHTTP(&addrCoordinator{oneShotCoordinator: coord, nodes: map[string]string{"owner": owner.URL}}, owner.Client(), claimTestSecret, "caller")
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := tr.Claim(ctx, "owner", peer.ClaimRequest{Sid: "s1", Mode: peer.ModePoll, WaitMs: 60000})
		errc <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the claim never reached the handler")
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler's request context did not end when the caller cancelled")
	}
	assert.Error(t, <-errc)
}

// addrCoordinator resolves node addresses from a map.
type addrCoordinator struct {
	*oneShotCoordinator
	nodes map[string]string
}

func (a *addrCoordinator) GetNode(id string) (*model.ClusterNode, error) {
	addr, ok := a.nodes[id]
	if !ok {
		return nil, nil
	}
	return &model.ClusterNode{Id: id, Address: addr}, nil
}

// The router the application builds sends wakes over the HTTP PeerTransport:
// a filter-change wake for a push stream whose lease node-b holds arrives at
// node-b's /_cluster/wake-transmitter as a WakeMessage body.
func TestApplicationRouter_WakeReachesPeerOverHTTP(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", claimTestSecret)
	t.Setenv("I2SIG_CLUSTER_NODE_ID", "node-a")
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	require.Nil(t, testPeerTransportFor, "production wiring: no injected transport")

	type hit struct {
		path string
		msg  peer.WakeMessage
		ok   bool
	}
	got := make(chan hit, 4)
	nodeB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m peer.WakeMessage
		_ = json.NewDecoder(r.Body).Decode(&m)
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		got <- hit{r.URL.Path, m, authSupport.ValidateClusterToken(claimTestSecret, tok, m.Sid, m.Mode, 30*time.Second)}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer nodeB.Close()

	p, err := dbProviders.OpenPersistence("memorydb:", "app_router_peer_http")
	require.NoError(t, err)
	sa := NewApplication(p, "http://127.0.0.1:0/")
	t.Cleanup(sa.Shutdown)
	require.NotNil(t, sa.EventRouter)

	const sid = "s-358-app"
	now := time.Now().UTC()
	require.NoError(t, p.Coordinator.RegisterNode(model.ClusterNode{Id: "node-b", Address: nodeB.URL, StartedAt: now, LastSeenAt: now}))
	acquired, _, err := p.Coordinator.TryAcquireOrRenewLease(cluster.PushTransmitterResource(sid), "node-b", time.Minute)
	require.NoError(t, err)
	require.True(t, acquired)

	sa.EventRouter.NotifySubjectFilterChange(sid)

	select {
	case h := <-got:
		assert.Equal(t, peer.WakeTransmitterPath, h.path)
		assert.Equal(t, peer.WakeMessage{Sid: sid, Mode: peer.ModePush, Reason: eventRouter.ReasonFilterChange}, h.msg)
		assert.True(t, h.ok, "the wake carries a valid cluster token")
	case <-time.After(5 * time.Second):
		t.Fatal("the wake never reached node-b's /_cluster/wake-transmitter")
	}
}
