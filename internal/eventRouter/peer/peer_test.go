package peer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "peer-test-secret"

// fakeCoordinator answers node lookups from a fixed table.
type fakeCoordinator struct {
	cluster.ClusterCoordinator
	nodes []model.ClusterNode
}

func (f *fakeCoordinator) GetNode(id string) (*model.ClusterNode, error) {
	for i := range f.nodes {
		if f.nodes[i].Id == id {
			return &f.nodes[i], nil
		}
	}
	return nil, nil
}

func (f *fakeCoordinator) GetActiveNodes() ([]model.ClusterNode, error) { return f.nodes, nil }

func validBearer(r *http.Request, sid, mode string) bool {
	h := r.Header.Get("Authorization")
	return strings.HasPrefix(h, "Bearer ") &&
		authSupport.ValidateClusterToken(testSecret, strings.TrimPrefix(h, "Bearer "), sid, mode, 30*time.Second)
}

func TestHTTPClaim_RoundTripWithRefs(t *testing.T) {
	enq := time.UnixMilli(1759570000000)
	var got ClaimRequest
	var rawAnswer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, ClaimPath, r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		if !validBearer(r, got.Sid, got.Mode) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := json.Marshal(ClaimResponse{
			Refs:          []interfaces.PendingRef{{Jti: "j1", AckJti: "a1", EnqueuedAt: enq}, {Jti: "j2", AckJti: "j2", EnqueuedAt: enq}},
			MoreAvailable: true,
		})
		rawAnswer = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	tr := NewHTTP(&fakeCoordinator{nodes: []model.ClusterNode{{Id: "b", Address: srv.URL + "/"}}}, srv.Client(), testSecret, "a")
	req := ClaimRequest{Sid: "s1", Mode: ModePoll, MaxEvents: 10, WaitMs: 100, AckJtis: []string{"x"}, SetErrJtis: []string{"y"}, ClientId: "a"}
	resp, err := tr.Claim(context.Background(), "b", req)
	require.NoError(t, err)
	assert.Equal(t, req, got, "the request arrives as sent")
	assert.True(t, resp.MoreAvailable)
	assert.False(t, resp.NotOwner)
	require.Len(t, resp.Refs, 2)
	assert.Equal(t, "j1", resp.Refs[0].Jti)
	assert.Equal(t, "a1", resp.Refs[0].AckJti)
	assert.True(t, enq.Equal(resp.Refs[0].EnqueuedAt))
	assert.JSONEq(t, `{"refs":[{"jti":"j1","ackJti":"a1","enqueuedAt":1759570000000},{"jti":"j2","ackJti":"j2","enqueuedAt":1759570000000}],"moreAvailable":true,"notOwner":false}`, rawAnswer)
}

func TestHTTPClaim_InvalidTokenIs401Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ClaimRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !validBearer(r, req.Sid, req.Mode) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	coord := &fakeCoordinator{nodes: []model.ClusterNode{{Id: "b", Address: srv.URL}}}

	_, err := NewHTTP(coord, srv.Client(), "wrong-secret", "a").Claim(context.Background(), "b", ClaimRequest{Sid: "s1", Mode: ModePoll})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")

	_, err = NewHTTP(coord, srv.Client(), testSecret, "a").Claim(context.Background(), "b", ClaimRequest{Sid: "s1", Mode: ModePoll})
	require.NoError(t, err, "the right secret is accepted")
}

func TestHTTPClaim_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	tr := NewHTTP(&fakeCoordinator{nodes: []model.ClusterNode{{Id: "b", Address: srv.URL}}}, srv.Client(), testSecret, "a")
	_, err := tr.Claim(context.Background(), "b", ClaimRequest{Sid: "s1", Mode: ModePoll})
	require.Error(t, err)
}

func TestHTTPClaim_UnknownNodeIsUnreachable(t *testing.T) {
	tr := NewHTTP(&fakeCoordinator{}, nil, testSecret, "a")
	_, err := tr.Claim(context.Background(), "b", ClaimRequest{Sid: "s1", Mode: ModePoll})
	assert.ErrorIs(t, err, ErrPeerUnreachable)
}

// The claim client has no client timeout: a claim waiting longer than the
// wake client's 5 second timeout is bounded by WaitMs plus 5 seconds instead.
func TestHTTPClaim_NoClientTimeoutSharesTransport(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}}
	tr := NewHTTP(&fakeCoordinator{}, client, testSecret, "a").(*httpTransport)
	assert.Zero(t, tr.claimClient.Timeout)
	assert.Same(t, client.Transport, tr.claimClient.Transport)
}

func TestHTTPClaim_CallerCancelEndsHandlerContext(t *testing.T) {
	ended := make(chan struct{})
	entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server watches for a closed connection only once the body is read.
		_, _ = io.ReadAll(r.Body)
		close(entered)
		<-r.Context().Done()
		close(ended)
	}))
	defer srv.Close()
	tr := NewHTTP(&fakeCoordinator{nodes: []model.ClusterNode{{Id: "b", Address: srv.URL}}}, srv.Client(), testSecret, "a")

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := tr.Claim(ctx, "b", ClaimRequest{Sid: "s1", Mode: ModePoll, WaitMs: 60000})
		errc <- err
	}()
	<-entered
	cancel()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler's request context did not end when the caller cancelled")
	}
	require.Error(t, <-errc)
}

func TestHTTPWake_MarshalsWakeMessageToModeRoute(t *testing.T) {
	type hit struct {
		path string
		body WakeMessage
		ok   bool
	}
	var mu sync.Mutex
	var hits []hit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m WakeMessage
		require.NoError(t, json.Unmarshal(raw, &m))
		mu.Lock()
		hits = append(hits, hit{r.URL.Path, m, validBearer(r, m.Sid, m.Mode)})
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	coord := &fakeCoordinator{nodes: []model.ClusterNode{{Id: "a", Address: srv.URL}, {Id: "b", Address: srv.URL}, {Id: "c", Address: srv.URL}}}
	tr := NewHTTP(coord, srv.Client(), testSecret, "a")

	require.NoError(t, tr.Wake(context.Background(), "b", WakeMessage{Sid: "s1", Mode: ModePush, Reason: "filter-change"}))
	require.NoError(t, tr.Wake(context.Background(), "", WakeMessage{Sid: "p1", Mode: ModeSstpServer}))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, hits, 3, "one owner wake plus a broadcast to the two other nodes")
	assert.Equal(t, WakeTransmitterPath, hits[0].path)
	assert.Equal(t, WakeMessage{Sid: "s1", Mode: ModePush, Reason: "filter-change"}, hits[0].body)
	for _, h := range hits {
		assert.True(t, h.ok, "every wake carries a valid cluster token")
	}
	assert.Equal(t, WakeSstpServerPath, hits[1].path)
	assert.Equal(t, WakeSstpServerPath, hits[2].path)

	assert.Error(t, tr.Wake(context.Background(), "b", WakeMessage{Sid: "s1", Mode: "bogus"}))
}

func TestHTTPWake_RejectedIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	tr := NewHTTP(&fakeCoordinator{nodes: []model.ClusterNode{{Id: "b", Address: srv.URL}}}, srv.Client(), testSecret, "a")
	assert.Error(t, tr.Wake(context.Background(), "b", WakeMessage{Sid: "s1", Mode: ModePush}))
}

type recHandler struct {
	mu    sync.Mutex
	wakes []WakeMessage
	ctx   context.Context
}

func (h *recHandler) HandleWake(msg WakeMessage) {
	h.mu.Lock()
	h.wakes = append(h.wakes, msg)
	h.mu.Unlock()
}

func (h *recHandler) HandleClaim(ctx context.Context, req ClaimRequest) ClaimResponse {
	h.ctx = ctx
	return ClaimResponse{Refs: []interfaces.PendingRef{{Jti: req.Sid}}}
}

func TestInProcess_RegisteredAndUnregistered(t *testing.T) {
	reg := NewInProcess()
	a, b := &recHandler{}, &recHandler{}
	reg.Register("a", a)
	reg.Register("b", b)
	tr := reg.For("a")

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "caller")
	resp, err := tr.Claim(ctx, "b", ClaimRequest{Sid: "s1", Mode: ModePoll})
	require.NoError(t, err)
	require.Len(t, resp.Refs, 1)
	assert.Equal(t, "s1", resp.Refs[0].Jti)
	assert.Equal(t, "caller", b.ctx.Value(ctxKey{}), "Claim runs with the caller's context")

	require.NoError(t, tr.Wake(context.Background(), "b", WakeMessage{Sid: "s1", Mode: ModePush}))
	require.NoError(t, tr.Wake(context.Background(), "", WakeMessage{Sid: "s2", Mode: ModeSstpServer}))
	assert.Len(t, b.wakes, 2)
	assert.Empty(t, a.wakes, "a broadcast skips the sender")

	reg.Unregister("b")
	_, err = tr.Claim(ctx, "b", ClaimRequest{Sid: "s1", Mode: ModePoll})
	assert.True(t, errors.Is(err, ErrPeerUnreachable))
	assert.ErrorIs(t, tr.Wake(context.Background(), "b", WakeMessage{Sid: "s1", Mode: ModePush}), ErrPeerUnreachable)
	_, err = tr.Claim(ctx, "never", ClaimRequest{Sid: "s1", Mode: ModePoll})
	assert.ErrorIs(t, err, ErrPeerUnreachable)
}
