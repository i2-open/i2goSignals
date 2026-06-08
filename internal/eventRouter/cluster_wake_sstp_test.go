package eventRouter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chanClosed reports whether ch is closed within d. The SSTP buffers signal a
// wake-up by closing (and replacing) their notifier channel, so a held long-poll
// selecting on WakeupCh() returns immediately (PRD #154 Q11.1, Q11.2).
func chanClosed(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// TestWakeSstpClient_WakesClientBuffer verifies that the local WakeSstpClient
// router method wakes the pair's SSTP-client outbound buffer so a runner waiting
// on the buffer drains the pending event into the next outbound cycle (Q11.2).
func TestWakeSstpClient_WakesClientBuffer(t *testing.T) {
	h := newTestRouter(t)
	pairId := "pair-wake-client"
	buf := buffer.CreateEventPollBuffer(nil, 1, 1)
	h.router.mu.Lock()
	h.router.sstpBuffers[pairId] = buf
	h.router.mu.Unlock()

	wakeCh := buf.WakeupCh()
	h.router.WakeSstpClient(pairId)

	assert.True(t, chanClosed(wakeCh, time.Second),
		"WakeSstpClient must wake the pair's client outbound buffer")
}

// TestWakeSstpServer_WakesServerBuffer verifies that the local WakeSstpServer
// router method wakes the pair's SSTP-server long-poll buffer so a held long-poll
// returns the event immediately (Q11.1).
func TestWakeSstpServer_WakesServerBuffer(t *testing.T) {
	h := newTestRouter(t)
	txSid := "sstp-tx-wake-server"
	buf := h.router.sstpServerBufferFor(txSid)

	wakeCh := buf.WakeupCh()
	h.router.WakeSstpServer(txSid)

	assert.True(t, chanClosed(wakeCh, time.Second),
		"WakeSstpServer must wake the pair's server long-poll buffer")
}

// TestWakeSstp_UnknownTargetIsNoOp verifies idempotency/safety: a wake for a pair
// with no resident buffer is a silent no-op rather than a panic, so duplicate or
// stale cluster wake-ups are harmless (issue #167 idempotency).
func TestWakeSstp_UnknownTargetIsNoOp(t *testing.T) {
	h := newTestRouter(t)
	require.NotPanics(t, func() {
		h.router.WakeSstpClient("no-such-pair")
		h.router.WakeSstpServer("no-such-tx")
	})
}

// capturedSstpWake records one inbound /_cluster/wake-sstp-* request observed by a
// stub peer node.
type capturedSstpWake struct {
	path string
	body map[string]string
	auth string
}

// stubWakePeer starts an httptest server that records every inbound wake-sstp
// request onto the returned channel, replying 202.
func stubWakePeer(t *testing.T, sink chan capturedSstpWake) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		sink <- capturedSstpWake{path: r.URL.Path, body: body, auth: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sstpClientPairForMatch builds an SSTP-initiator pair record whose outbound
// (transmit) side matches account-disabled events from the default test issuer.
func sstpClientPairForMatch(txSid, pairId string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:              txSid,
			Iss:             dupTestIssuer,
			Aud:             []string{"https://receiver.example.com"},
			EventsDelivered: []string{typeAcctDisabled},
			RouteMode:       model.RouteModeForward,
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:        model.SstpRoleInitiator,
			EndpointUrl: "https://peer.example.com/sstp/" + pairId,
		},
	}
}

// TestHandleEvent_BroadcastsWakeSstpClientToRemoteOwner verifies issue #167: when
// HandleEvent matches an outbound event against an SSTP-client pair whose
// sstp-client lease is held by a different node, it broadcasts
// POST /_cluster/wake-sstp-client to that node with the existing cluster auth
// token (Q11.2).
func TestHandleEvent_BroadcastsWakeSstpClientToRemoteOwner(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	s := setupDedupRouterPollStream(t) // gives a resolvable inbound stream
	r := s.h.router

	pairId := "pair-remote-owner"
	txSid := "sstp-tx-remote"
	pair := sstpClientPairForMatch(txSid, pairId)

	r.mu.Lock()
	r.sstpClientStreams[pairId] = *pair
	r.sstpBuffers[pairId] = buffer.CreateEventPollBuffer(nil, 1, 1)
	r.mu.Unlock()

	wakes := make(chan capturedSstpWake, 4)
	peer := stubWakePeer(t, wakes)
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-B", Address: peer.URL, LastSeenAt: time.Now().UTC()}))
	resource := fmt.Sprintf("sstp-client:%s", pairId)
	acquired, _, err := r.coordinator.TryAcquireOrRenewLease(resource, "node-B", 30*time.Second)
	require.NoError(t, err)
	require.True(t, acquired)

	token := newRiscToken("jti-wake-client", dupTestIssuer, s.audience)
	require.NoError(t, r.HandleEvent(token, `{"raw":true}`, s.streamID))

	got := waitForWake(t, wakes, "/_cluster/wake-sstp-client")
	assert.Equal(t, pairId, got.body["sid"], "the wake must target the pair")
	require.True(t, len(got.auth) > 7 && got.auth[:7] == "Bearer ",
		"the wake must reuse the cluster bearer-token scheme")
}

// TestHandleEvent_BroadcastsWakeSstpServerToActiveNodes verifies issue #167: when
// HandleEvent matches an outbound event against an SSTP-server pair, it broadcasts
// POST /_cluster/wake-sstp-server to the active cluster nodes so a held long-poll
// returns the event (Q11.1).
func TestHandleEvent_BroadcastsWakeSstpServerToActiveNodes(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	s := setupDedupRouterPollStream(t)
	r := s.h.router

	pairId := "pair-server-bcast"
	txSid := "sstp-tx-server-bcast"
	pair := sstpClientPairForMatch(txSid, pairId)
	pair.SstpMethod.Role = model.SstpRoleResponder // server (responder) side

	r.mu.Lock()
	r.sstpServerStreams[txSid] = *pair
	r.mu.Unlock()

	wakes := make(chan capturedSstpWake, 4)
	peer := stubWakePeer(t, wakes)
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-B", Address: peer.URL, LastSeenAt: time.Now().UTC()}))

	token := newRiscToken("jti-wake-server", dupTestIssuer, s.audience)
	require.NoError(t, r.HandleEvent(token, `{"raw":true}`, s.streamID))

	got := waitForWake(t, wakes, "/_cluster/wake-sstp-server")
	assert.Equal(t, txSid, got.body["sid"], "the wake must target the pair's tx side")
}

// waitForWake blocks until a wake on the given path is observed, failing the test
// on timeout. Other-path wakes are skipped so a test asserting on one route is not
// tripped by the other.
func waitForWake(t *testing.T, ch chan capturedSstpWake, path string) capturedSstpWake {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case got := <-ch:
			if got.path == path {
				return got
			}
		case <-deadline:
			t.Fatalf("expected a wake on %s within timeout", path)
			return capturedSstpWake{}
		}
	}
}
