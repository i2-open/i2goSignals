package eventRouter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// matchingSet builds an account-disabled SET that the harness's push streams
// (iss DEFAULT, aud receiver.example.com) match.
func matchingSet(n int) *goSet.SecurityEventToken {
	token := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "DEFAULT",
			Audience: jwt.ClaimStrings{"https://receiver.example.com"},
		},
		Events: map[string]interface{}{typeAcctDisabled: map[string]interface{}{}},
	}
	token.ID = fmt.Sprintf("sync-jti-%d", n)
	return token
}

// A stream deleted from the store by another node is dropped by the next
// stream-table sync: its runner stops, its lease is released at once, and later
// SETs write no pending marker for it (#350). A stream still in the store is
// kept.
func TestSyncStreamTable_DropsStreamDeletedElsewhere(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	coord := h.router.coordinator

	survivor := h.createPushStream(t, "ALL")
	victim := h.createPushStream(t, "ALL")
	sid := victim.StreamConfiguration.Id
	resource := cluster.PushTransmitterResource(sid)
	h.router.UpdateStreamState(survivor.DeepCopy())
	h.router.UpdateStreamState(victim.DeepCopy())

	// A matching SET lands a marker on the victim, and its runner takes the lease.
	require.NoError(t, h.router.HandleEvent(matchingSet(1), `{"n":1}`, survivor.StreamConfiguration.Id))
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 1 }, 5*time.Second, 5*time.Millisecond)
	waitLeaseOwner(t, coord, resource, "node-restart")
	runner := h.runnerFor(sid)
	require.NotNil(t, runner)

	// Another node deletes the stream: only the store changes.
	require.NoError(t, h.streamService.DeleteStream(context.Background(), sid))

	states, err := h.router.SyncStreamTable(context.Background())
	require.NoError(t, err)
	assert.Contains(t, states, survivor.StreamConfiguration.Id)
	assert.NotContains(t, states, sid)

	rx.release()
	waitFinished(t, runner, "the deleted stream's runner did not stop")
	owner, _, _, err := coord.GetLeaseOwner(resource)
	require.NoError(t, err)
	assert.Empty(t, owner, "the deleted stream's lease is released, not left to expire")
	assert.Nil(t, h.runnerFor(sid))
	assert.NotContains(t, h.router.StreamIds(), sid)
	assert.Contains(t, h.router.StreamIds(), survivor.StreamConfiguration.Id, "a stream still in the store is kept")

	before := h.pendingCount(sid)
	require.NoError(t, h.router.HandleEvent(matchingSet(2), `{"n":2}`, survivor.StreamConfiguration.Id))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, before, h.pendingCount(sid), "no marker is written for a dropped stream")
}

// A stream created or deleted on this node is announced to every other active
// node on POST /_cluster/stream-changed with the cluster bearer token, so the
// peer reconciles its stream table at once instead of on its 40s sync (#349,
// #350). This node and address-less nodes are skipped.
func TestBroadcastStreamChanged_TellsEveryOtherActiveNode(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	h := newRestartHarness(t, newHoldingReceiver())
	r := h.router

	calls := make(chan capturedSstpWake, 8)
	peerB := stubWakePeer(t, calls)
	peerC := stubWakePeer(t, calls)
	now := time.Now().UTC()
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: r.nodeId, Address: peerB.URL, LastSeenAt: now}))
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-B", Address: peerB.URL, LastSeenAt: now}))
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-C", Address: peerC.URL, LastSeenAt: now}))
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-D", LastSeenAt: now}))

	r.BroadcastStreamChanged("sid-new")

	require.Len(t, calls, 2, "one call per other node with an address, and the broadcast has returned")
	for i := 0; i < 2; i++ {
		got := <-calls
		assert.Equal(t, "/_cluster/stream-changed", got.path)
		assert.Equal(t, "sid-new", got.body["sid"])
		require.True(t, len(got.auth) > 7)
		assert.True(t, authSupport.ValidateClusterToken("test-secret", got.auth[7:], "sid-new", "stream-changed", 30*time.Second))
	}
}

// A peer that does not ack a stream-changed call (it could not reconcile, or
// the call failed) is retried until it does, and the broadcast returns only
// then; a peer that acked is not called again.
func TestBroadcastStreamChanged_RetriesUntilEveryPeerAcks(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	h := newRestartHarness(t, newHoldingReceiver())
	r := h.router

	peer := func(failures int32) (*httptest.Server, *atomic.Int32) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) <= failures {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}))
		t.Cleanup(srv.Close)
		return srv, &calls
	}
	flaky, flakyCalls := peer(2)
	steady, steadyCalls := peer(0)
	now := time.Now().UTC()
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-flaky", Address: flaky.URL, LastSeenAt: now}))
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-steady", Address: steady.URL, LastSeenAt: now}))

	r.BroadcastStreamChanged("sid-new")

	assert.Equal(t, int32(3), flakyCalls.Load(), "the peer is retried until it acks")
	assert.Equal(t, int32(1), steadyCalls.Load(), "a peer that acked is not called again")
}
