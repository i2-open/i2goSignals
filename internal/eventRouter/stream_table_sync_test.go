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
	resource := cluster.PushTransmitter.Resource(sid)
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

// countingPeer is a stub peer that answers stream-changed calls with the
// status status() returns, counting the calls.
func countingPeer(t *testing.T, status func(call int32) int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status(calls.Add(1)))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// holdLease makes node the stream's push-transmitter lease holder.
func holdLease(t *testing.T, r *router, sid, node string) {
	t.Helper()
	acquired, _, _, err := r.coordinator.TryAcquireOrRenewLease(cluster.PushTransmitter.Resource(sid), node, 30*time.Second)
	require.NoError(t, err)
	require.True(t, acquired)
}

// A stream created, updated, re-statused or deleted on this node is announced
// to every other active node on POST /_cluster/stream-changed with the
// cluster bearer token, so the peer reconciles its stream table at once
// instead of on its 40s sync (#349, #350). This node and address-less nodes
// are skipped. With no lease holder the broadcast returns at once and the
// peers are told in the background.
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

	start := time.Now()
	r.BroadcastStreamChanged("sid-new")
	assert.Less(t, time.Since(start), 500*time.Millisecond, "with no lease holder nothing is waited for")

	require.Eventually(t, func() bool { return len(calls) == 2 }, 5*time.Second, 10*time.Millisecond,
		"one call per other node with an address")
	for i := 0; i < 2; i++ {
		got := <-calls
		assert.Equal(t, "/_cluster/stream-changed", got.path)
		assert.Equal(t, "sid-new", got.body["sid"])
		require.True(t, len(got.auth) > 7)
		assert.True(t, authSupport.ValidateClusterToken("test-secret", got.auth[7:], "sid-new", "stream-changed", 30*time.Second))
	}
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, calls, "an acked peer is not called again")
}

// The broadcast waits only for the stream's lease holder. A non-holder whose
// calls fail does not delay it, and is told in the background once it
// recovers; a peer that acked is not called again.
func TestBroadcastStreamChanged_WaitsOnlyForTheHolder(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	h := newRestartHarness(t, newHoldingReceiver())
	r := h.router

	holder, holderCalls := countingPeer(t, func(int32) int { return http.StatusAccepted })
	flaky, flakyCalls := countingPeer(t, func(call int32) int {
		if call <= 2 {
			return http.StatusServiceUnavailable
		}
		return http.StatusAccepted
	})
	now := time.Now().UTC()
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-holder", Address: holder.URL, LastSeenAt: now}))
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-flaky", Address: flaky.URL, LastSeenAt: now}))
	holdLease(t, r, "sid-held", "node-holder")

	start := time.Now()
	r.BroadcastStreamChanged("sid-held")
	assert.Less(t, time.Since(start), 500*time.Millisecond, "a failing non-holder does not delay the broadcast")
	assert.Equal(t, int32(1), holderCalls.Load(), "the holder acked before the broadcast returned")

	require.Eventually(t, func() bool { return flakyCalls.Load() == 3 }, 10*time.Second, 20*time.Millisecond,
		"the non-holder is retried in the background until it acks")
	time.Sleep(1500 * time.Millisecond)
	assert.Equal(t, int32(3), flakyCalls.Load(), "an acked peer is not called again")
	assert.Equal(t, int32(1), holderCalls.Load(), "the settled holder is not told again")
}

// A lease holder that never acks holds the broadcast for the holder window
// only; it is then left to the background notifier.
func TestBroadcastStreamChanged_UnackedHolderBoundedByWindow(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	h := newRestartHarness(t, newHoldingReceiver())
	r := h.router

	holder, holderCalls := countingPeer(t, func(int32) int { return http.StatusServiceUnavailable })
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-holder", Address: holder.URL, LastSeenAt: time.Now().UTC()}))
	holdLease(t, r, "sid-held", "node-holder")

	start := time.Now()
	r.BroadcastStreamChanged("sid-held")
	took := time.Since(start)
	assert.GreaterOrEqual(t, took, streamChangedHolderWindow-streamChangedRetryInterval)
	assert.Less(t, took, streamChangedHolderWindow+time.Second, "the broadcast returns after the holder window")
	called := holderCalls.Load()
	assert.GreaterOrEqual(t, called, int32(4), "the holder is retried every second within the window")
	require.Eventually(t, func() bool { return holderCalls.Load() > called }, 5*time.Second, 20*time.Millisecond,
		"the unacked holder is told again in the background")
}

// A peer that refuses a stream-changed call with a 4xx (a token mismatch, say)
// is not retried: no retry can fix it.
func TestBroadcastStreamChanged_RefusedPeerIsNotRetried(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	h := newRestartHarness(t, newHoldingReceiver())
	r := h.router

	srv, calls := countingPeer(t, func(int32) int { return http.StatusUnauthorized })
	require.NoError(t, r.coordinator.RegisterNode(model.ClusterNode{Id: "node-misconfigured", Address: srv.URL, LastSeenAt: time.Now().UTC()}))

	start := time.Now()
	r.BroadcastStreamChanged("sid-new")
	assert.Less(t, time.Since(start), 500*time.Millisecond, "the broadcast returns at once")

	require.Eventually(t, func() bool { return calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(streamChangedRetryInterval + 500*time.Millisecond)
	assert.Equal(t, int32(1), calls.Load(), "a refused call is not retried")
	require.Eventually(t, func() bool {
		r.notifyMu.Lock()
		defer r.notifyMu.Unlock()
		_, running := r.peerNotifiers["node-misconfigured"]
		return !running
	}, 2*time.Second, 10*time.Millisecond, "the notifier exits once nothing is pending")
}
