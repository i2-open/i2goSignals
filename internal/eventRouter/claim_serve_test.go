package eventRouter

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingTransport records the Claim calls a router sends, passing them on
// to next when it is set.
type countingTransport struct {
	next   peer.PeerTransport
	claims atomic.Int64
	mu     sync.Mutex
	sent   []peer.ClaimRequest
}

func (c *countingTransport) Wake(ctx context.Context, owner string, msg peer.WakeMessage) error {
	if c.next == nil {
		return nil
	}
	return c.next.Wake(ctx, owner, msg)
}

func (c *countingTransport) Claim(ctx context.Context, owner string, req peer.ClaimRequest) (peer.ClaimResponse, error) {
	c.claims.Add(1)
	c.mu.Lock()
	c.sent = append(c.sent, req)
	c.mu.Unlock()
	if c.next == nil {
		return peer.ClaimResponse{}, nil
	}
	return c.next.Claim(ctx, owner, req)
}

// claimPersistence opens one in-memory store for a set of claimNode routers.
func claimPersistence(t *testing.T) *dbProviders.Persistence {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "claim_serve_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})
	return persistence
}

// claimNode starts a router over persistence as cluster node nodeId.
func claimNode(t *testing.T, persistence *dbProviders.Persistence, nodeId string, servesClaims bool, coordinator cluster.ClusterCoordinator, transport peer.PeerTransport) *filterPushHarness {
	t.Helper()
	r := NewRouter(RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          coordinator,
		ServesClaims:         servesClaims,
		SubjectFilterService: persistence.SubjectFilterService,
		PeerTransport:        transport,
	}, nodeId).(*router)
	t.Cleanup(r.Shutdown)
	return &filterPushHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
		eventService:  persistence.EventService,
		subjectFilter: persistence.SubjectFilterService,
	}
}

func leaseHolder(t *testing.T, persistence *dbProviders.Persistence, resource string) string {
	t.Helper()
	owner, _, _, err := persistence.Coordinator.GetLeaseOwner(resource)
	require.NoError(t, err)
	return owner
}

// A node with ServesClaims false never takes a poll-transmitter lease nor
// builds a queue; a serving node then takes the lease and serves the rows,
// and the non-serving node names it as the owner.
func TestClaimServe_NonServingNodeTakesNoPollLease(t *testing.T) {
	persistence := claimPersistence(t)
	ingest := claimNode(t, persistence, "node-ingest", false, persistence.Coordinator, nil)
	owner := claimNode(t, persistence, "node-owner", true, persistence.Coordinator, nil)

	sid := owner.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish).StreamConfiguration.Id
	owner.addPendingEvents(t, sid, 3)
	resource := cluster.PollTransmitter.Resource(sid)

	node, self := ingest.router.resolveOwner(resource)
	assert.False(t, self)
	assert.Empty(t, node)
	assert.Empty(t, leaseHolder(t, persistence, resource), "a non-serving node takes no poll-transmitter lease")
	assert.Nil(t, ingest.router.pollBufferFor(sid), "a non-serving node builds no queue")

	node, self = owner.router.resolveOwner(resource)
	assert.True(t, self)
	assert.Equal(t, "node-owner", node)
	assert.Equal(t, "node-owner", leaseHolder(t, persistence, resource))
	sets, status := owner.poll(sid)
	assert.Equal(t, 200, status)
	assert.Len(t, sets, 3, "the lease owner serves the stored rows")

	ingest.router.leaseOwners.forget(resource)
	node, self = ingest.router.resolveOwner(resource)
	assert.False(t, self)
	assert.Equal(t, "node-owner", node, "the non-serving node names the lease owner")
}

// The SSTP-acceptor resource follows the same rule as a poll transmitter.
func TestClaimServe_NonServingNodeTakesNoSstpServerLease(t *testing.T) {
	persistence := claimPersistence(t)
	ingest := claimNode(t, persistence, "node-ingest", false, persistence.Coordinator, nil)
	resource := cluster.SstpServer.Resource("pair-no-lease")

	node, self := ingest.router.resolveOwner(resource)
	assert.False(t, self)
	assert.Empty(t, node)
	assert.Empty(t, leaseHolder(t, persistence, resource))
}

// With no coordinator every stream is this node's: no lease, no Claim.
func TestClaimServe_NoCoordinatorServesLocally(t *testing.T) {
	persistence := claimPersistence(t)
	transport := &countingTransport{}
	h := claimNode(t, persistence, "node-solo", true, nil, transport)

	sid := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish).StreamConfiguration.Id
	h.addPendingEvents(t, sid, 2)
	resource := cluster.PollTransmitter.Resource(sid)

	node, self := h.router.resolveOwner(resource)
	assert.True(t, self)
	assert.Equal(t, "node-solo", node)
	sets, status := h.poll(sid)
	assert.Equal(t, 200, status)
	assert.Len(t, sets, 2)
	assert.Empty(t, leaseHolder(t, persistence, resource), "no lease without a coordinator")
	assert.Zero(t, transport.claims.Load(), "no Claim without a coordinator")
}

// A poll that reaches a node which does not own the stream is answered by
// the owner through one Claim; only an unknown stream is a 404.
func TestClaimServe_NonOwnerPollServedThroughOneClaim(t *testing.T) {
	persistence := claimPersistence(t)
	bus := peer.NewInProcess()
	owner := claimNode(t, persistence, "node-a", true, persistence.Coordinator, bus.For("node-a"))
	viaB := &countingTransport{next: bus.For("node-b")}
	other := claimNode(t, persistence, "node-b", true, persistence.Coordinator, viaB)
	bus.Register("node-a", owner.router)
	bus.Register("node-b", other.router)

	rec := owner.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := rec.StreamConfiguration.Id
	other.router.UpdateStreamState(rec) // node-b knows the stream, as every node does
	owner.queuePollEvents(t, sid, 4)
	require.Equal(t, "node-a", leaseHolder(t, persistence, cluster.PollTransmitter.Resource(sid)))

	sets, _, status := other.router.PollStreamHandler(context.Background(), sid, model.PollParameters{
		MaxEvents: 100, ReturnImmediately: true,
	})
	assert.Equal(t, 200, status)
	assert.Len(t, sets, 4, "the owner's queue answers the non-owner's poll")
	assert.Equal(t, int64(1), viaB.claims.Load(), "one Claim per request")
	assert.Nil(t, other.router.pollBufferFor(sid), "the non-owner keeps no queue")

	_, _, status = other.router.PollStreamHandler(context.Background(), "no-such-stream", model.PollParameters{
		MaxEvents: 10, ReturnImmediately: true,
	})
	assert.Equal(t, 404, status)
}

func TestClaimServe_WaitMs(t *testing.T) {
	r := &router{pollDefaultTimeoutSecs: 30, pollMaxTimeoutSecs: 60}
	assert.Equal(t, int64(29000), r.claimWaitMs(0, false), "default wait less one second")
	assert.Equal(t, int64(4000), r.claimWaitMs(5, false))
	assert.Equal(t, int64(59000), r.claimWaitMs(600, false), "capped at the max wait")
	assert.Equal(t, int64(0), r.claimWaitMs(1, false), "never below zero")
	assert.Equal(t, int64(0), r.claimWaitMs(30, true), "returnImmediately sends no wait")
}

// blockingTransport holds every waiting Claim until release closes and
// answers a returnImmediately Claim empty at once.
type blockingTransport struct {
	countingTransport
	release chan struct{}
}

func (b *blockingTransport) Claim(ctx context.Context, owner string, req peer.ClaimRequest) (peer.ClaimResponse, error) {
	_, _ = b.countingTransport.Claim(ctx, owner, req)
	if !req.ReturnImmediately {
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return peer.ClaimResponse{}, nil
}

// With the per-owner budget used up a waiting Claim goes with
// returnImmediately and the empty answer is held for the wait plus slack.
func TestClaimServe_BudgetExhaustedSendsReturnImmediatelyAndHolds(t *testing.T) {
	transport := &blockingTransport{release: make(chan struct{})}
	r := &router{nodeId: "node-b", peers: transport, claimInflightMax: 1}
	before := testutil.ToFloat64(peerClaimBudgetExhausted)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.claimRemote(context.Background(), "node-a", peer.ClaimRequest{Sid: "s", Mode: peer.ModePoll, MaxEvents: 5, WaitMs: 5000})
	}()
	require.Eventually(t, func() bool { return r.claimInflightCounter("node-a").Load() == 1 }, 2*time.Second, 5*time.Millisecond)

	start := time.Now()
	_, err := r.claimRemote(context.Background(), "node-a", peer.ClaimRequest{Sid: "s", Mode: peer.ModePoll, MaxEvents: 5, WaitMs: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, time.Since(start), 1100*time.Millisecond, "an empty answer is held for WaitMs plus one second")
	assert.Equal(t, before+1, testutil.ToFloat64(peerClaimBudgetExhausted))

	transport.mu.Lock()
	require.Len(t, transport.sent, 2)
	second := transport.sent[1]
	transport.mu.Unlock()
	assert.True(t, second.ReturnImmediately)
	assert.Zero(t, second.WaitMs)
	assert.Equal(t, "node-b", second.ClientId)

	close(transport.release)
	<-done
	assert.Zero(t, r.claimInflightCounter("node-a").Load(), "the budget is returned")
}

func TestClaimServe_CollectorsExported(t *testing.T) {
	cs := ClaimCollectors()
	require.Len(t, cs, 2)
	peerClaimsTotal.WithLabelValues("poll", "served").Add(0)
	assert.Equal(t, 1, testutil.CollectAndCount(peerClaimsTotal, "goSignals_router_peer_claims_total"))
	assert.Equal(t, 1, testutil.CollectAndCount(peerClaimBudgetExhausted, "goSignals_router_peer_claim_budget_exhausted_total"))
}

// An SSTP request that neither acks nor asks for events (returnEvents=false)
// resolves no owner: no lease is taken and no Claim is sent. One that asks
// for events resolves the owner, which takes the acceptor lease.
func TestClaimServe_SstpReturnEventsFalseWithoutAcksMakesNoClaim(t *testing.T) {
	persistence := claimPersistence(t)
	transport := &countingTransport{}
	h := claimNode(t, persistence, "node-a", true, persistence.Coordinator, transport)

	txSid, rxSid, pairId := "claim-tx", "claim-rx", "claim-pair"
	require.NoError(t, persistence.StreamService.PersistStreamStateRecord(context.Background(), sstpServerPairState(txSid, rxSid, pairId)))
	rec, err := persistence.StreamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)
	resource := cluster.SstpServer.Resource(txSid)

	_, err = h.router.SstpServerHandler(context.Background(), rec, goSetSstp.Message{ReturnEvents: goSetSstp.BoolPtr(false)}, nil)
	require.NoError(t, err)
	assert.Empty(t, leaseHolder(t, persistence, resource), "no owner is resolved")
	assert.Zero(t, transport.claims.Load())

	_, err = h.router.SstpServerHandler(context.Background(), rec, goSetSstp.Message{ReturnImmediately: goSetSstp.BoolPtr(true)}, nil)
	require.NoError(t, err)
	assert.Equal(t, "node-a", leaseHolder(t, persistence, resource), "asking for events takes the acceptor lease")
	assert.Zero(t, transport.claims.Load(), "the owner serves itself")
}

// releaseCounter is a coordinator that only counts lease releases.
type releaseCounter struct {
	cluster.ClusterCoordinator
	released atomic.Int64
}

func (c *releaseCounter) ReleaseLeaseIfOwned(string, string) error {
	c.released.Add(1)
	return nil
}

// The request path gives a stream lease back through releaseStreamLease (a
// stream that went away under the acquire). A renewal loop that does not stop
// must not hold that request: the wait is bounded, and the release follows
// once the loop has stopped, so a late renewal cannot re-take the lease.
func TestReleaseStreamLease_BoundsTheRenewalWait(t *testing.T) {
	prev := streamLeaseReleaseWait
	streamLeaseReleaseWait = 20 * time.Millisecond
	t.Cleanup(func() { streamLeaseReleaseWait = prev })

	coord := &releaseCounter{}
	r := newBareRouter(RouterDeps{Coordinator: coord})
	r.streamLeases = map[string]*streamLease{}
	resource := cluster.PollTransmitter.Resource("s1")
	sl := &streamLease{cancel: func() {}, done: make(chan struct{})}
	r.streamLeases[resource] = sl

	returned := make(chan struct{})
	go func() {
		r.releaseStreamLease(resource)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("releaseStreamLease waited on a renewal loop that never stopped")
	}
	assert.Zero(t, coord.released.Load(), "the lease is not given back while its renewal may still re-take it")

	close(sl.done)
	require.Eventually(t, func() bool { return coord.released.Load() == 1 }, 2*time.Second, time.Millisecond,
		"the lease is given back once the renewal loop has stopped")
}
