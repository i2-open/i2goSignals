package eventRouter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An explicit RFC 8936 "maxEvents": 0 is an acknowledgement-only poll: the
// acks are applied, nothing is claimed and no SETs come back. An absent
// maxEvents keeps the server default (#369).

// ackOnlyPoll sends an acknowledgement-only poll (explicit maxEvents 0) for
// the wire JTIs acks through r.
func ackOnlyPoll(r *router, sid string, acks []string) (map[string]string, bool, int) {
	return r.PollStreamHandler(context.Background(), sid, model.PollParameters{
		AckOnly:           true,
		ReturnImmediately: true,
		Acks:              acks,
	})
}

// defaultLongPoll is a long poll that leaves maxEvents out, timing how long
// it takes to answer.
func defaultLongPoll(r *router, sid string) (map[string]string, time.Duration) {
	start := time.Now()
	sets, _, _ := r.PollStreamHandler(context.Background(), sid, model.PollParameters{
		ReturnImmediately: false,
		TimeoutSecs:       3,
	})
	return sets, time.Since(start)
}

func TestPollAckOnly_ExplicitZeroAppliesAcksAndClaimsNothing(t *testing.T) {
	t.Setenv("I2SIG_POLL_CLAIM_TTL", "30s")
	h, _ := newPollKeyHarness(t, "1h")
	sid := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish).StreamConfiguration.Id
	h.queuePollEvents(t, sid, 4)
	buf := h.router.pollBufferFor(sid)
	require.NotNil(t, buf)

	first, _, status := h.router.PollStreamHandler(context.Background(), sid, model.PollParameters{
		MaxEvents: 1, ReturnImmediately: true,
	})
	require.Equal(t, 200, status)
	require.Len(t, first, 1)
	require.Equal(t, 1, buf.ClaimedCnt())

	sets, more, status := ackOnlyPoll(h.router, sid, keysOf(first))
	assert.Equal(t, 200, status)
	assert.Empty(t, sets, "an acknowledgement-only poll returns no SETs")
	assert.False(t, more)
	assert.Equal(t, 0, buf.ClaimedCnt(), "an acknowledgement-only poll claims nothing")
	assert.Equal(t, 3, h.pendingCount(sid), "the acks are applied")

	// An absent maxEvents still returns up to the server default.
	rest, _, status := h.router.PollStreamHandler(context.Background(), sid, model.PollParameters{ReturnImmediately: true})
	assert.Equal(t, 200, status)
	assert.Len(t, rest, 3, "a poll without maxEvents returns up to the default batch")
}

// An ack-only request with no acks is still answered empty and claims nothing.
func TestPollAckOnly_WithoutAcksReturnsEmpty(t *testing.T) {
	h, _ := newPollKeyHarness(t, "1h")
	sid := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish).StreamConfiguration.Id
	h.queuePollEvents(t, sid, 2)

	sets, _, status := ackOnlyPoll(h.router, sid, nil)
	assert.Equal(t, 200, status)
	assert.Empty(t, sets)
	assert.Equal(t, 0, h.router.pollBufferFor(sid).ClaimedCnt())
}

// A receiver acking on a separate request alongside its long poll: the long
// poll gets the pending batch at once rather than finding it claimed by the
// ack-only request (a claim-TTL stall).
func TestPollAckOnly_ParallelLongPollOnOwnerGetsBatch(t *testing.T) {
	t.Setenv("I2SIG_POLL_CLAIM_TTL", "30s")
	h, _ := newPollKeyHarness(t, "1h")
	sid := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish).StreamConfiguration.Id
	h.queuePollEvents(t, sid, 2)
	handed, _, _ := h.router.PollStreamHandler(context.Background(), sid, model.PollParameters{MaxEvents: 2, ReturnImmediately: true})
	require.Len(t, handed, 2)

	// The ack-only request lands first.
	h.queuePollEvents(t, sid, 3)
	ackSets, _, status := ackOnlyPoll(h.router, sid, keysOf(handed))
	require.Equal(t, 200, status)
	assert.Empty(t, ackSets)
	got, took := defaultLongPoll(h.router, sid)
	assert.Len(t, got, 3, "the long poll receives the pending batch")
	assert.Less(t, took, time.Second, "no claim stall")

	// Both in flight together.
	h.queuePollEvents(t, sid, 3)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ackSets, _, _ = ackOnlyPoll(h.router, sid, keysOf(got))
	}()
	var next map[string]string
	go func() {
		defer wg.Done()
		next, took = defaultLongPoll(h.router, sid)
	}()
	wg.Wait()
	assert.Empty(t, ackSets)
	assert.Len(t, next, 3)
	assert.Less(t, took, time.Second)
	assert.Equal(t, 3, h.pendingCount(sid), "the acks are applied")
}

// The same through a non-owner: the ack-only Claim asks for no events, and
// the long poll's Claim gets the batch.
func TestPollAckOnly_ParallelLongPollThroughClaimGetsBatch(t *testing.T) {
	t.Setenv("I2SIG_POLL_CLAIM_TTL", "30s")
	persistence := claimPersistence(t)
	bus := peer.NewInProcess()
	owner := claimNode(t, persistence, "node-a", true, persistence.Coordinator, bus.For("node-a"))
	viaB := &countingTransport{next: bus.For("node-b")}
	other := claimNode(t, persistence, "node-b", true, persistence.Coordinator, viaB)
	bus.Register("node-a", owner.router)
	bus.Register("node-b", other.router)

	rec := owner.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := rec.StreamConfiguration.Id
	other.router.UpdateStreamState(rec)
	owner.queuePollEvents(t, sid, 2)
	require.Equal(t, "node-a", leaseHolder(t, persistence, cluster.PollTransmitterResource(sid)))
	buf := owner.router.pollBufferFor(sid)

	handed, _, _ := other.router.PollStreamHandler(context.Background(), sid, model.PollParameters{MaxEvents: 2, ReturnImmediately: true})
	require.Len(t, handed, 2)

	owner.queuePollEvents(t, sid, 3)
	ackSets, _, status := ackOnlyPoll(other.router, sid, keysOf(handed))
	require.Equal(t, 200, status)
	assert.Empty(t, ackSets)
	assert.Equal(t, 0, buf.ClaimedCnt(), "the ack-only Claim claims nothing on the owner")
	viaB.mu.Lock()
	ackClaim := viaB.sent[len(viaB.sent)-1]
	viaB.mu.Unlock()
	assert.Zero(t, ackClaim.MaxEvents, "the ack-only Claim asks for no events")
	assert.Len(t, ackClaim.AckJtis, 2)

	got, took := defaultLongPoll(other.router, sid)
	assert.Len(t, got, 3, "the long poll receives the pending batch")
	assert.Less(t, took, time.Second, "no claim stall")

	owner.queuePollEvents(t, sid, 3)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ackSets, _, _ = ackOnlyPoll(other.router, sid, keysOf(got))
	}()
	var next map[string]string
	go func() {
		defer wg.Done()
		next, took = defaultLongPoll(other.router, sid)
	}()
	wg.Wait()
	assert.Empty(t, ackSets)
	assert.Len(t, next, 3)
	assert.Less(t, took, time.Second)
	assert.Equal(t, 3, owner.pendingCount(sid), "the acks are applied")
}

// SSTP acknowledgements need no wire change: an exchange that acks and asks
// for no events claims nothing, on the owner and through a Claim (#369).
func TestSstpServer_AckOnlyExchangeClaimsNothing(t *testing.T) {
	h := newSstpRunnerHarness(t)
	txSid, rxSid, pairId := "sstp-tx-ackonly", "sstp-rx-ackonly", "pair-ackonly"
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), sstpServerPairState(txSid, rxSid, pairId)))
	h.persistOutboundEvent(t, txSid, "sstp-ackonly-1")
	h.persistOutboundEvent(t, txSid, "sstp-ackonly-2")
	rec, err := h.router.streamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)

	drained, err := h.router.SstpServerHandler(context.Background(), rec, goSetSstp.Message{ReturnImmediately: goSetSstp.BoolPtr(true)}, nil)
	require.NoError(t, err)
	require.Len(t, drained.Sets, 2)
	buf := h.router.sstpServerBufferFor(txSid)
	require.NotNil(t, buf)
	require.Equal(t, 2, buf.ClaimedCnt())

	acked := keysOf(drained.Sets)[0]
	resp, err := h.router.SstpServerHandler(context.Background(), rec, goSetSstp.Message{
		ReturnEvents: goSetSstp.BoolPtr(false),
		Ack:          []string{acked},
	}, nil)
	require.NoError(t, err)
	assert.Empty(t, resp.Sets)
	assert.Equal(t, 1, buf.ClaimedCnt(), "the ack frees its claim and nothing new is claimed")
	assert.Len(t, pendingOutbound(t, h, txSid), 1, "the ack is applied")
}

func TestSstpServer_AckOnlyClaimFromNonOwnerAsksForNoEvents(t *testing.T) {
	persistence := claimPersistence(t)
	transport := &countingTransport{}
	owner := claimNode(t, persistence, "node-a", true, persistence.Coordinator, nil)
	other := claimNode(t, persistence, "node-b", true, persistence.Coordinator, transport)

	txSid, rxSid, pairId := "claim-tx-ackonly", "claim-rx-ackonly", "claim-pair-ackonly"
	require.NoError(t, persistence.StreamService.PersistStreamStateRecord(context.Background(), sstpServerPairState(txSid, rxSid, pairId)))
	rec, err := persistence.StreamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)
	_, err = owner.router.SstpServerHandler(context.Background(), rec, goSetSstp.Message{ReturnImmediately: goSetSstp.BoolPtr(true)}, nil)
	require.NoError(t, err)
	require.Equal(t, "node-a", leaseHolder(t, persistence, cluster.SstpServerResource(txSid)))

	_, err = other.router.SstpServerHandler(context.Background(), rec, goSetSstp.Message{
		ReturnEvents: goSetSstp.BoolPtr(false),
		Ack:          []string{"some-jti"},
	}, nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), transport.claims.Load())
	transport.mu.Lock()
	defer transport.mu.Unlock()
	assert.Zero(t, transport.sent[0].MaxEvents, "the SSTP ack Claim asks for no events")
	assert.Equal(t, []string{"some-jti"}, transport.sent[0].AckJtis)
}
