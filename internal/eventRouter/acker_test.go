package eventRouter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ackRecorder is an acker apply func that records each write.
type ackRecorder struct {
	mu     sync.Mutex
	writes [][]string
	err    error
}

func (a *ackRecorder) apply(_ context.Context, jtis []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.writes = append(a.writes, append([]string(nil), jtis...))
	return a.err
}

func (a *ackRecorder) snapshot() [][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][]string(nil), a.writes...)
}

func (a *ackRecorder) total() int {
	n := 0
	for _, w := range a.snapshot() {
		n += len(w)
	}
	return n
}

func jtiRange(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%d", prefix, i)
	}
	return out
}

// A zero window writes every completion inline, one write per batch, exactly
// as before #336.
func TestAcker_ZeroWindowAcksInline(t *testing.T) {
	rec := &ackRecorder{}
	a := newAcker(context.Background(), ackerConfig{sid: "s", transport: "push", apply: rec.apply, max: 8})
	defer func() { _ = a.close() }()

	b1, err := a.reserve(context.Background(), []string{"a", "b", "c"})
	require.NoError(t, err)
	require.NoError(t, a.complete([]string{"a", "b"}, []string{"c"}))
	assert.Equal(t, [][]string{{"a", "b"}}, rec.snapshot(), "acked inline, the released JTI not acked")
	assert.Equal(t, 0, a.size())
	assert.Len(t, b1, 3)

	rec.err = errors.New("boom")
	_, _ = a.reserve(context.Background(), []string{"d"})
	assert.Error(t, a.complete([]string{"d"}, nil), "an inline write's error is returned")
	assert.Equal(t, 0, a.size(), "a failed ack leaves the set: the SET stays pending and is redelivered")
}

// Completions inside one window coalesce into one write.
func TestAcker_CoalescesWithinWindow(t *testing.T) {
	rec := &ackRecorder{}
	a := newAcker(context.Background(), ackerConfig{sid: "s", transport: "push", apply: rec.apply, window: 50 * time.Millisecond, max: 64})
	defer func() { _ = a.close() }()

	for i := 0; i < 4; i++ {
		jtis := jtiRange(fmt.Sprintf("b%d", i), 3)
		_, err := a.reserve(context.Background(), jtis)
		require.NoError(t, err)
		require.NoError(t, a.complete(jtis, nil))
	}
	assert.Empty(t, rec.snapshot(), "nothing written before the window ends")
	assert.Equal(t, 12, a.size(), "queued acks stay in flight until written")
	require.Eventually(t, func() bool { return rec.total() == 12 }, 2*time.Second, 5*time.Millisecond)
	assert.Len(t, rec.snapshot(), 1, "one coalesced write")
	assert.Equal(t, 0, a.size())
}

// A queue at its size cap is written before the window ends.
func TestAcker_SizeCapDrainsEarly(t *testing.T) {
	rec := &ackRecorder{}
	a := newAcker(context.Background(), ackerConfig{sid: "s", transport: "push", apply: rec.apply, window: time.Hour, max: 16, sizeCap: 4})
	defer func() { _ = a.close() }()

	jtis := jtiRange("x", 4)
	_, err := a.reserve(context.Background(), jtis)
	require.NoError(t, err)
	require.NoError(t, a.complete(jtis, nil))
	require.Eventually(t, func() bool { return rec.total() == 4 }, 2*time.Second, 5*time.Millisecond)
}

// A reservation that would take the set past its bound waits until the acker
// has written enough to make room, and a JTI already in flight is never
// handed out twice.
func TestAcker_BoundBlocksAndDedups(t *testing.T) {
	rec := &ackRecorder{}
	gate := make(chan struct{})
	apply := func(ctx context.Context, jtis []string) error {
		<-gate
		return rec.apply(ctx, jtis)
	}
	a := newAcker(context.Background(), ackerConfig{sid: "s", transport: "push", apply: apply, window: time.Hour, max: 4, sizeCap: 100})
	defer func() { _ = a.close() }()

	first := jtiRange("f", 4)
	got, err := a.reserve(context.Background(), first)
	require.NoError(t, err)
	require.Len(t, got, 4)
	require.NoError(t, a.complete(first, nil))

	dup, err := a.reserve(context.Background(), []string{"f-0", "f-1"})
	require.NoError(t, err)
	assert.Empty(t, dup, "in-flight JTIs are dropped, not resent")
	assert.True(t, a.inFlight("f-2"))

	reserved := make(chan []string, 1)
	go func() {
		got, _ := a.reserve(context.Background(), []string{"n-0"})
		reserved <- got
	}()
	select {
	case <-reserved:
		t.Fatal("reserve past the bound did not wait")
	case <-time.After(50 * time.Millisecond):
	}
	// The waiting reserve nudged a drain; once the write lands there is room.
	close(gate)
	select {
	case got := <-reserved:
		assert.Equal(t, []string{"n-0"}, got)
	case <-time.After(2 * time.Second):
		t.Fatal("reserve never got room")
	}
	assert.Equal(t, 4, rec.total())

	// A full set whose wait is cancelled returns the context's error.
	more := jtiRange("m", 3)
	_, err = a.reserve(context.Background(), more)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = a.reserve(ctx, jtiRange("z", 4))
	assert.ErrorIs(t, err, context.Canceled)
}

// A batch larger than the bound is let in alone, so delivery never wedges.
func TestAcker_OversizedBatchFitsAlone(t *testing.T) {
	rec := &ackRecorder{}
	a := newAcker(context.Background(), ackerConfig{sid: "s", transport: "push", apply: rec.apply, max: 2})
	defer func() { _ = a.close() }()
	got, err := a.reserve(context.Background(), jtiRange("o", 5))
	require.NoError(t, err)
	assert.Len(t, got, 5)
}

// close writes what is queued; JTIs reserved but never completed are not
// acked (they stay pending for the successor).
func TestAcker_CloseFlushes(t *testing.T) {
	rec := &ackRecorder{}
	a := newAcker(context.Background(), ackerConfig{sid: "s", transport: "push", apply: rec.apply, window: time.Hour, max: 64})
	_, _ = a.reserve(context.Background(), []string{"a", "b", "c"})
	require.NoError(t, a.complete([]string{"a", "b"}, nil))
	require.NoError(t, a.close())
	assert.Equal(t, [][]string{{"a", "b"}}, rec.snapshot())
	require.NoError(t, a.close(), "close is idempotent")
	assert.Len(t, rec.snapshot(), 1)
}

// A completion that lands after close (a push whose response arrived while the
// runner was stopping) is still written: with the flush loop gone, it drains
// inline instead of sitting in a queue nobody applies.
func TestAcker_CompleteAfterCloseDrainsInline(t *testing.T) {
	rec := &ackRecorder{}
	a := newAcker(context.Background(), ackerConfig{sid: "s", transport: "push", apply: rec.apply, window: time.Hour, max: 64})
	_, _ = a.reserve(context.Background(), []string{"a", "b", "c"})
	require.NoError(t, a.close())
	assert.Empty(t, rec.snapshot())
	require.NoError(t, a.complete([]string{"c"}, nil))
	assert.Equal(t, [][]string{{"c"}}, rec.snapshot())
}

// An ack refused because this node's lease tenure ran out (#364) is not
// dropped: the batch goes back to the front of the queue with its JTIs still
// in flight, no outcome is reported, and the next flush after a renewal writes
// it. Nothing fences the acker; reservations go on.
func TestAcker_NotOwnerRequeuesUntilRenewed(t *testing.T) {
	rec := &ackRecorder{err: fmt.Errorf("ack: %w", errNotLeaseOwner)}
	var appliedMu sync.Mutex
	var applied []error
	a := newAcker(context.Background(), ackerConfig{
		sid: "s", transport: "push", apply: rec.apply, window: time.Hour, max: 64,
		onApplied: func(_ []string, err error) {
			appliedMu.Lock()
			applied = append(applied, err)
			appliedMu.Unlock()
		},
	})
	defer func() { _ = a.close() }()

	_, _ = a.reserve(context.Background(), []string{"a", "b"})
	require.NoError(t, a.complete([]string{"a", "b"}, nil))
	assert.ErrorIs(t, a.flush(), errNotLeaseOwner)
	assert.Equal(t, 2, a.size(), "the refused batch stays in flight")
	appliedMu.Lock()
	assert.Empty(t, applied, "a refused batch reports no outcome")
	appliedMu.Unlock()

	got, err := a.reserve(context.Background(), []string{"c"})
	require.NoError(t, err, "a refused ack does not fence the acker")
	assert.Equal(t, []string{"c"}, got)

	rec.mu.Lock()
	rec.err = nil
	rec.mu.Unlock()
	require.NoError(t, a.flush())
	writes := rec.snapshot()
	require.Len(t, writes, 2)
	assert.Equal(t, writes[0], writes[1], "the renewed flush writes the same batch")
	assert.Equal(t, 1, a.size(), "only the unacked reservation is left")
	appliedMu.Lock()
	defer appliedMu.Unlock()
	require.Equal(t, []error{nil}, applied)
}

func TestAckerEnv(t *testing.T) {
	t.Setenv("I2SIG_DELIVERY_INFLIGHT_MAX", "")
	t.Setenv("I2SIG_ACK_COALESCE_WINDOW", "")
	assert.Equal(t, defaultDeliveryInFlightMax, deliveryInFlightMax())
	assert.Equal(t, defaultAckCoalesceWindow, ackCoalesceWindow())
	t.Setenv("I2SIG_DELIVERY_INFLIGHT_MAX", "1000")
	t.Setenv("I2SIG_ACK_COALESCE_WINDOW", "0")
	assert.Equal(t, 1000, deliveryInFlightMax())
	assert.Equal(t, time.Duration(0), ackCoalesceWindow())
	t.Setenv("I2SIG_DELIVERY_INFLIGHT_MAX", "-3")
	t.Setenv("I2SIG_ACK_COALESCE_WINDOW", "soon")
	assert.Equal(t, defaultDeliveryInFlightMax, deliveryInFlightMax())
	assert.Equal(t, defaultAckCoalesceWindow, ackCoalesceWindow())

	r := &router{pushConcurrency: 32, deliveryInFlightMax: 10}
	assert.Equal(t, 128, r.inFlightMax(), "the bound never falls below one full batch")
}

// With the acks held in the coalescing queue, a delivered SET is still pending
// in the store, yet backfill does not read it back and resend it; a runner
// restart writes the queued acks before the successor starts, so each SET is
// delivered once and none is left pending.
func TestPushAckCoalescing_RestartFlushesQueuedAcksNoResend(t *testing.T) {
	t.Setenv("I2SIG_ACK_COALESCE_WINDOW", "1h")
	t.Setenv("I2SIG_PUSH_BACKFILL_INTERVAL", "20ms")
	rx := newHoldingReceiver()
	rx.release()
	h := newRestartHarness(t, rx)

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 6)
	h.router.UpdateStreamState(stream.DeepCopy())

	require.Eventually(t, func() bool { return len(rx.snapshot()) >= len(jtis) }, 10*time.Second, 5*time.Millisecond)
	pushes := rx.settle(t)
	assert.Len(t, pushes, len(jtis), "backfill resends nothing whose ack is queued")
	assert.Equal(t, len(jtis), h.pendingCount(sid), "acks are queued, not yet written")

	prev := h.runnerFor(sid)
	h.saveAndSync(t, sid, endpointPatch("https://receiver.example.com/moved"))
	waitFinished(t, prev, "old runner did not stop")
	assert.Equal(t, 0, h.pendingCount(sid), "the stopping runner wrote its queued acks")

	pushes = rx.settle(t)
	for jti, got := range deliveriesByJti(pushes) {
		assert.Len(t, got, 1, "jti %s delivered once", jti)
	}
}

// Queued acks refused after a takeover are not written: once the old owner's
// recorded tenure has run out its acker writes nothing, makes no lease call,
// and the SETs stay pending for the new owner to redeliver (#364).
func TestPushAckCoalescing_TenureEndLeavesSentSetsPending(t *testing.T) {
	t.Setenv("I2SIG_ACK_COALESCE_WINDOW", "1h")
	rx := newHoldingReceiver()
	rx.release()
	h := newRestartHarness(t, rx)
	coord := unwrapCoordinator(h.router.coordinator)
	setter, ok := coord.(clockSetter)
	require.True(t, ok)
	clock := &leaseClock{t: time.Now().UTC()}
	setter.SetClock(clock.now)
	t.Cleanup(func() { setter.SetClock(nil) })
	require.NotNil(t, h.router.leases)
	h.router.leases.now = clock.now

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 3)
	resource := cluster.PushTransmitterResource(sid)
	h.router.UpdateStreamState(stream.DeepCopy())
	require.Eventually(t, func() bool { return len(rx.snapshot()) >= len(jtis) }, 10*time.Second, 5*time.Millisecond)
	waitLeaseOwner(t, coord, resource, "node-restart")
	require.True(t, h.router.leases.StillOwner(resource))

	clock.advance(time.Minute)
	took, _, _, err := coord.TryAcquireOrRenewLease(resource, "node-b", time.Hour)
	require.NoError(t, err)
	require.True(t, took)
	assert.False(t, h.router.leases.StillOwner(resource), "the tenure ran out with the lease")

	v, ok := h.router.pushAckers.Load(sid)
	require.True(t, ok)
	ack := v.(*acker)
	assert.ErrorIs(t, ack.flush(), errNotLeaseOwner)
	assert.Equal(t, len(jtis), h.pendingCount(sid), "an ack past the tenure writes nothing; the SETs are redelivered by the owner")
}

// An SSTP peer ack is queued on the pair's acker: the SET keeps its in-flight
// claim, so no concurrent cycle re-sends it, until the coalesced ack is
// written; then the claim clears and the SET is no longer pending.
func TestSstpAckCoalescing_ClaimHeldUntilAckWritten(t *testing.T) {
	h := newSstpRunnerHarness(t)
	r := h.router
	r.ackCoalesceWindow = time.Hour

	txSid, rxSid, pairId := "sstp-tx-coalesce", "sstp-rx-coalesce", "pair-coalesce"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	jtis := []string{"coalesce-1", "coalesce-2", "coalesce-3"}
	for _, jti := range jtis {
		h.persistOutboundEvent(t, txSid, jti)
	}
	claimed := r.claimSstpJtis(pairId, jtis, len(jtis))
	require.Len(t, claimed, 3)
	sent := r.resolveOutboundSets(r.outboundRefs(pairId, claimed))
	require.Len(t, sent, 3)

	pending := func() int {
		ids, _ := r.eventService.GetEventIds(context.Background(), txSid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
		return len(ids)
	}
	claims := func() int {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return len(r.sstpInFlight[pairId])
	}

	n := r.handleSstpAcks(rec, nil, jtis[:2], sent)
	assert.Equal(t, 2, n)
	assert.Equal(t, 2, claims(), "the acked SETs stay claimed until their ack is written; the unacked one is released")
	assert.Equal(t, 3, pending())
	assert.Empty(t, r.claimSstpJtis(pairId, jtis[:2], 2), "a claimed SET is not handed out again")

	ack := r.sstpAcker(pairId)
	require.NotNil(t, ack)
	require.NoError(t, ack.flush())
	assert.Equal(t, 0, claims())
	assert.Equal(t, 1, pending(), "only the unacked SET is still pending")

	r.RemoveStream(pairId)
	assert.Nil(t, r.sstpAcker(pairId), "a removed pair leaves no acker")
}
