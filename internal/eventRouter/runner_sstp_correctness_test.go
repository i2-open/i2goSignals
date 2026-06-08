package eventRouter

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression suite for the four SSTP delivery-correctness findings (PRD #154):
//   #5 server never consumes the inbound Ack -> outbound SET re-delivered forever
//   #6 inbound event matching an SSTP-client pair is never AddEventToStream'd -> lost
//   #8 RemoveStream leaks the four sstp* maps + buffers + the client runner goroutine
//   #9 a live SSTP-client config update (pause / rotate) is never seen by the runner

// --- Finding #5: server consumes inbound Ack and stops re-delivering ----------

// TestSstpServer_ConsumesInboundAckAndStopsRedelivery proves the server acks the
// JTIs the peer reports in Message.Ack on the outbound buffer AND via eventService,
// so a delivered SET is NOT re-sent on the following cycle (mirrors the RFC8936
// poll transmitter params.Acks handling).
func TestSstpServer_ConsumesInboundAckAndStopsRedelivery(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	txSid, rxSid, pairId := "sstp-tx-ack", "sstp-rx-ack", "pair-ack"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))

	jti := "sstp-srv-out-1"
	h.persistOutboundEvent(t, txSid, jti)

	// Cycle 1: server delivers the pending outbound SET.
	resp1, status1 := h.router.SstpServerHandler(context.Background(), pairId, goSetSstp.Message{}, nil)
	require.Equal(t, 200, status1)
	require.Contains(t, resp1.Sets, jti, "cycle 1 must deliver the pending outbound SET")

	// Cycle 2: the peer's request carries the JTI in Ack (acking cycle 1's delivery).
	// returnImmediately so we don't long-poll an empty buffer.
	ackMsg := goSetSstp.Message{
		Ack:               []string{jti},
		ReturnImmediately: goSetSstp.BoolPtr(true),
	}
	resp2, status2 := h.router.SstpServerHandler(context.Background(), pairId, ackMsg, nil)
	require.Equal(t, 200, status2)
	assert.NotContains(t, resp2.Sets, jti, "an acked SET must not be re-delivered on the next cycle")

	// The acked JTI must be gone from the tx-side pending list (eventService ack).
	pending, _ := h.router.eventService.GetEventIds(context.Background(), txSid, model.PollParameters{
		MaxEvents:         10,
		ReturnImmediately: true,
	})
	assert.NotContains(t, pending, jti, "an acked outbound SET must be removed from the tx-side pending list")

	// Cycle 3: still gone (no infinite redelivery).
	resp3, status3 := h.router.SstpServerHandler(context.Background(), pairId,
		goSetSstp.Message{ReturnImmediately: goSetSstp.BoolPtr(true)}, nil)
	require.Equal(t, 200, status3)
	assert.NotContains(t, resp3.Sets, jti, "acked SET must stay gone on subsequent cycles")
}

// --- Finding #6: inbound event for an SSTP-client pair becomes deliverable ----

// TestSstpClientFanout_AddsEventToStreamPendingList proves an inbound event that
// matches a registered SSTP-client pair is added to the tx-side pending list (via
// AddEventToStream), so the next outbound cycle finds and delivers it rather than
// silently losing it.
func TestSstpClientFanout_AddsEventToStreamPendingList(t *testing.T) {
	// A resolvable inbound stream (so HandleEvent reaches the fan-out), mirroring
	// the cluster_wake_sstp tests.
	s := setupDedupRouterPollStream(t)
	r := s.h.router
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
	})
	r.sstpDelivery = adapter

	txSid, pairId := "sstp-tx-fan", "pair-fan"
	pair := sstpClientPairForMatch(txSid, pairId) // matches iss/aud/event-type of the inbound stream
	buf := buffer.CreateEventPollBuffer(nil, 0, 0)
	t.Cleanup(buf.Close)
	r.mu.Lock()
	r.sstpClientStreams[pairId] = *pair
	r.sstpBuffers[pairId] = buf
	r.mu.Unlock()

	// An inbound event matching the pair, ingested via the resolvable inbound stream.
	jti := "sstp-fan-1"
	token := newRiscToken(jti, dupTestIssuer, s.audience)
	require.NoError(t, r.HandleEvent(token, `{"raw":"fan"}`, s.streamID))

	// The JTI must now be in the tx-side pending list — recoverable/deliverable by
	// the next outbound cycle, not lost (Finding #6).
	pending, _ := r.eventService.GetEventIds(context.Background(), txSid, model.PollParameters{
		MaxEvents:         10,
		ReturnImmediately: true,
	})
	assert.Contains(t, pending, jti, "inbound event matching an SSTP-client pair must be added to the tx-side pending list")

	// And a cycle delivers it (proving end-to-end deliverability).
	cfg := *fastSstpCfg()
	cfg.fillDefaults()
	delay := cfg.BaseDelay
	_, _, _ = r.runSstpCycle(context.Background(), pair, buf, 0, cfg, &delay)
	reqs := adapter.Requests()
	require.NotEmpty(t, reqs, "the woken cycle must deliver the fanned-out event")
	found := false
	for _, rq := range reqs {
		for _, ev := range rq.Events {
			if ev.Jti == jti {
				found = true
			}
		}
	}
	assert.True(t, found, "the inbound event must be delivered on the outbound cycle, not lost")
}

// --- NEW Finding #1: CLIENT acks its outbound buffer (no infinite redelivery) -

// TestSstpClient_AcksOutboundBufferAndStopsRedelivery is the CLIENT-side analogue
// of TestSstpServer_ConsumesInboundAckAndStopsRedelivery. The client outbound
// buffer is filled by SubmitEvent (the #6 fan-out) and drained via GetEvents,
// which only COPIES — only AckEvents removes. After a SET is confirmed
// delivered/acked in cycle 1, the runner must AckEvents it on the client outbound
// buffer so cycle 2 does NOT re-drain and re-send it, and the buffer is empty.
func TestSstpClient_AcksOutboundBufferAndStopsRedelivery(t *testing.T) {
	jti := "sstp-cli-out-1"
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
		Acked:          []string{jti},
	})
	h := newSstpRunnerHarness(t, adapter)

	txSid, pairId := "sstp-tx-cli-ack", "pair-cli-ack"
	state := sstpPairState(txSid, pairId)
	h.persistOutboundEvent(t, txSid, jti)

	// Fill the client outbound buffer exactly as the #6 fan-out does: SubmitEvent.
	buf := buffer.CreateEventPollBuffer(nil, 0, 0)
	t.Cleanup(buf.Close)
	h.registerSstpClient(state, buf)
	buf.SubmitEvent(jti)
	// Wait for the buffer's async drain to surface the JTI so cycle 1 drains it.
	require.Eventually(t, func() bool { return buf.Cnt() == 1 },
		2*time.Second, 5*time.Millisecond, "outbound SET must land in the client buffer")

	cfg := *fastSstpCfg()
	cfg.fillDefaults()
	delay := cfg.BaseDelay

	// Cycle 1: drains + delivers + acks the SET.
	_, _, _ = h.router.runSstpCycle(context.Background(), state, buf, 1, cfg, &delay)
	require.GreaterOrEqual(t, adapter.Calls(), 1, "cycle 1 must deliver the SET")
	c1 := adapter.Calls()

	// After cycle 1 the acked SET must be GONE from the client outbound buffer.
	assert.Equal(t, 0, buf.Cnt(), "an acked outbound SET must be removed from the client buffer")

	// The acked JTI must also be gone from the tx-side pending list.
	pending, _ := h.router.eventService.GetEventIds(context.Background(), txSid, model.PollParameters{
		MaxEvents: 10, ReturnImmediately: true,
	})
	assert.NotContains(t, pending, jti, "an acked outbound SET must be removed from the tx-side pending list")

	// Cycle 2: nothing left to drain from the buffer (and nothing pending), so the
	// SET is NOT re-sent. The only way it would be re-sent is the buffer GetEvents
	// re-surfacing it (the bug) — assert the request set carrying this JTI did not grow.
	_, _, _ = h.router.runSstpCycle(context.Background(), state, buf, 1, cfg, &delay)
	sends := 0
	for _, rq := range adapter.Requests() {
		for _, ev := range rq.Events {
			if ev.Jti == jti {
				sends++
			}
		}
	}
	assert.Equal(t, 1, sends, "the acked SET must be sent exactly once, not redelivered on cycle 2")
	_ = c1
}

// --- NEW Finding #2: held-cycle second push does not re-send in-flight SETs ----

// TestSstpClient_SecondPushDoesNotResendInFlight proves that while a primary cycle
// holds [X] in flight (X still physically in the buffer because GetEvents only
// copies), a second push fired by a newly-arrived event Y sends ONLY Y, not X.
func TestSstpClient_SecondPushDoesNotResendInFlight(t *testing.T) {
	x, y := "sstp-inflight-x", "sstp-inflight-y"
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
		// Never ack: the primary's X stays unacked/in-flight so we can prove the
		// second push does not re-grab it from the still-populated buffer.
		Acked: nil,
	})
	adapter.SetBlockingPrimaryOnly()
	primaryStarted := make(chan struct{}, 1)
	adapter.SetOnDeliver(func() {
		select {
		case primaryStarted <- struct{}{}:
		default:
		}
	})
	h := newSstpRunnerHarness(t, adapter)

	txSid, pairId := "sstp-tx-inflight", "pair-inflight"
	state := sstpPairState(txSid, pairId)
	h.persistOutboundEvent(t, txSid, x)
	h.persistOutboundEvent(t, txSid, y)

	buf := buffer.CreateEventPollBuffer(nil, 0, 0)
	t.Cleanup(buf.Close)
	h.registerSstpClient(state, buf)
	buf.SubmitEvent(x)
	require.Eventually(t, func() bool { return buf.Cnt() == 1 },
		2*time.Second, 5*time.Millisecond, "X must land in the buffer")

	cfg := *fastSstpCfg()
	cfg.fillDefaults()

	loopDone := make(chan bool, 1)
	go func() {
		loopDone <- h.router.runSstpClientLoop("sstp-client:"+pairId, state, buf, 1, cfg)
	}()

	select {
	case <-primaryStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("primary long-poll cycle never started")
	}

	// Y arrives while the primary holds X in flight.
	buf.SubmitEvent(y)
	buf.Wakeup()

	// A second push (returnEvents=false) must fire carrying ONLY Y.
	require.Eventually(t, func() bool {
		for _, req := range adapter.Requests() {
			if req.ReturnEvents != nil && !*req.ReturnEvents {
				return true
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "a second push must fire for Y")

	for _, req := range adapter.Requests() {
		if req.ReturnEvents != nil && !*req.ReturnEvents {
			jtis := map[string]bool{}
			for _, ev := range req.Events {
				jtis[ev.Jti] = true
			}
			assert.True(t, jtis[y], "second push must carry Y")
			assert.False(t, jtis[x], "second push must NOT re-send X (already in flight in the primary cycle)")
		}
	}

	adapter.Unblock()
	h.router.Shutdown()
	select {
	case <-loopDone:
	case <-time.After(3 * time.Second):
		t.Fatal("runner loop did not exit after shutdown")
	}
}

// TestSstpClient_FailedDeliveryRetriesClaimedEvent proves the in-flight claim is
// released on delivery FAILURE so the event is re-drained and retried on a later
// cycle (not dropped).
func TestSstpClient_FailedDeliveryRetriesClaimedEvent(t *testing.T) {
	jti := "sstp-retry-1"
	// Script: cycle 1 transport-fails (no ack), cycle 2 succeeds and acks.
	adapter := delivery.NewSstpMemoryScript(
		delivery.SstpOutcome{Classification: goSetSstp.Classification{Class: goSetSstp.ClassTransport}},
		delivery.SstpOutcome{
			Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
			Acked:          []string{jti},
		},
	)
	h := newSstpRunnerHarness(t, adapter)

	txSid, pairId := "sstp-tx-retry", "pair-retry"
	state := sstpPairState(txSid, pairId)
	h.persistOutboundEvent(t, txSid, jti)

	buf := buffer.CreateEventPollBuffer(nil, 0, 0)
	t.Cleanup(buf.Close)
	h.registerSstpClient(state, buf)
	buf.SubmitEvent(jti)
	require.Eventually(t, func() bool { return buf.Cnt() == 1 },
		2*time.Second, 5*time.Millisecond, "SET must land in the buffer")

	cfg := *fastSstpCfg()
	cfg.fillDefaults()
	delay := cfg.BaseDelay

	// Cycle 1: transport failure — claim must be released so the event is retried.
	_, _, _ = h.router.runSstpCycle(context.Background(), state, buf, 1, cfg, &delay)
	assert.Equal(t, 1, buf.Cnt(), "failed delivery must leave the SET in the buffer for retry")

	// Cycle 2: succeeds and acks — proving the previously-failed event was re-drained.
	_, _, _ = h.router.runSstpCycle(context.Background(), state, buf, 1, cfg, &delay)
	sends := 0
	for _, rq := range adapter.Requests() {
		for _, ev := range rq.Events {
			if ev.Jti == jti {
				sends++
			}
		}
	}
	assert.GreaterOrEqual(t, sends, 2, "the failed event must be re-drained and re-sent on a later cycle")
	assert.Equal(t, 0, buf.Cnt(), "after the successful ack the SET must be gone from the buffer")
}

// --- Cross-node ack: the server honors an ack regardless of delivering node -----

// TestSstpServer_AcksOutboundRegardlessOfDeliveringNode proves the SSTP-server
// endpoint honors a peer's inbound Ack even when THIS router never delivered the
// SET itself. The endpoint takes no cluster lease (any node serves it, Q11.1), so
// in production cycle N's delivery and cycle N+1's ack routinely land on different
// nodes. Per-node delivery tracking would silently drop the legitimate ack and
// redeliver the SET forever; the handler instead acks unconditionally against the
// durable pending list, mirroring the RFC8936 poll transmitter (PollStreamHandler).
func TestSstpServer_AcksOutboundRegardlessOfDeliveringNode(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	txSid, rxSid, pairId := "sstp-tx-srvack", "sstp-rx-srvack", "pair-srvack"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))

	// A pending outbound SET. This router never delivers it (simulating that another
	// node served the delivering cycle). The peer now acks it against THIS node.
	jti := "sstp-srv-acked-elsewhere"
	h.persistOutboundEvent(t, txSid, jti)

	ack := goSetSstp.Message{
		Ack:               []string{jti},
		ReturnImmediately: goSetSstp.BoolPtr(true),
	}
	_, status := h.router.SstpServerHandler(context.Background(), pairId, ack, nil)
	require.Equal(t, 200, status)

	// The ack must be honored: the SET is removed from the durable pending list even
	// though this node never delivered it. A per-node delivery gate would leave it
	// pending and redeliver it forever.
	pending, _ := h.router.eventService.GetEventIds(context.Background(), txSid, model.PollParameters{
		MaxEvents: 10, ReturnImmediately: true,
	})
	assert.NotContains(t, pending, jti, "a cross-node ack must remove the pending outbound SET (no per-node delivery gate)")
}

// --- Finding #8: RemoveStream tears down the SSTP maps, buffers, and runner ----

// TestRemoveStream_TearsDownSstpClient proves RemoveStream deletes the four sstp*
// map entries, closes the buffers, and the client runner goroutine exits.
func TestRemoveStream_TearsDownSstpClient(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
	})
	h := newSstpRunnerHarness(t, adapter)

	// In production txSid == pairId for a pair; use the same value so the single
	// SID passed to RemoveStream matches both client (PairId) and server (txSid) maps.
	sid := "pair-rm"
	state := sstpPairState(sid, sid)

	clientBuf := buffer.CreateEventPollBuffer(nil, 0, 0)
	serverBuf := buffer.CreateEventPollBuffer(nil, 0, 0)
	h.router.mu.Lock()
	h.router.sstpClientStreams[sid] = *state
	h.router.sstpBuffers[sid] = clientBuf
	h.router.sstpServerStreams[sid] = *state
	h.router.sstpServerBuffers[sid] = serverBuf
	h.router.mu.Unlock()

	// Start the client runner goroutine; it must exit after RemoveStream.
	handlerDone := make(chan struct{})
	go func() {
		h.router.SstpClientStreamHandler(state, clientBuf)
		close(handlerDone)
	}()
	require.Eventually(t, func() bool { return h.coord.AcquireCalls() >= 1 },
		2*time.Second, 10*time.Millisecond, "runner must start")

	h.router.RemoveStream(sid)

	// Maps cleared.
	h.router.mu.RLock()
	_, c1 := h.router.sstpClientStreams[sid]
	_, c2 := h.router.sstpBuffers[sid]
	_, c3 := h.router.sstpServerStreams[sid]
	_, c4 := h.router.sstpServerBuffers[sid]
	h.router.mu.RUnlock()
	assert.False(t, c1, "sstpClientStreams entry must be deleted")
	assert.False(t, c2, "sstpBuffers entry must be deleted")
	assert.False(t, c3, "sstpServerStreams entry must be deleted")
	assert.False(t, c4, "sstpServerBuffers entry must be deleted")

	// Buffers closed.
	assert.True(t, clientBuf.IsClosed(), "client buffer must be closed")
	assert.True(t, serverBuf.IsClosed(), "server buffer must be closed")

	// Runner goroutine exits (no leak, no continued delivery).
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("client runner goroutine did not exit after RemoveStream — leak")
	}
}

// --- Finding #9: a live config update is observed by the running runner -------

// TestSstpClient_LiveConfigUpdateObservedByRunner proves that updating a running
// SSTP-client pair's status to Paused via UpdateStreamState is seen by the running
// runner within a cycle (it stops delivering), i.e. the map and the goroutine share
// one source of truth.
func TestSstpClient_LiveConfigUpdateObservedByRunner(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
		Acked:          nil, // never ack so the event keeps being eligible
	})
	h := newSstpRunnerHarness(t, adapter)

	txSid, pairId := "sstp-tx-live", "pair-live"
	state := sstpPairState(txSid, pairId)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), state))
	h.persistOutboundEvent(t, txSid, "sstp-live-1")

	// Start via the production wiring path so the runner uses the same source of
	// truth the map update path mutates.
	h.router.UpdateStreamState(state)
	require.Eventually(t, func() bool { return h.coord.AcquireCalls() >= 1 },
		2*time.Second, 10*time.Millisecond, "runner must start")

	// Let it run a few cycles, then pause via the production update path.
	require.Eventually(t, func() bool { return adapter.Calls() >= 1 },
		2*time.Second, 5*time.Millisecond, "runner must deliver at least once before pause")

	paused := sstpPairState(txSid, pairId)
	paused.Status = model.StreamStatePause
	h.router.UpdateStreamState(paused)

	// Within a cycle the runner must observe the pause and stop delivering. Record
	// the call count shortly after the pause, then assert it stops growing.
	require.Eventually(t, func() bool {
		before := adapter.Calls()
		time.Sleep(80 * time.Millisecond)
		return adapter.Calls() == before
	}, 3*time.Second, 10*time.Millisecond, "runner must stop delivering after a live pause")

	// The map's source-of-truth status must be paused.
	h.router.mu.RLock()
	got := h.router.sstpClientStreams[pairId]
	h.router.mu.RUnlock()
	assert.Equal(t, model.StreamStatePause, got.Status, "the shared source of truth must reflect the pause")
}
