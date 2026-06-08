package eventRouter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCoordinator is a fully controllable cluster.ClusterCoordinator for the
// SSTP-client runner tests. Acquire/renew outcomes are scripted; release is
// recorded. It lets a test drive lease loss, heartbeat blips, and graceful
// release deterministically without relying on wall-clock lease expiry.
type fakeCoordinator struct {
	mu sync.Mutex
	// acquireResults is consumed in order on each TryAcquireOrRenewLease call;
	// the final entry repeats after exhaustion. true = lease held.
	acquireResults []bool
	acquireCalls   int
	releaseCalls   int
	fencing        int64
}

func newFakeCoordinator(results ...bool) *fakeCoordinator {
	if len(results) == 0 {
		results = []bool{true}
	}
	return &fakeCoordinator{acquireResults: results}
}

func (c *fakeCoordinator) TryAcquireOrRenewLease(resource, nodeId string, d time.Duration) (bool, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := c.acquireCalls
	if idx >= len(c.acquireResults) {
		idx = len(c.acquireResults) - 1
	}
	c.acquireCalls++
	if c.acquireResults[idx] {
		c.fencing++
		return true, c.fencing, nil
	}
	return false, 0, nil
}

func (c *fakeCoordinator) ReleaseLeaseIfOwned(resource, nodeId string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releaseCalls++
	return nil
}

func (c *fakeCoordinator) Releases() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.releaseCalls
}

func (c *fakeCoordinator) AcquireCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.acquireCalls
}

func (c *fakeCoordinator) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
	return "", time.Time{}, 0, nil
}
func (c *fakeCoordinator) RegisterNode(node model.ClusterNode) error    { return nil }
func (c *fakeCoordinator) GetActiveNodeCount() (int64, error)           { return 1, nil }
func (c *fakeCoordinator) GetActiveNodes() ([]model.ClusterNode, error) { return nil, nil }
func (c *fakeCoordinator) GetNode(nodeId string) (*model.ClusterNode, error) {
	return &model.ClusterNode{Id: nodeId}, nil
}

var _ cluster.ClusterCoordinator = (*fakeCoordinator)(nil)

// fastSstpCfg returns a deterministic, fast config for runner tests: no jitter,
// short heartbeat, short backoff.
func fastSstpCfg() *sstpBackoffConfig {
	return &sstpBackoffConfig{
		BaseDelay:           5 * time.Millisecond,
		MaxDelay:            50 * time.Millisecond,
		BackoffFactor:       2.0,
		LeaseDuration:       200 * time.Millisecond,
		HeartbeatInterval:   20 * time.Millisecond,
		HeartbeatRetryDelay: 10 * time.Millisecond,
		Jitter:              func() time.Duration { return 0 },
	}
}

// sstpRunnerHarness wires a router with an injected fake coordinator and SSTP
// seam, the standard memory persistence for events/streams, and prometheus
// counters. The router is started disabled-of-runners (no auto UpdateStreamState
// for SSTP) so tests can drive the runner explicitly.
type sstpRunnerHarness struct {
	router     *router
	coord      *fakeCoordinator
	adapter    *delivery.SstpMemoryAdapter
	inCounter  *prometheus.CounterVec
	outCounter *prometheus.CounterVec
}

func newSstpRunnerHarness(t *testing.T, adapter *delivery.SstpMemoryAdapter, results ...bool) *sstpRunnerHarness {
	t.Helper()
	base := newTestRouter(t)
	coord := newFakeCoordinator(results...)
	// Swap the coordinator and SSTP seam on the already-constructed router.
	base.router.coordinator = coord
	base.router.sstpDelivery = adapter
	base.router.sstpCfgOverride = fastSstpCfg()

	inCounter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "sstp_test_in", Help: "t"},
		[]string{"type", "iss", "tfr", "stream_id"})
	outCounter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "sstp_test_out", Help: "t"},
		[]string{"type", "iss", "tfr", "stream_id"})
	base.router.SetEventCounter(inCounter, outCounter)

	return &sstpRunnerHarness{
		router:     base.router,
		coord:      coord,
		adapter:    adapter,
		inCounter:  inCounter,
		outCounter: outCounter,
	}
}

// sstpPairState builds an SSTP-initiator pair record. txSid is the outbound SID.
func sstpPairState(txSid, pairId string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       dupTestIssuer,
			Aud:       []string{"https://peer.example.com"},
			RouteMode: model.RouteModeForward,
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         "https://peer.example.com/sstp/" + pairId,
			AuthorizationHeader: "Bearer secret",
		},
	}
}

func outCounterValueSstp(t *testing.T, vec *prometheus.CounterVec, sid string) float64 {
	t.Helper()
	return testutil.ToFloat64(vec.With(prometheus.Labels{
		"type":      typeAcctDisabled,
		"iss":       dupTestIssuer,
		"tfr":       "SSTP",
		"stream_id": sid,
	}))
}

// persistOutboundEvent persists a SET for txSid and marks it pending for that
// stream so the runner's backfill picks it up.
func (h *sstpRunnerHarness) persistOutboundEvent(t *testing.T, txSid, jti string) {
	t.Helper()
	token := newRiscToken(jti, dupTestIssuer, "https://peer.example.com")
	_, err := h.router.eventService.AddEvent(context.Background(), token, txSid, `{"raw":true}`)
	require.NoError(t, err)
	require.NoError(t, h.router.eventService.AddEventToStream(context.Background(), jti, txSid))
}

// --- Acceptance: lease acquire + outbound flush + metric --------------------

// TestSstpClient_FlushesOutboundAndCountsMetric: the runner takes the lease,
// drains a pending outbound event through the seam, acks it on the peer ack, and
// increments eventsOut with tfr=SSTP and stream_id=txSid (Q46).
func TestSstpClient_FlushesOutboundAndCountsMetric(t *testing.T) {
	jti := "sstp-out-1"
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
		Acked:          []string{jti},
	})
	h := newSstpRunnerHarness(t, adapter)

	txSid := "sstp-tx-1"
	h.persistOutboundEvent(t, txSid, jti)

	state := sstpPairState(txSid, "pair-flush")
	buf := buffer.CreateEventPollBuffer(nil, 0, 0)
	t.Cleanup(buf.Close)

	go h.router.SstpClientStreamHandler(state, buf)

	require.Eventually(t, func() bool {
		return outCounterValueSstp(t, h.outCounter, txSid) >= 1.0
	}, 3*time.Second, 10*time.Millisecond, "expected one outbound SSTP event counted")

	assert.GreaterOrEqual(t, h.coord.AcquireCalls(), 1, "runner must acquire the sstp-client lease")
}

// --- Acceptance: 4xx pauses ONLY the outbound direction ---------------------

// TestSstpCycle_4xxPausesOutboundOnly: a ClassRequestError (4xx) transitions the
// outbound Status to paused and signals exit, while the inbound side
// (InboundStatus) is left untouched (Q12.3).
func TestSstpCycle_4xxPausesOutboundOnly(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassRequestError},
	})
	h := newSstpRunnerHarness(t, adapter)

	state := sstpPairState("sstp-tx-4xx", "pair-4xx")
	state.InboundStatus = model.StreamStateEnabled
	h.persistOutboundEvent(t, "sstp-tx-4xx", "j4xx")
	buf := buffer.CreateEventPollBuffer(nil, 0, 0)
	t.Cleanup(buf.Close)

	cfg := *fastSstpCfg()
	cfg.fillDefaults()
	delay := cfg.BaseDelay
	_, _, exit := h.router.runSstpCycle(context.Background(), state, buf, 0, cfg, &delay)

	assert.True(t, exit, "4xx must exit the cycle loop")
	assert.Equal(t, model.StreamStatePause, state.Status, "outbound direction must be paused")
	assert.Equal(t, model.StreamStateEnabled, state.InboundStatus, "inbound direction must NOT be paused")
}

// --- Acceptance: 5xx / transport back off without pausing -------------------

// TestSstpCycle_5xxBacksOffWithoutPausing: a ClassTransient (5xx) returns a
// positive delay, does NOT exit, and does NOT pause the stream (Q25).
func TestSstpCycle_5xxBacksOffWithoutPausing(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassTransient},
	})
	h := newSstpRunnerHarness(t, adapter)

	state := sstpPairState("sstp-tx-5xx", "pair-5xx")
	h.persistOutboundEvent(t, "sstp-tx-5xx", "j5xx")
	buf := buffer.CreateEventPollBuffer(nil, 0, 0)
	t.Cleanup(buf.Close)

	cfg := *fastSstpCfg()
	cfg.fillDefaults()
	delay := cfg.BaseDelay
	_, resumeDelay, exit := h.router.runSstpCycle(context.Background(), state, buf, 0, cfg, &delay)

	assert.False(t, exit, "5xx must not exit the cycle loop")
	assert.Greater(t, resumeDelay, time.Duration(0), "5xx must yield a backoff delay")
	assert.Equal(t, model.StreamStateEnabled, state.Status, "5xx must not pause the stream")
}

// TestSstpCycle_TransportBacksOffExponentially: consecutive transport failures
// grow the backoff delay per the configured factor, capped at MaxDelay (Q25).
func TestSstpCycle_TransportBacksOffExponentially(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassTransport},
	})
	h := newSstpRunnerHarness(t, adapter)

	state := sstpPairState("sstp-tx-bk", "pair-bk")
	h.persistOutboundEvent(t, "sstp-tx-bk", "jbk")
	buf := buffer.CreateEventPollBuffer(nil, 0, 0)
	t.Cleanup(buf.Close)

	cfg := sstpBackoffConfig{BaseDelay: 10 * time.Millisecond, MaxDelay: 80 * time.Millisecond, BackoffFactor: 2.0}
	cfg.fillDefaults()
	delay := cfg.BaseDelay

	_, d1, _ := h.router.runSstpCycle(context.Background(), state, buf, 0, cfg, &delay)
	_, d2, _ := h.router.runSstpCycle(context.Background(), state, buf, 0, cfg, &delay)
	_, d3, _ := h.router.runSstpCycle(context.Background(), state, buf, 0, cfg, &delay)

	assert.Equal(t, 10*time.Millisecond, d1)
	assert.Equal(t, 20*time.Millisecond, d2)
	assert.Equal(t, 40*time.Millisecond, d3)
}

// --- Acceptance: lease-loss cancels in-flight requests (race-tested) ---------

// TestSstpClient_LeaseLossCancelsInflight: with a cycle blocked mid-flight, the
// heartbeat observing lease loss must cancel the parent context, aborting the
// in-flight DeliverSstp, and the loop must return true (re-acquire) (Q14.a).
func TestSstpClient_LeaseLossCancelsInflight(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
	})
	adapter.SetBlocking()
	started := make(chan struct{}, 1)
	adapter.SetOnDeliver(func() {
		select {
		case started <- struct{}{}:
		default:
		}
	})

	// Acquire succeeds on the initial handler acquire AND the first heartbeat
	// renew (so a cycle starts), then loses the lease on the next renew.
	h := newSstpRunnerHarness(t, adapter, true, false)

	state := sstpPairState("sstp-tx-loss", "pair-loss")
	buf := buffer.CreateEventPollBuffer([]string{"x"}, 0, 0)
	t.Cleanup(buf.Close)
	// Give the runner something to "deliver" so it enters DeliverSstp.
	h.persistOutboundEvent(t, "sstp-tx-loss", "x")

	cfg := *fastSstpCfg()
	cfg.fillDefaults()

	done := make(chan bool, 1)
	go func() {
		done <- h.router.runSstpClientLoop("sstp-client:pair-loss", state, buf, 1, cfg)
	}()

	// Cycle must start.
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("DeliverSstp never started")
	}

	// Heartbeat will renew once (true) then lose (false) → cycleCtx cancelled →
	// the blocked DeliverSstp returns and the loop returns true (re-acquire).
	select {
	case retry := <-done:
		assert.True(t, retry, "lease loss must signal re-acquire (return true)")
	case <-time.After(3 * time.Second):
		t.Fatal("loop did not exit after lease loss — in-flight cancellation failed")
	}
}

// --- Acceptance: heartbeat single-retry on a blip (race-tested) -------------

// TestSstpHeartbeat_SingleRetryOnBlip: a single failed renew followed by a
// success keeps ownership (no cancellation, no spurious takeover) (Q14.c).
func TestSstpHeartbeat_SingleRetryOnBlip(t *testing.T) {
	// renew sequence: blip (false), then success (true).
	h := newSstpRunnerHarness(t, delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{}), false, true)
	cfg := *fastSstpCfg()
	cfg.fillDefaults()

	retained := h.router.renewSstpLeaseWithRetry(context.Background(), "sstp-client:pair-blip", "pair-blip", cfg)
	assert.True(t, retained, "a single blip followed by success must retain ownership")
	assert.Equal(t, 2, h.coord.AcquireCalls(), "exactly one retry after the blip")
}

// TestSstpHeartbeat_TwoFailuresLoseLease: two consecutive renew failures (blip +
// failed retry) declare the lease lost.
func TestSstpHeartbeat_TwoFailuresLoseLease(t *testing.T) {
	h := newSstpRunnerHarness(t, delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{}), false, false)
	cfg := *fastSstpCfg()
	cfg.fillDefaults()

	retained := h.router.renewSstpLeaseWithRetry(context.Background(), "sstp-client:pair-2f", "pair-2f", cfg)
	assert.False(t, retained, "two consecutive failures must declare the lease lost")
	assert.Equal(t, 2, h.coord.AcquireCalls(), "single retry only — no more than two attempts")
}

// --- Acceptance: POLL_RETRY_* knobs tune the SSTP backoff -------------------

// TestLoadSstpBackoffConfig_HonorsPollRetryEnv: the SSTP-client backoff reads the
// same POLL_RETRY_* knobs as the poll receiver, so operators tune both in one
// place (Q25).
func TestLoadSstpBackoffConfig_HonorsPollRetryEnv(t *testing.T) {
	t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "3")
	t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "120")
	t.Setenv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "4")

	cfg := loadSstpBackoffConfig()
	assert.Equal(t, 3*time.Second, cfg.BaseDelay)
	assert.Equal(t, 120*time.Second, cfg.MaxDelay)
	assert.Equal(t, 4.0, cfg.BackoffFactor)
}

func TestLoadSstpBackoffConfig_LegacyPollRetryNames(t *testing.T) {
	t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "")
	t.Setenv("POLL_RETRY_BASE_DELAY", "7")

	cfg := loadSstpBackoffConfig()
	assert.Equal(t, 7*time.Second, cfg.BaseDelay)
}

// --- Acceptance: takeover jitter is bounded to [100ms,500ms] ----------------

// TestSstpTakeoverJitter_Bounded: the default jitter is always within the
// documented 100–500ms window (Q16).
func TestSstpTakeoverJitter_Bounded(t *testing.T) {
	for i := 0; i < 1000; i++ {
		j := defaultSstpJitter()
		assert.GreaterOrEqual(t, j, sstpTakeoverJitterMin)
		assert.LessOrEqual(t, j, sstpTakeoverJitterMax)
	}
}

// --- Acceptance: graceful shutdown releases the lease -----------------------

// TestSstpClient_GracefulShutdownReleasesLease: when the router context is
// cancelled (Shutdown), the handler releases the sstp-client lease before
// returning (Q14.b).
func TestSstpClient_GracefulShutdownReleasesLease(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
	})
	h := newSstpRunnerHarness(t, adapter)

	state := sstpPairState("sstp-tx-shut", "pair-shut")
	buf := buffer.CreateEventPollBuffer(nil, 0, 0)

	handlerDone := make(chan struct{})
	go func() {
		h.router.SstpClientStreamHandler(state, buf)
		close(handlerDone)
	}()

	// Let the runner acquire and enter the loop.
	require.Eventually(t, func() bool { return h.coord.AcquireCalls() >= 1 },
		2*time.Second, 10*time.Millisecond, "runner must acquire the lease")

	h.router.Shutdown() // cancels r.ctx

	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not exit on shutdown")
	}
	assert.GreaterOrEqual(t, h.coord.Releases(), 1, "graceful shutdown must release the lease")
}

// --- Wiring: UpdateStreamState starts the runner for initiators only ---------

// TestUpdateStreamState_StartsRunnerForInitiator: feeding an initiator pair to
// the production UpdateStreamState path registers the pair and acquires the
// sstp-client lease; a responder pair does not (Q4.1, Q11.1).
func TestUpdateStreamState_StartsRunnerForInitiator(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{
		Classification: goSetSstp.Classification{Class: goSetSstp.ClassOK},
	})
	h := newSstpRunnerHarness(t, adapter)

	initiator := sstpPairState("sstp-tx-init", "pair-init")
	h.router.UpdateStreamState(initiator)

	require.Eventually(t, func() bool { return h.coord.AcquireCalls() >= 1 },
		2*time.Second, 10*time.Millisecond, "initiator must start the runner and acquire the lease")

	h.router.mu.RLock()
	_, registered := h.router.sstpClientStreams["pair-init"]
	_, hasBuf := h.router.sstpBuffers["pair-init"]
	h.router.mu.RUnlock()
	assert.True(t, registered, "initiator pair must be registered")
	assert.True(t, hasBuf, "initiator pair must get an outbound buffer")
}

func TestUpdateStreamState_NoRunnerForResponder(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	responder := sstpPairState("sstp-tx-resp", "pair-resp")
	responder.SstpMethod.Role = model.SstpRoleResponder
	h.router.UpdateStreamState(responder)

	// Give any (unwanted) runner a window to start, then assert no lease was taken
	// and no client-side bookkeeping was created.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, h.coord.AcquireCalls(), "responder must NOT take the sstp-client lease")
	h.router.mu.RLock()
	_, registered := h.router.sstpClientStreams["pair-resp"]
	h.router.mu.RUnlock()
	assert.False(t, registered, "responder must not be registered as a client runner")
}

// TestPreInitializeCounter_SstpEmitsSstpTfr: pre-initializing the counter for an
// SSTP pair primes the metric series with tfr=SSTP (Q46).
func TestPreInitializeCounter_SstpEmitsSstpTfr(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	state := sstpPairState("sstp-tx-pre", "pair-pre")
	h.router.PreInitializeCounter(state)

	v := testutil.ToFloat64(h.outCounter.With(prometheus.Labels{
		"type":      "NONE",
		"iss":       dupTestIssuer,
		"tfr":       "SSTP",
		"stream_id": "sstp-tx-pre",
	}))
	assert.Equal(t, 0.0, v, "SSTP pair must pre-initialize the eventsOut series with tfr=SSTP")
}
