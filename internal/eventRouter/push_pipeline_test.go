package eventRouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Issue #339 (ADR 0044): a push stream keeps up to K batches on the wire at
// once, K = min(push concurrency, in-flight bound / batch size).

// pipelineSeam is a PushDelivery that records arrival order and the peak
// number of concurrent Deliver calls, holding each push for hold. A JTI in
// failOnce gets that classification the first time it is pushed.
type pipelineSeam struct {
	mu       sync.Mutex
	inflight int
	peak     int
	arrivals []string
	accepted map[string]int
	failOnce map[string]goSetPush.Classification
	hold     time.Duration
}

func newPipelineSeam(hold time.Duration) *pipelineSeam {
	return &pipelineSeam{hold: hold, accepted: map[string]int{}, failOnce: map[string]goSetPush.Classification{}}
}

func (s *pipelineSeam) Deliver(_ context.Context, req delivery.PushRequest) delivery.PushOutcome {
	jti := req.Event.Jti
	s.mu.Lock()
	s.inflight++
	if s.inflight > s.peak {
		s.peak = s.inflight
	}
	s.arrivals = append(s.arrivals, jti)
	cls, fail := s.failOnce[jti]
	delete(s.failOnce, jti)
	s.mu.Unlock()

	time.Sleep(s.hold)

	s.mu.Lock()
	s.inflight--
	if !fail {
		s.accepted[jti]++
	}
	s.mu.Unlock()
	if fail {
		return delivery.PushOutcome{Classification: cls}
	}
	return delivery.PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
		Key:            req.Key,
		Kid:            req.Kid,
	}
}

func (s *pipelineSeam) snapshot() (peak int, arrivals []string, accepted map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	accepted = make(map[string]int, len(s.accepted))
	for k, v := range s.accepted {
		accepted[k] = v
	}
	return s.peak, append([]string(nil), s.arrivals...), accepted
}

// recoveryStats records push_recovery_duration_seconds observations.
type recoveryStats struct {
	mu        sync.Mutex
	durations []float64
}

func (s *recoveryStats) TrackLeaseAcquisition(string, bool)           {}
func (s *recoveryStats) IncLeasesHeld()                               {}
func (s *recoveryStats) DecLeasesHeld()                               {}
func (s *recoveryStats) RecordPushFailure(string, string)             {}
func (s *recoveryStats) RecordStateTransition(string, string, string) {}
func (s *recoveryStats) RecordIdleVerifyOutcome(string, string)       {}
func (s *recoveryStats) ObservePushRecoveryDuration(_ string, secs float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durations = append(s.durations, secs)
}

func (s *recoveryStats) observed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.durations)
}

// newPipelineHarness is a signing-push harness with a caller-chosen push
// concurrency and fast backfill / retry timers.
func newPipelineHarness(t *testing.T, seam delivery.PushDelivery, concurrency string) *filterPushHarness {
	t.Helper()
	t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "0")
	t.Setenv("I2SIG_PUSH_CONCURRENCY", concurrency)
	t.Setenv("I2SIG_PUSH_BACKFILL_INTERVAL", "50ms")
	t.Setenv("I2SIG_PUSH_RETRY_BASE_DELAY", "10ms")
	return newPushBatchHarness(t, seam)
}

func TestPushInFlightBatches_Formula(t *testing.T) {
	cases := []struct {
		concurrency, inFlightMax, want int
	}{
		{8, 256, 8},  // 256 / 32 = 8, the pool is 8
		{16, 256, 4}, // 256 / 64
		{32, 256, 2}, // 256 / 128: the ADR 0037 ceiling
		{1, 256, 1},  // I2SIG_PUSH_CONCURRENCY=1 is the ADR 0040 ordering knob
		{2, 8, 1},    // the in-flight bound holds exactly one batch of 8
		{4, 40, 2},   // 40 / 16 rounds down
		{32, 64, 1},  // the bound is raised to one full batch, never below
	}
	for _, c := range cases {
		r := &router{pushConcurrency: c.concurrency, deliveryInFlightMax: c.inFlightMax}
		assert.Equal(t, c.want, r.pushInFlightBatches(), "concurrency=%d inFlightMax=%d", c.concurrency, c.inFlightMax)
	}
}

// With K=2 and a pool of two, a stream with a deep backlog has more pushes on
// the wire than one batch's pool can open — never more than K pools — and
// every SET is delivered exactly once.
func TestPushPipeline_KBatchesInFlight(t *testing.T) {
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	seam := newPipelineSeam(40 * time.Millisecond)
	h := newPipelineHarness(t, seam, "2")
	require.Equal(t, 2, h.router.pushInFlightBatches())

	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 48)
	h.router.UpdateStreamState(stream.DeepCopy())

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 20*time.Second, 10*time.Millisecond)
	peak, _, accepted := seam.snapshot()
	assert.Greater(t, peak, 2, "a second batch goes out while the first is on the wire")
	assert.LessOrEqual(t, peak, 4, "at most K batches, each at most the pool wide")
	require.Len(t, accepted, len(jtis))
	for _, jti := range jtis {
		assert.Equal(t, 1, accepted[jti], "jti %s is delivered once", jti)
	}
}

// ADR 0040: I2SIG_PUSH_CONCURRENCY=1 collapses K to 1, so a receiver sees the
// SETs one at a time, in buffer order.
func TestPushPipeline_ConcurrencyOneKeepsArrivalOrder(t *testing.T) {
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	seam := newPipelineSeam(time.Millisecond)
	h := newPipelineHarness(t, seam, "1")
	require.Equal(t, 1, h.router.pushInFlightBatches())

	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 30)
	// The buffer order is the order the event store hands pending SETs out.
	want := pendingJtis(t, h, sid)
	require.Len(t, want, 30)
	h.router.UpdateStreamState(stream.DeepCopy())

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 20*time.Second, 10*time.Millisecond)
	peak, arrivals, _ := seam.snapshot()
	assert.Equal(t, 1, peak, "one push on the wire at a time")
	assert.Equal(t, want, arrivals, "the receiver sees the SETs in buffer order")
}

// A failure in one of K in-flight batches enters the existing T1 recovery
// path once the other batches have finished; recovery resolves (and is
// observed in push_recovery_duration_seconds), and every SET not yet
// delivered — the failed one included — is redelivered.
func TestPushPipeline_OneFailedBatchRecoversAndTheRestRedeliver(t *testing.T) {
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
	}))
	defer status.Close()

	seam := newPipelineSeam(20 * time.Millisecond)
	h := newPipelineHarness(t, seam, "2")
	stats := &recoveryStats{}
	h.router.SetStatsHandler(stats)
	require.Equal(t, 2, h.router.pushInFlightBatches())

	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, status.URL+"/events", "")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 40)
	// jtis[12] rides the second batch (8 per batch at concurrency 2).
	seam.mu.Lock()
	seam.failOnce[jtis[12]] = goSetPush.Classification{Class: goSetPush.ClassServerError}
	seam.mu.Unlock()
	h.router.UpdateStreamState(stream.DeepCopy())

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 20*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return stats.observed() > 0 }, 5*time.Second, 10*time.Millisecond,
		"push_recovery_duration_seconds is observed")

	_, _, accepted := seam.snapshot()
	require.Len(t, accepted, len(jtis), "every SET is delivered")
	assert.Equal(t, 1, accepted[jtis[12]], "the failed SET is redelivered after recovery")
	got, _ := h.storedStatus(t, sid)
	assert.Equal(t, model.StreamStateEnabled, got, "recovery resumes the stream")
}
