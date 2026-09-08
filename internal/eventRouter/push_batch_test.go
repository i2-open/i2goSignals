package eventRouter

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
)

// inflightAdapter is a PushDelivery that reports every push accepted after
// holding it for `hold`, and records the peak number of concurrent Deliver
// calls so a test can see the worker pool's fan-out (ADR 0035).
type inflightAdapter struct {
	mu       sync.Mutex
	inflight int
	peak     int
	calls    int
	hold     time.Duration
}

func (a *inflightAdapter) Deliver(_ context.Context, req delivery.PushRequest) delivery.PushOutcome {
	a.mu.Lock()
	a.inflight++
	if a.inflight > a.peak {
		a.peak = a.inflight
	}
	a.mu.Unlock()

	time.Sleep(a.hold)

	a.mu.Lock()
	a.inflight--
	a.calls++
	a.mu.Unlock()
	return delivery.PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
		Key:            req.Key,
		Kid:            req.Kid,
	}
}

func (a *inflightAdapter) stats() (calls, peak int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls, a.peak
}

// newPushBatchHarness is newFilterPushRouter with a caller-supplied delivery
// seam. The returned harness's adapter field is only set when seam is a
// MemoryAdapter.
func newPushBatchHarness(t *testing.T, seam delivery.PushDelivery) *filterPushHarness {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "push_batch_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})

	r := NewRouter(RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          persistence.Coordinator,
		SubjectFilterService: persistence.SubjectFilterService,
		PushDelivery:         seam,
	}, "node-push-batch").(*router)
	t.Cleanup(r.Shutdown)

	h := &filterPushHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
		eventService:  persistence.EventService,
		subjectFilter: persistence.SubjectFilterService,
	}
	if m, ok := seam.(*delivery.MemoryAdapter); ok {
		h.adapter = m
	}
	return h
}

func (h *filterPushHarness) addPendingEvents(t *testing.T, sid string, n int) []string {
	t.Helper()
	jtis := make([]string, 0, n)
	for i := 0; i < n; i++ {
		jtis = append(jtis, h.addPendingEvent(t, sid, emailSubjectFor("batch@example.com"), false))
	}
	return jtis
}

// TestPushBatch_PoolFansOutAndAcksTheBatch: ten pending SETs on a stream with
// the default pool run through more than one worker at a time, never more than
// the configured concurrency, and every 202 is acked in the one batch ack.
func TestPushBatch_PoolFansOutAndAcksTheBatch(t *testing.T) {
	seam := &inflightAdapter{hold: 50 * time.Millisecond}
	h := newPushBatchHarness(t, seam)
	require.Equal(t, defaultPushConcurrency(), h.router.pushConcurrency)

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 10)
	require.Equal(t, 10, h.pendingCount(sid))

	res := h.router.pushBatch(jtis, stream, nil, "", 0)

	require.Empty(t, res.failedJti)
	require.Equal(t, 10, res.acked)
	require.Equal(t, 0, h.pendingCount(sid), "every accepted SET is acked")

	calls, peak := seam.stats()
	require.Equal(t, 10, calls)
	require.LessOrEqual(t, peak, defaultPushConcurrency(), "pool never exceeds I2SIG_PUSH_CONCURRENCY")
	require.GreaterOrEqual(t, peak, 2, "pool actually runs pushes side by side (peak %d)", peak)
}

// TestPushBatch_ConcurrencyOneIsSerial: I2SIG_PUSH_CONCURRENCY=1 keeps the
// batched reads and acks but never overlaps two POSTs.
func TestPushBatch_ConcurrencyOneIsSerial(t *testing.T) {
	t.Setenv("I2SIG_PUSH_CONCURRENCY", "1")
	seam := &inflightAdapter{hold: 5 * time.Millisecond}
	h := newPushBatchHarness(t, seam)
	require.Equal(t, 1, h.router.pushConcurrency)
	require.Equal(t, 4, h.router.pushBatchMax())

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 6)

	res := h.router.pushBatch(jtis, stream, nil, "", 0)
	require.Equal(t, 6, res.acked)
	require.Equal(t, 0, h.pendingCount(sid))
	calls, peak := seam.stats()
	require.Equal(t, 6, calls)
	require.Equal(t, 1, peak)
}

// TestPushBatch_FirstFailureStopsDispatchAndLeavesRestPending: with a serial
// pool the third push fails on transport; the two 202s before it are acked,
// the failure is reported as the batch's failure, and the failed plus the
// never-dispatched JTIs stay pending for backfill.
func TestPushBatch_FirstFailureStopsDispatchAndLeavesRestPending(t *testing.T) {
	t.Setenv("I2SIG_PUSH_CONCURRENCY", "1")
	accepted := delivery.PushOutcome{Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted}}
	failed := delivery.PushOutcome{Classification: goSetPush.Classification{Class: goSetPush.ClassTransport}}
	seam := delivery.NewMemoryScript(accepted, accepted, failed, accepted, accepted)
	h := newPushBatchHarness(t, seam)

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 5)

	res := h.router.pushBatch(jtis, stream, nil, "", 0)

	require.Equal(t, jtis[2], res.failedJti)
	require.Equal(t, goSetPush.ClassTransport, res.failedCls.Class)
	require.Equal(t, 2, res.acked)
	require.Equal(t, 3, seam.Calls(), "pool stops taking work after the failure")
	require.Equal(t, 3, h.pendingCount(sid), "failed and undispatched SETs remain pending")
}

// TestPushBatch_MissingRecordIsSkippedNotFailed: a JTI whose record was
// deleted between buffer pop and dispatch is neither pushed nor reported as a
// failure; the rest of the batch proceeds.
func TestPushBatch_MissingRecordIsSkippedNotFailed(t *testing.T) {
	seam := delivery.NewMemoryAdapter(delivery.PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
	})
	h := newPushBatchHarness(t, seam)

	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 2)
	batch := []string{jtis[0], "jti-never-stored", jtis[1]}

	res := h.router.pushBatch(batch, stream, nil, "", 0)

	require.Empty(t, res.failedJti)
	require.Equal(t, 2, res.acked)
	require.Equal(t, 2, seam.Calls())
	require.Equal(t, 0, h.pendingCount(sid))
}

// TestNewRouter_PushConcurrencyEnv: the knob is read at construction; an
// invalid value falls back to the default.
func TestNewRouter_PushConcurrencyEnv(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Setenv("I2SIG_PUSH_CONCURRENCY", "3")
		h := newPushBatchHarness(t, delivery.NewMemoryAdapter(delivery.PushOutcome{}))
		require.Equal(t, 3, h.router.pushConcurrency)
		require.Equal(t, 12, h.router.pushBatchMax())
	})
	t.Run("invalid", func(t *testing.T) {
		t.Setenv("I2SIG_PUSH_CONCURRENCY", "0")
		h := newPushBatchHarness(t, delivery.NewMemoryAdapter(delivery.PushOutcome{}))
		require.Equal(t, defaultPushConcurrency(), h.router.pushConcurrency)
	})
}

// TestClampPushConcurrency_HoldsTheMeasuredPlateau: the ADR 0037 derivation is
// the processor count clamped into the range the sweep measured, so a small
// container is not left near-serial on latency-bound work and a large one does
// not grow the ack-deferral window past 128 SETs for no measured gain.
func TestClampPushConcurrency_HoldsTheMeasuredPlateau(t *testing.T) {
	for _, tc := range []struct {
		procs int
		want  int
	}{
		{procs: 1, want: minPushConcurrency},
		{procs: 4, want: minPushConcurrency},
		{procs: minPushConcurrency, want: minPushConcurrency},
		{procs: 14, want: 14},
		{procs: maxPushConcurrency, want: maxPushConcurrency},
		{procs: 64, want: maxPushConcurrency},
		{procs: 256, want: maxPushConcurrency},
	} {
		require.Equal(t, tc.want, clampPushConcurrency(tc.procs), "procs=%d", tc.procs)
	}
}

// TestDefaultPushConcurrency_FollowsGOMAXPROCS: the default is read from the
// processors the process can actually see, not from a constant.
func TestDefaultPushConcurrency_FollowsGOMAXPROCS(t *testing.T) {
	restore := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(restore) })

	runtime.GOMAXPROCS(1)
	require.Equal(t, minPushConcurrency, defaultPushConcurrency(), "a one-processor host takes the floor")

	runtime.GOMAXPROCS(maxPushConcurrency + 8)
	require.Equal(t, maxPushConcurrency, defaultPushConcurrency(), "a large host takes the ceiling")

	runtime.GOMAXPROCS(12)
	require.Equal(t, 12, defaultPushConcurrency(), "in between, the processor count is the default")
	require.Equal(t, 48, (&router{pushConcurrency: defaultPushConcurrency()}).pushBatchMax(),
		"the ack-deferral window is 4x the derived default")
}

// TestDrainPushBatch_FillsFromQueuedBuffer: fifty queued JTIs come out of the
// real push buffer as 20, 20, 10 with a cap of 20, and a single queued JTI
// comes out alone without blocking.
func TestDrainPushBatch_FillsFromQueuedBuffer(t *testing.T) {
	jtis := make([]string, 50)
	for i := range jtis {
		jtis[i] = "j"
	}
	buf := buffer.CreateEventPushBuffer(jtis)
	t.Cleanup(buf.Close)

	var sizes []int
	for got := 0; got < 50; {
		first := (<-buf.Out).(string)
		batch := drainPushBatch(first, buf.Out, buf, 20)
		sizes = append(sizes, len(batch))
		got += len(batch)
	}
	require.Equal(t, []int{20, 20, 10}, sizes)

	buf.SubmitEvent("solo")
	first := (<-buf.Out).(string)
	done := make(chan []string, 1)
	go func() { done <- drainPushBatch(first, buf.Out, buf, 20) }()
	select {
	case batch := <-done:
		require.Equal(t, []string{"solo"}, batch)
	case <-time.After(2 * time.Second):
		t.Fatal("drainPushBatch blocked on an empty buffer")
	}
}
