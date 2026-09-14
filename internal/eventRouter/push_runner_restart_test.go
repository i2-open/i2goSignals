package eventRouter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #306: a push runner captures its signing issuer, route mode and
// endpoint from the record it was started on. UpdateStreamState syncs the
// router's map copy for fan-out matching, but the runner goroutine never reads
// that copy, so a changed setting must restart the runner — stop it and start
// a fresh one on the updated record — while a status-only sync leaves the
// running runner alone. Since #309 the fresh runner starts in the background
// once the old one has exited.

func (h *testHarness) pushBufferFor(sid string) *buffer.EventPushBuffer {
	h.router.mu.RLock()
	defer h.router.mu.RUnlock()
	return h.router.pushBuffers[sid]
}

// waitReplacementBuffer waits for the restart hand-off to register a buffer
// other than prev.
func (h *testHarness) waitReplacementBuffer(t *testing.T, sid string, prev *buffer.EventPushBuffer) *buffer.EventPushBuffer {
	t.Helper()
	var next *buffer.EventPushBuffer
	require.Eventually(t, func() bool {
		next = h.pushBufferFor(sid)
		return next != nil && next != prev
	}, 10*time.Second, 5*time.Millisecond, "the restarted runner has a buffer")
	return next
}

func TestUpdateStreamState_PushRunnerRestartsOnTransmitSettingChange(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	stream := mustCreateTestStream(t, h, projectId)
	sid := stream.StreamConfiguration.Id

	h.router.UpdateStreamState(stream)
	first := h.pushBufferFor(sid)
	require.NotNil(t, first, "first registration starts a runner")

	// Status-only sync: same runner, same buffer.
	statusOnly := stream.DeepCopy()
	statusOnly.Status = model.StreamStatePause
	statusOnly.ErrorMsg = "operator paused"
	h.router.UpdateStreamState(statusOnly)
	same := h.pushBufferFor(sid)
	require.NotNil(t, same)
	assert.Same(t, first, same, "a status sync must not bounce the runner")
	assert.False(t, first.IsClosed())

	// route_mode change: the runner is restarted on a fresh buffer.
	changed := stream.DeepCopy()
	changed.StreamConfiguration.RouteMode = model.RouteModeForward
	h.router.UpdateStreamState(changed)
	assert.True(t, first.IsClosed(), "the previous runner's buffer is closed so it exits")
	second := h.waitReplacementBuffer(t, sid, first)
	assert.NotSame(t, first, second, "a changed transmit setting starts a new runner")

	h.router.mu.RLock()
	synced := h.router.pushStreams[sid]
	h.router.mu.RUnlock()
	assert.Equal(t, model.RouteModeForward, synced.GetRouteMode(), "the map copy carries the new mode for fan-out matching")

	// iss change restarts too; aud change restarts too.
	issChanged := changed.DeepCopy()
	issChanged.StreamConfiguration.Iss = "https://other-issuer.example"
	h.router.UpdateStreamState(issChanged)
	assert.True(t, second.IsClosed())
	third := h.waitReplacementBuffer(t, sid, second)
	assert.NotSame(t, second, third)
}

func TestPushRunnerSettingsChanged(t *testing.T) {
	base := model.StreamConfiguration{
		Iss:       "https://iss.example",
		Aud:       []string{"a", "b"},
		RouteMode: model.RouteModePublish,
		Delivery: &model.OneOfStreamConfigurationDelivery{PushTransmitMethod: &model.PushTransmitMethod{
			Method: model.DeliveryPush, EndpointUrl: "https://rx.example/events", AuthorizationHeader: "Bearer x",
		}},
	}
	mutate := func(f func(c *model.StreamConfiguration)) model.StreamConfiguration {
		c := base.DeepCopy()
		f(&c)
		return c
	}
	assert.False(t, pushRunnerSettingsChanged(base, base.DeepCopy()), "identical settings")
	assert.False(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.Description = "x" })), "description is not a runner setting")
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.RouteMode = model.RouteModeForward })))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.Iss = "https://new.example" })))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.Aud = []string{"a"} })))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) { c.SigningAlg = "ES256" })))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) {
		c.Delivery.PushTransmitMethod.EndpointUrl = "https://rx2.example/events"
	})))
	assert.True(t, pushRunnerSettingsChanged(base, mutate(func(c *model.StreamConfiguration) {
		c.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer y"
	})))
}

// Issue #309: a restart must stop the old runner after at most the batch it is
// already sending and start the new runner only once the old one has exited,
// so nothing goes out with the old settings afterwards and nothing is sent
// twice.

// recordedPush is one push a holdingReceiver saw, with the transmit settings
// the runner pushed it under.
type recordedPush struct {
	jti       string
	auth      string
	endpoint  string
	routeMode string
}

// holdingReceiver is a PushDelivery that records every push and holds each
// request until the test releases it, so a restart can land while a batch is
// in flight. classify decides the outcome of each push; nil accepts all.
type holdingReceiver struct {
	mu       sync.Mutex
	pushes   []recordedPush
	entered  chan struct{}
	gate     chan struct{}
	gateOnce sync.Once
	classify func(p recordedPush) goSetPush.FailureClass
}

func newHoldingReceiver() *holdingReceiver {
	return &holdingReceiver{entered: make(chan struct{}, 1024), gate: make(chan struct{})}
}

func (rx *holdingReceiver) Deliver(ctx context.Context, req delivery.PushRequest) delivery.PushOutcome {
	mode := req.Stream.GetRouteMode()
	if mode == "" {
		mode = model.RouteModePublish
	}
	p := recordedPush{
		jti:       req.Event.Jti,
		auth:      req.Stream.StreamConfiguration.Delivery.GetAuthorizationHeader(),
		endpoint:  req.Stream.StreamConfiguration.Delivery.GetEndpointUrl(),
		routeMode: mode,
	}
	rx.mu.Lock()
	rx.pushes = append(rx.pushes, p)
	classify := rx.classify
	rx.mu.Unlock()
	rx.entered <- struct{}{}

	hold := time.NewTimer(10 * time.Second)
	defer hold.Stop()
	select {
	case <-rx.gate:
	case <-ctx.Done():
	case <-hold.C:
	}

	class := goSetPush.ClassAccepted
	if classify != nil {
		class = classify(p)
	}
	return delivery.PushOutcome{Classification: goSetPush.Classification{Class: class}, Key: req.Key, Kid: req.Kid}
}

// release lets every held and future request complete.
func (rx *holdingReceiver) release() {
	rx.gateOnce.Do(func() { close(rx.gate) })
}

// waitEntered blocks until a push has reached the receiver.
func (rx *holdingReceiver) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-rx.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no push reached the receiver")
	}
}

func (rx *holdingReceiver) snapshot() []recordedPush {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	return append([]recordedPush(nil), rx.pushes...)
}

// settle waits until the receiver has seen no new push for a quiet period, so
// a late duplicate has had the chance to show up before the test counts.
func (rx *holdingReceiver) settle(t *testing.T) []recordedPush {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last := -1
	for time.Now().Before(deadline) {
		n := len(rx.snapshot())
		if n == last {
			return rx.snapshot()
		}
		last = n
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("receiver never went quiet")
	return nil
}

// newRestartHarness is a push router whose runners deliver through rx, with
// the receiver status-poll and T3 keepalive off so the only traffic is the
// pending events, and a serial pool so the in-flight batch is at most
// pushBatchMax (4) SETs.
func newRestartHarness(t *testing.T, rx *holdingReceiver) *filterPushHarness {
	t.Helper()
	return newRestartHarnessWith(t, rx, nil)
}

// newRestartHarnessWith is newRestartHarness with the router's coordinator
// passed through wrap (nil keeps the store's own).
func newRestartHarnessWith(t *testing.T, rx *holdingReceiver, wrap func(cluster.ClusterCoordinator) cluster.ClusterCoordinator) *filterPushHarness {
	t.Helper()
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "0")
	t.Setenv("I2SIG_PUSH_CONCURRENCY", "1")
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Cleanup(rx.release)

	persistence, err := dbProviders.OpenPersistence("memorydb:", "push_runner_restart_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})
	coordinator := persistence.Coordinator
	if wrap != nil {
		coordinator = wrap(coordinator)
	}
	r := NewRouter(RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          coordinator,
		SubjectFilterService: persistence.SubjectFilterService,
		PushDelivery:         rx,
	}, "node-restart").(*router)
	t.Cleanup(r.Shutdown)

	return &filterPushHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
		eventService:  persistence.EventService,
		subjectFilter: persistence.SubjectFilterService,
	}
}

func (h *filterPushHarness) runnerFor(sid string) *pushRunner {
	h.router.mu.RLock()
	defer h.router.mu.RUnlock()
	return h.router.pushRunners[sid]
}

func (h *filterPushHarness) handoffFor(sid string) *pushHandoff {
	h.router.mu.RLock()
	defer h.router.mu.RUnlock()
	return h.router.pushHandoffs[sid]
}

// waitReplacementRunner waits for a restart hand-off to register a runner
// other than prev.
func (h *filterPushHarness) waitReplacementRunner(t *testing.T, sid string, prev *pushRunner) *pushRunner {
	t.Helper()
	var next *pushRunner
	require.Eventually(t, func() bool {
		next = h.runnerFor(sid)
		return next != nil && next != prev
	}, 10*time.Second, 5*time.Millisecond, "the hand-off starts a new runner")
	return next
}

func waitClosed(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(msg)
	}
}

func waitFinished(t *testing.T, runner *pushRunner, msg string) {
	t.Helper()
	require.NotNil(t, runner)
	waitClosed(t, runner.finished(), msg)
}

// countingCoordinator counts lease attempts, so a test knows a runner has
// reached the lease wait.
type countingCoordinator struct {
	cluster.ClusterCoordinator
	attempts atomic.Int64
}

func (c *countingCoordinator) TryAcquireOrRenewLease(resource, nodeId string, d time.Duration) (bool, int64, error) {
	c.attempts.Add(1)
	return c.ClusterCoordinator.TryAcquireOrRenewLease(resource, nodeId, d)
}

func deliveriesByJti(pushes []recordedPush) map[string][]recordedPush {
	out := map[string][]recordedPush{}
	for _, p := range pushes {
		out[p.jti] = append(out[p.jti], p)
	}
	return out
}

// With ten pending events and a receiver that holds each request, rotating the
// authorization header while a batch is in flight delivers every JTI exactly
// once, returns from the update without waiting for the batch, and puts the new
// header on every request after the in-flight batch.
func TestPushRunnerRestart_HeaderRotationDeliversOnceAndStopsOldHeader(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	stream.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer old"
	jtis := h.addPendingEvents(t, sid, 10)

	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)

	rotated := stream.DeepCopy()
	rotated.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer new"
	returned := make(chan struct{})
	go func() {
		h.router.UpdateStreamState(rotated)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("UpdateStreamState waited for the in-flight batch")
	}
	rx.release()

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 10*time.Millisecond)
	pushes := rx.settle(t)

	byJti := deliveriesByJti(pushes)
	require.Len(t, byJti, len(jtis))
	for _, jti := range jtis {
		assert.Len(t, byJti[jti], 1, "jti %s must be delivered exactly once", jti)
	}

	oldHeader, seenNew := 0, false
	for _, p := range pushes {
		if p.auth == "Bearer new" {
			seenNew = true
			continue
		}
		assert.False(t, seenNew, "a request with the old header went out after the new header (jti %s)", p.jti)
		oldHeader++
	}
	assert.True(t, seenNew, "the new runner delivered the rest of the backlog")
	assert.LessOrEqual(t, oldHeader, h.router.pushBatchMax(), "only the in-flight batch may carry the old header")
}

// Changing route_mode from PB to FW with pending events never delivers an
// event in both forms.
func TestPushRunnerRestart_RouteModeChangeNeverDeliversBothForms(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	stream.StreamConfiguration.RouteMode = model.RouteModePublish
	jtis := h.addPendingEvents(t, sid, 10)

	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)

	forward := stream.DeepCopy()
	forward.StreamConfiguration.RouteMode = model.RouteModeForward
	h.router.UpdateStreamState(forward)
	rx.release()

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 10*time.Millisecond)
	byJti := deliveriesByJti(rx.settle(t))
	require.Len(t, byJti, len(jtis))
	for _, jti := range jtis {
		assert.Len(t, byJti[jti], 1, "jti %s must be delivered once, in one form", jti)
	}
}

// A runner in recoveryLoop (the receiver returned 5xx and the backoff sleep is
// an hour) exits after a restart-triggering update, and only the successor is
// live afterwards.
func TestPushRunnerRestart_RunnerInRecoveryExits(t *testing.T) {
	t.Setenv("I2SIG_PUSH_RETRY_BASE_DELAY", "1h")
	rx := newHoldingReceiver()
	rx.release()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	oldEndpoint := stream.StreamConfiguration.Delivery.GetEndpointUrl()
	rx.mu.Lock()
	rx.classify = func(p recordedPush) goSetPush.FailureClass {
		if p.endpoint == oldEndpoint {
			return goSetPush.ClassServerError
		}
		return goSetPush.ClassAccepted
	}
	rx.mu.Unlock()
	h.addPendingEvents(t, sid, 1)

	h.router.UpdateStreamState(stream.DeepCopy())
	// The 5xx sends the runner into transport-backoff recovery, which pauses
	// the stream and then sleeps.
	require.Eventually(t, func() bool {
		st, err := h.streamService.GetStreamState(context.Background(), sid)
		return err == nil && st.Status == model.StreamStatePause
	}, 5*time.Second, 5*time.Millisecond, "the runner entered recovery")
	old := h.runnerFor(sid)

	moved := stream.DeepCopy()
	moved.StreamConfiguration.Delivery.PushTransmitMethod.EndpointUrl = "https://receiver2.example.com/events"
	h.router.UpdateStreamState(moved)

	waitFinished(t, old, "the runner in recoveryLoop exits after the restart")
	h.waitReplacementRunner(t, sid, old)
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 10*time.Millisecond,
		"the successor delivers to the new endpoint")
	assert.Equal(t, int64(1), h.router.runningPushRunners.Load(), "only one runner is live for the stream")
	assert.True(t, h.router.pushRunnerLive(sid))
}

// A runner waiting for the lease (another node holds it) exits after a
// restart-triggering update rather than after its 15s retry delay.
func TestPushRunnerRestart_RunnerWaitingForLeaseExits(t *testing.T) {
	rx := newHoldingReceiver()
	rx.release()
	coord := &countingCoordinator{}
	h := newRestartHarnessWith(t, rx, func(c cluster.ClusterCoordinator) cluster.ClusterCoordinator {
		coord.ClusterCoordinator = c
		return coord
	})
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	held, _, err := coord.ClusterCoordinator.TryAcquireOrRenewLease("push-transmitter:"+sid, "node-other", time.Hour)
	require.NoError(t, err)
	require.True(t, held)

	h.router.UpdateStreamState(stream.DeepCopy())
	require.Eventually(t, func() bool { return coord.attempts.Load() >= 1 }, 5*time.Second, 5*time.Millisecond)
	old := h.runnerFor(sid)
	require.True(t, old.live(), "the runner is waiting for the lease")

	moved := stream.DeepCopy()
	moved.StreamConfiguration.Delivery.PushTransmitMethod.EndpointUrl = "https://receiver2.example.com/events"
	h.router.UpdateStreamState(moved)

	waitFinished(t, old, "the runner waiting for the lease exits after the restart")
	h.waitReplacementRunner(t, sid, old)
	assert.Equal(t, int64(1), h.router.runningPushRunners.Load(), "only the successor is live")
}

// Two restart-triggering updates in quick succession leave exactly one live
// runner, using the second update's settings.
func TestPushRunnerRestart_TwoQuickUpdatesLeaveOneRunnerOnSecondSettings(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	stream.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer A"
	jtis := h.addPendingEvents(t, sid, 10)

	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)
	old := h.runnerFor(sid)

	second := stream.DeepCopy()
	second.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer B"
	h.router.UpdateStreamState(second)
	handoff := h.handoffFor(sid)
	require.NotNil(t, handoff, "the first update leaves a hand-off pending while the batch is held")

	third := stream.DeepCopy()
	third.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer C"
	h.router.UpdateStreamState(third)
	assert.Same(t, handoff, h.handoffFor(sid), "the second update joins the pending hand-off")
	rx.release()

	waitClosed(t, handoff.done, "the hand-off completes")
	waitFinished(t, old, "the old runner exits")
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 10*time.Millisecond)
	pushes := rx.settle(t)

	byJti := deliveriesByJti(pushes)
	require.Len(t, byJti, len(jtis))
	for _, jti := range jtis {
		assert.Len(t, byJti[jti], 1, "jti %s must be delivered exactly once", jti)
	}
	for _, p := range pushes {
		assert.NotEqual(t, "Bearer B", p.auth, "no runner ever ran on the superseded settings")
	}
	assert.Equal(t, "Bearer C", pushes[len(pushes)-1].auth, "the successor runs on the second update's settings")
	assert.Equal(t, int64(1), h.router.runningPushRunners.Load(), "exactly one runner is live")
	assert.True(t, h.router.pushRunnerLive(sid))
}

// RemoveStream during a pending hand-off cancels it: no runner starts and none
// is left live.
func TestPushRunnerRestart_RemoveStreamDuringHandoffLeavesNoRunner(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 10)

	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)
	old := h.runnerFor(sid)

	rotated := stream.DeepCopy()
	rotated.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer new"
	h.router.UpdateStreamState(rotated)
	handoff := h.handoffFor(sid)
	require.NotNil(t, handoff)

	h.router.RemoveStream(sid)
	rx.release()

	waitClosed(t, handoff.done, "the cancelled hand-off returns")
	waitFinished(t, old, "the old runner exits")
	assert.Equal(t, int64(0), h.router.runningPushRunners.Load(), "no runner is live")
	assert.False(t, h.router.pushRunnerLive(sid))
	assert.Nil(t, h.runnerFor(sid))
	for _, p := range rx.settle(t) {
		assert.NotEqual(t, "Bearer new", p.auth, "nothing is delivered for a removed stream")
	}
}

// A status change to anything but enabled during a pending hand-off is saved,
// and the runner the hand-off starts exits as it does for a non-enabled stream.
func TestPushRunnerRestart_PauseDuringHandoffIsHonoured(t *testing.T) {
	rx := newHoldingReceiver()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 10)

	h.router.UpdateStreamState(stream.DeepCopy())
	rx.waitEntered(t)
	old := h.runnerFor(sid)

	rotated := stream.DeepCopy()
	rotated.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer new"
	h.router.UpdateStreamState(rotated)
	handoff := h.handoffFor(sid)
	require.NotNil(t, handoff)

	paused := rotated.DeepCopy()
	paused.Status = model.StreamStatePause
	h.router.UpdateStreamState(paused)
	rx.release()

	waitClosed(t, handoff.done, "the hand-off completes")
	waitFinished(t, old, "the old runner exits")
	h.router.mu.RLock()
	saved := h.router.pushStreams[sid]
	h.router.mu.RUnlock()
	assert.Equal(t, model.StreamStatePause, saved.Status, "the pause is saved")
	require.Eventually(t, func() bool { return h.router.runningPushRunners.Load() == 0 }, 5*time.Second, 5*time.Millisecond,
		"the runner started on a paused record exits")
	assert.False(t, h.router.pushRunnerLive(sid))
	assert.Positive(t, h.pendingCount(sid), "a paused stream keeps its events queued")
	for _, p := range rx.settle(t) {
		assert.NotEqual(t, "Bearer new", p.auth, "nothing is delivered on a paused stream")
	}
}

// After a restart the lease-owner cache still names this node: the old
// runner's forget has run before the successor notes its acquisition.
func TestPushRunnerRestart_LeaseOwnerCacheStillNamesThisNode(t *testing.T) {
	rx := newHoldingReceiver()
	rx.release()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	resource := "push-transmitter:" + sid
	cachedOwner := func() string {
		return h.router.leaseOwners.owner(resource, func() (string, error) { return "", errors.New("not cached") })
	}

	h.router.UpdateStreamState(stream.DeepCopy())
	require.Eventually(t, func() bool { return cachedOwner() == h.router.nodeId }, 5*time.Second, 5*time.Millisecond)
	old := h.runnerFor(sid)

	rotated := stream.DeepCopy()
	rotated.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = "Bearer new"
	h.router.UpdateStreamState(rotated)
	waitFinished(t, old, "the old runner exits")
	h.waitReplacementRunner(t, sid, old)

	require.Eventually(t, func() bool { return cachedOwner() == h.router.nodeId }, 5*time.Second, 5*time.Millisecond,
		"the successor notes this node as the lease owner")
	require.Never(t, func() bool { return cachedOwner() != h.router.nodeId }, 300*time.Millisecond, 10*time.Millisecond,
		"nothing of the old runner is left to clear the successor's note")
}

// Repeated restarts leave no runner behind: the runner count returns to one,
// and every pending event is still delivered exactly once.
func TestPushRunnerRestart_RepeatedRestartsLeaveOneRunner(t *testing.T) {
	rx := newHoldingReceiver()
	rx.release()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 20)

	h.router.UpdateStreamState(stream.DeepCopy())
	current := h.runnerFor(sid)
	var retired []*pushRunner
	for i := 0; i < 5; i++ {
		next := stream.DeepCopy()
		next.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader = fmt.Sprintf("Bearer %d", i)
		h.router.UpdateStreamState(next)
		retired = append(retired, current)
		current = h.waitReplacementRunner(t, sid, current)
	}
	for _, old := range retired {
		waitFinished(t, old, "every retired runner exits")
	}

	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 10*time.Millisecond)
	byJti := deliveriesByJti(rx.settle(t))
	require.Len(t, byJti, len(jtis))
	for _, jti := range jtis {
		assert.Len(t, byJti[jti], 1, "jti %s must be delivered exactly once", jti)
	}
	assert.Equal(t, int64(1), h.router.runningPushRunners.Load(), "the runner count returns to one")
	assert.True(t, current.live())
}
