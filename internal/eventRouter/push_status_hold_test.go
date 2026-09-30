package eventRouter

import (
	"context"
	"testing"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// submitPending adds n pending events to sid and hands them to its runner's
// buffer, as a local ingest does.
func (h *filterPushHarness) submitPending(t *testing.T, sid string, n int) []string {
	t.Helper()
	jtis := h.addPendingEvents(t, sid, n)
	h.router.mu.RLock()
	buf, ok := h.router.pushBuffers[sid]
	h.router.mu.RUnlock()
	require.True(t, ok, "the stream has a push buffer")
	for _, jti := range jtis {
		buf.SubmitEvent(jti)
	}
	return jtis
}

// setStatus stores an operator status change and applies the stored record,
// as the status handler (and a peer's stream-changed call) does.
func (h *filterPushHarness) setStatus(t *testing.T, sid, status, reason string) {
	t.Helper()
	ctx := context.Background()
	h.streamService.UpdateStreamStatus(ctx, sid, status, reason)
	rec, err := h.streamService.GetStreamState(ctx, sid)
	require.NoError(t, err)
	h.router.UpdateStreamState(rec)
}

// startDeliveringPushStream creates a push stream, starts its runner and
// waits for it to deliver one SET, so the runner is live and holds the lease.
func startDeliveringPushStream(t *testing.T) (*filterPushHarness, *holdingReceiver, string) {
	t.Helper()
	rx := newHoldingReceiver()
	rx.release()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	h.router.UpdateStreamState(stream.DeepCopy())
	require.Eventually(t, func() bool {
		h.router.mu.RLock()
		defer h.router.mu.RUnlock()
		_, ok := h.router.pushBuffers[sid]
		return ok
	}, 5*time.Second, 5*time.Millisecond)
	h.submitPending(t, sid, 1)
	rx.waitEntered(t)
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 5*time.Second, 10*time.Millisecond)
	return h, rx, sid
}

// An operator's pause or disable stops a live, delivering runner: the SETs
// that arrive afterwards stay pending and nothing more is sent. The runner
// exits and gives up the stream, and a re-enable starts one that sends them.
func TestPushStatusHold_OperatorPauseStopsLiveRunner(t *testing.T) {
	for _, status := range []string{model.StreamStatePause, model.StreamStateDisable} {
		t.Run(status, func(t *testing.T) {
			h, rx, sid := startDeliveringPushStream(t)
			runner := h.runnerFor(sid)

			h.setStatus(t, sid, status, "operator hold")
			sent := len(rx.snapshot())
			// The hold retired the runner and its buffer at once, so SETs routed
			// now are only stored pending, as on a node with no runner.
			h.addPendingEvents(t, sid, 2)

			waitFinished(t, runner, "the runner exits once the stream is held off")
			assert.Len(t, rx.settle(t), sent, "nothing is sent on a held-off stream")
			assert.Equal(t, 2, h.pendingCount(sid), "the SETs stay pending")
			assert.False(t, h.router.pushRunnerLive(sid))
			stored, reason := h.storedStatus(t, sid)
			assert.Equal(t, status, stored)
			assert.Equal(t, "operator hold", reason, "the runner leaves the operator's status alone")

			h.reEnable(t, sid)
			require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 20*time.Millisecond,
				"the re-enabled stream delivers what queued meanwhile")
			assert.Len(t, rx.snapshot(), sent+2)
		})
	}
}

// An idle runner on a paused stream exits on its next backfill tick, so it
// does not hold the stream's lease until a SET happens to arrive.
func TestPushStatusHold_IdleRunnerExitsOnPause(t *testing.T) {
	h, _, sid := startDeliveringPushStream(t)
	runner := h.runnerFor(sid)

	h.setStatus(t, sid, model.StreamStatePause, "operator hold")

	waitFinished(t, runner, "the idle runner exits on the backfill tick")
	assert.False(t, h.router.pushRunnerLive(sid))
}

// A pushStreams copy left paused while the store says enabled (a sync made
// during a pause the runner has since ended itself) does not hold the runner
// off: the store decides, and the copy is refreshed.
func TestPushStatusHold_StaleCopyDoesNotHoldOff(t *testing.T) {
	h, rx, sid := startDeliveringPushStream(t)
	runner := h.runnerFor(sid)

	h.router.mu.Lock()
	stale := h.router.pushStreams[sid]
	stale.SetStatus(model.StreamStatePause, "runner's own pause, since ended")
	h.router.pushStreams[sid] = stale
	h.router.mu.Unlock()

	sent := len(rx.snapshot())
	h.submitPending(t, sid, 1)
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Len(t, rx.snapshot(), sent+1)
	assert.True(t, runner.live(), "the runner keeps running")

	h.router.mu.RLock()
	refreshed := h.router.pushStreams[sid].Status
	h.router.mu.RUnlock()
	assert.Equal(t, model.StreamStateEnabled, refreshed, "the copy is refreshed from the store")
}

// A runner that takes the stream's lease reads the stream from the store
// before pushing: a copy that says enabled while the store says paused (a
// change made elsewhere this node has not caught up with) delivers nothing,
// and the runner exits.
func TestPushStatusHold_TakeoverReadsTheStore(t *testing.T) {
	rx := newHoldingReceiver()
	rx.release()
	h := newRestartHarness(t, rx)
	stream := h.createPushStream(t, "NONE")
	sid := stream.StreamConfiguration.Id
	h.addPendingEvents(t, sid, 2)
	h.streamService.UpdateStreamStatus(context.Background(), sid, model.StreamStatePause, "paused elsewhere")

	stale := stream.DeepCopy()
	require.Equal(t, model.StreamStateEnabled, stale.Status)
	h.router.UpdateStreamState(stale)

	var runner *pushRunner
	require.Eventually(t, func() bool { runner = h.runnerFor(sid); return runner != nil }, 5*time.Second, 5*time.Millisecond)
	waitFinished(t, runner, "the runner exits after reading the paused stream")
	assert.Empty(t, rx.settle(t), "nothing is delivered on a stream the store says is paused")
	assert.Equal(t, 2, h.pendingCount(sid), "the SETs stay pending")
	stored, reason := h.storedStatus(t, sid)
	assert.Equal(t, model.StreamStatePause, stored)
	assert.Equal(t, "paused elsewhere", reason)
}

// runnerPauseReason is a pause reason as a push runner stores it for its own
// receiver-recovery pause, here as read back from another node's runner.
const runnerPauseReason = "PUSH-SRV: transport failure on jti=x; entering transport-backoff recovery"

// A pause stored by a runner itself, on this node or another, leaves this
// node's runner running: a standby keeps waiting for the lease, so it can take
// the stream over if the holder dies mid-recovery.
func TestPushStatusHold_RunnerPauseKeepsStandby(t *testing.T) {
	h, _, sid := startDeliveringPushStream(t)
	runner := h.runnerFor(sid)

	h.setStatus(t, sid, model.StreamStatePause, runnerPauseReason)

	assert.Never(t, func() bool { return !runner.live() }, 300*time.Millisecond, 20*time.Millisecond,
		"a runner's own pause does not retire the runner")
	assert.Same(t, runner, h.runnerFor(sid))
}

// A runner that takes the lease of a stream stored with a runner's own pause
// (its last holder died mid-recovery) ends that pause and delivers, whether
// its copy was enabled or was synced with the pause.
func TestPushStatusHold_TakeoverResumesRunnerPause(t *testing.T) {
	for name, copyPaused := range map[string]bool{"enabled copy": false, "paused copy": true} {
		t.Run(name, func(t *testing.T) {
			rx := newHoldingReceiver()
			rx.release()
			h := newRestartHarness(t, rx)
			stream := h.createPushStream(t, "NONE")
			sid := stream.StreamConfiguration.Id
			h.addPendingEvents(t, sid, 2)
			h.streamService.UpdateStreamStatus(context.Background(), sid, model.StreamStatePause, runnerPauseReason)

			rec := stream.DeepCopy()
			if copyPaused {
				rec.SetStatus(model.StreamStatePause, runnerPauseReason)
			}
			h.router.UpdateStreamState(rec)

			require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 20*time.Millisecond,
				"the new holder delivers what queued during the pause")
			assert.Len(t, rx.snapshot(), 2)
			stored, reason := h.storedStatus(t, sid)
			assert.Equal(t, model.StreamStateEnabled, stored, "the takeover ends the runner's pause")
			assert.Empty(t, reason)
		})
	}
}
