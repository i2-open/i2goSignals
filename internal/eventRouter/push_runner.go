package eventRouter

import (
	"context"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// pushRunner is the lifecycle handle of one push runner: the goroutine
// initPushStreamLocked starts to run PushStreamHandler (the lease wait) and
// runPushLoop (delivery, pre-flight and recovery) for one push transmitter on
// this node (#309). It carries the two signals a restart hands off on.
//
// Stop is fired by whoever retires the runner — a restart in
// UpdateStreamState, or RemoveStream. The runner checks it before taking each
// new batch, and every wait the runner makes (the lease wait, the pre-flight,
// recoveryLoop and its sleeps, the idle and backfill timers) is on ctx, which
// stop cancels. A batch already handed to pushBatch is not aborted: its pushes
// and its ack run on the router context and complete normally, so at most one
// batch goes out after stop. Router shutdown cancels ctx too, so a stopped
// runner and a shut-down router exit the same way.
//
// Finished closes once the goroutine has fully exited, after its deferred
// cleanup (the lease heartbeat, the lease-owner forget, the leases-held gauge).
// A successor runner for the same stream starts only after it closes, so the
// two never overlap: the successor's preload reads the store after the old
// in-flight batch was acked, and the old runner's forget cannot clear the
// successor's lease-owner note.
type pushRunner struct {
	buf    *buffer.EventPushBuffer
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// state is the record the runner runs on. The runner writes its own status
	// transitions to it, so it is read by anyone else only once finished has
	// fired: it then holds the last status the runner wrote.
	state *model.StreamStateRecord

	// reEnabled records that UpdateStreamState was handed an enabled record
	// while this runner was live, and so started nothing. Guarded by r.mu.
	reEnabled bool

	// keyCheck carries the background key check's nudge (#318): the runner
	// checks its signing key and, with none active, takes its key-unavailable
	// pause even when idle. Buffered, so a nudge never blocks the check.
	keyCheck chan struct{}
}

func newPushRunner(parent context.Context, buf *buffer.EventPushBuffer, state *model.StreamStateRecord) *pushRunner {
	ctx, cancel := context.WithCancel(parent)
	return &pushRunner{buf: buf, ctx: ctx, cancel: cancel, done: make(chan struct{}), state: state, keyCheck: make(chan struct{}, 1)}
}

// nudgeKeyCheck asks the runner to check its signing key. It never blocks.
func (p *pushRunner) nudgeKeyCheck() {
	select {
	case p.keyCheck <- struct{}{}:
	default:
	}
}

// stop fires the stop signal and closes the runner's buffer. It never blocks,
// so it is safe under r.mu. Wait on finished to know the runner has gone, and
// never while holding r.mu: the runner's exit path can need the lock.
func (p *pushRunner) stop() {
	p.cancel()
	p.buf.Close()
}

// stopped reports whether the runner must stop sending: stop was fired or the
// router is shutting down.
func (p *pushRunner) stopped() bool {
	return p.ctx.Err() != nil
}

// finished is the finished signal: closed once the runner goroutine has exited.
func (p *pushRunner) finished() <-chan struct{} {
	return p.done
}

// live reports whether the runner goroutine has not exited yet.
func (p *pushRunner) live() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// pushHandoff is a pending restart for one push stream: the old runner has been
// stopped and completePushHandoff starts its successor once it has finished.
// While one is pending, a further restart only saves its record, and
// RemoveStream cancels it by deleting it from r.pushHandoffs.
type pushHandoff struct {
	// done closes when the hand-off goroutine returns, whether it started a
	// runner or found the hand-off cancelled.
	done chan struct{}
}

// initPushStreamLocked registers a buffer preloaded with jtis and starts a
// push runner on state. The caller holds r.mu.
func (r *router) initPushStreamLocked(sid string, state *model.StreamStateRecord, jtis []string) {
	pushBuffer := buffer.CreateEventPushBuffer(jtis)
	runner := newPushRunner(r.ctx, pushBuffer, state)
	r.pushBuffers[sid] = pushBuffer
	r.pushRunners[sid] = runner
	r.runningPushRunners.Add(1)
	go func() {
		defer r.startPushRunnerIfReEnabled(sid, runner)
		defer close(runner.done)
		defer r.runningPushRunners.Add(-1)
		r.PushStreamHandler(state, runner)
	}()
}

// startPushRunnerIfReEnabled runs once runner has finished. A runner that
// stopped on its own (it disabled the stream, or found it no longer enabled)
// still counts as live until its cleanup is done, so a re-enable landing in
// that window started nothing (#308). When one did, and the stored status is
// still enabled, a new runner starts now, unless the runner was stopped, the
// router is shutting down, or something else has since replaced or removed the
// runner. A re-enable after finished fired started its own runner, which
// replaced this one in pushRunners.
func (r *router) startPushRunnerIfReEnabled(sid string, runner *pushRunner) {
	if runner.stopped() {
		return
	}
	r.mu.RLock()
	asked := runner.reEnabled
	r.mu.RUnlock()
	if !asked {
		return
	}
	stored, err := r.streamService.GetStreamState(r.ctx, sid)
	if err != nil || stored == nil || stored.Status != model.StreamStateEnabled {
		return
	}
	jtis := r.pendingPushJtis(sid)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil || r.pushRunners[sid] != runner {
		return
	}
	if _, pending := r.pushHandoffs[sid]; pending {
		return
	}
	state, present := r.pushStreams[sid]
	if !present || state.Status != model.StreamStateEnabled {
		return
	}
	eventLogger.Info("PUSH-SRV: stream re-enabled while its runner was exiting, starting one", "sid", sid)
	r.retirePushRunnerLocked(sid)
	r.initPushStreamLocked(sid, state.DeepCopy(), jtis)
}

// pendingPushJtis reads sid's pending JTIs from the store, to preload a new
// runner's buffer. The caller does not hold r.mu.
func (r *router) pendingPushJtis(sid string) []string {
	jtis, _ := r.eventService.GetEventIds(r.ctx, sid, model.PollParameters{
		MaxEvents:         0,
		ReturnImmediately: true,
		TimeoutSecs:       10,
	})
	return jtis
}

// retirePushRunnerLocked fires the stop signal of sid's runner and unregisters
// the runner and its buffer, returning the retired runner (nil when sid has
// none). It does not wait for the runner to exit. The caller holds r.mu.
func (r *router) retirePushRunnerLocked(sid string) *pushRunner {
	if pb, ok := r.pushBuffers[sid]; ok {
		pb.Close()
		delete(r.pushBuffers, sid)
	}
	runner, ok := r.pushRunners[sid]
	if !ok {
		return nil
	}
	delete(r.pushRunners, sid)
	runner.stop()
	drainPushBufferWhenFinished(runner)
	return runner
}

// drainPushBufferWhenFinished empties a closed runner buffer once its runner
// has exited. The buffer's pump goroutine exits only after everything queued in
// it has been read, and a stopped runner leaves its queue unread. Nothing is
// lost: those JTIs are still pending in the store, and a successor preloads
// them.
func drainPushBufferWhenFinished(runner *pushRunner) {
	go func() {
		<-runner.finished()
		for range runner.buf.Out {
		}
	}()
}

// completePushHandoff finishes a restart in the background. It waits for the
// old runner's finished signal without holding r.mu, then preloads the stream's
// pending JTIs and starts the new runner on the latest record in pushStreams.
// It starts nothing when RemoveStream cancelled the hand-off or the router has
// shut down. A record that is no longer enabled still gets its runner, which
// exits as any runner does for a stream that is not enabled, with one
// exception: a pause the old runner itself took (receiver recovery or a missing
// signing key) is ended first, see endRetiredRunnerPause.
func (r *router) completePushHandoff(sid string, old *pushRunner, handoff *pushHandoff) {
	defer close(handoff.done)
	ownPause := ""
	if old != nil {
		<-old.finished()
		ownPause = r.endRetiredRunnerPause(sid, old, handoff)
	}
	jtis := r.pendingPushJtis(sid)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pushHandoffs[sid] != handoff {
		return
	}
	delete(r.pushHandoffs, sid)
	state, present := r.pushStreams[sid]
	if !present || r.ctx.Err() != nil {
		return
	}
	if _, running := r.pushRunners[sid]; running {
		return
	}
	if ownPause != "" && state.Status == model.StreamStatePause && state.ErrorMsg == ownPause {
		state.SetStatus(model.StreamStateEnabled, "")
		r.pushStreams[sid] = state
	}
	r.initPushStreamLocked(sid, state.DeepCopy(), jtis)
}

// endRetiredRunnerPause ends the pause the retired runner old took itself, so
// that its successor runs. The update handler hands UpdateStreamState the
// stored record, and while a runner is in receiver recovery or waiting for its
// signing key that record is paused by the runner. Started on it, the successor
// would exit at once and leave the stream paused with no runner.
//
// A pause is the runner's own when old's record, read now that it has finished,
// is paused with the very reason still stored. An operator's pause or disable
// stores its own reason, or another status, and is left alone. The stored status
// is set to enabled, and the reason returned, only while the hand-off is still
// pending; otherwise it returns "". The successor pauses again if the receiver
// still fails or the key is still missing.
func (r *router) endRetiredRunnerPause(sid string, old *pushRunner, handoff *pushHandoff) string {
	final := old.state
	if final == nil || final.Status != model.StreamStatePause {
		return ""
	}
	r.mu.RLock()
	pending := r.pushHandoffs[sid] == handoff
	r.mu.RUnlock()
	if !pending || r.ctx.Err() != nil {
		return ""
	}
	stored, err := r.streamService.GetStreamState(r.ctx, sid)
	if err != nil || stored == nil || stored.Status != model.StreamStatePause || stored.ErrorMsg != final.ErrorMsg {
		return ""
	}
	eventLogger.Info("PUSH-SRV: runner restarted during its own pause; resuming so the new runner retries", "sid", sid, "reason", final.ErrorMsg)
	r.updateStream(stored, model.StreamStateEnabled, "")
	return final.ErrorMsg
}

// pushRunnerLiveLocked reports whether sid has a live push runner on this node:
// a registered runner whose finished signal has not fired, or a pending restart
// hand-off, which will start one. A runner that exited on its own (its stream
// was disabled, or was not enabled when it started) is not live, so a caller
// re-enabling the stream can start one without doubling up. The caller holds
// r.mu (read or write).
func (r *router) pushRunnerLiveLocked(sid string) bool {
	if _, pending := r.pushHandoffs[sid]; pending {
		return true
	}
	runner, ok := r.pushRunners[sid]
	return ok && runner.live()
}
