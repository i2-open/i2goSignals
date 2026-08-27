package buffer

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Benchmarks for the internal/eventRouter/buffer hot path: the poll buffer's
// submit/drain cycle, the long-poll wait/wake round trip, the acknowledgement
// scan, and push-buffer throughput.
//
// These are part of the spec #101 (Go 1.27 adoption) measurement floor
// recorded in docs/perf/go127-baseline.md. This package is the goroutine and
// channel-scheduling read in the benchmark set — the runtime side of a
// toolchain change rather than the encoding side. Keep the workload stable:
// the per-slice delta table compares against these exact shapes.

// benchBufferJtis builds n synthetic jtis in the pre-#274 ksuid shape. The
// server mints UUIDv7 jtis now, but this workload stays deliberately frozen so
// the per-slice delta table keeps comparing like with like.
func benchBufferJtis(n int) []string {
	jtis := make([]string, n)
	for i := range jtis {
		jtis[i] = fmt.Sprintf("2fY4Xz9kQpLmNbVcRsTuWxYz%04d", i)
	}
	return jtis
}

// waitForCount blocks until the buffer's reader goroutine has drained the in
// channel and the buffer holds want events. SubmitEvents is asynchronous, so
// every setup step that must observe its effect goes through here rather than
// through a sleep.
func waitForCount(b *testing.B, buf *EventPollBuffer, want int) {
	b.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for buf.Cnt() != want {
		if time.Now().After(deadline) {
			b.Fatalf("buffer did not reach %d events (stuck at %d)", want, buf.Cnt())
		}
		// Yield rather than sleep: this runs inside benchmark setup, and a
		// millisecond sleep here would dominate the measurement it precedes.
		runtime.Gosched()
	}
}

// BenchmarkPollBufferSubmitDrain measures the producer side end to end: the
// submit channel hop, the reader goroutine's append, and the notifier
// close/realloc it performs per event. It reports the cost of one event
// reaching a pollable state.
func BenchmarkPollBufferSubmitDrain(b *testing.B) {
	buf := CreateEventPollBuffer(nil, 0, 0)
	defer buf.Close()

	jtis := benchBufferJtis(b.N)
	b.ReportAllocs()
	b.ResetTimer()
	buf.SubmitEvents(jtis)
	waitForCount(b, buf, b.N)
}

// BenchmarkPollBufferGetEventsReady is the common poll: the buffer already
// holds more events than the receiver's maxEvents, so GetEvents takes the
// non-blocking path and copies out one bounded batch.
func BenchmarkPollBufferGetEventsReady(b *testing.B) {
	const buffered = 500
	buf := CreateEventPollBuffer(nil, 0, 0)
	defer buf.Close()

	buf.SubmitEvents(benchBufferJtis(buffered))
	waitForCount(b, buf, buffered)

	params := model.PollParameters{MaxEvents: 100, ReturnImmediately: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		events, more := buf.GetEvents(params)
		if events == nil || len(*events) != 100 || !more {
			b.Fatal("expected a bounded batch with more available")
		}
	}
}

// BenchmarkPollBufferGetEventsAckOnly measures the acknowledge-only poll
// against an empty buffer — the RFC 8936 §2.4 short poll that must never
// block.
func BenchmarkPollBufferGetEventsAckOnly(b *testing.B) {
	buf := CreateEventPollBuffer(nil, 0, 0)
	defer buf.Close()

	params := model.PollParameters{ReturnImmediately: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if events, more := buf.GetEvents(params); events != nil || more {
			b.Fatal("empty buffer must return no events")
		}
	}
}

// BenchmarkPollBufferWaitWake measures the long-poll round trip: a receiver
// blocked in GetEvents on an empty buffer, an event submitted behind it, and
// the poller returning with that event.
//
// Scheduling decides whether a given iteration resolves through the notifier
// wake or finds the event already appended and takes the ready path; both are
// the real long-poll code path and neither can stall, since the submit
// happens unconditionally. That makes the benchmark stable to compare across
// toolchains, which is what the per-slice delta table needs.
func BenchmarkPollBufferWaitWake(b *testing.B) {
	buf := CreateEventPollBuffer(nil, 5, 30)
	defer buf.Close()

	params := model.PollParameters{MaxEvents: 1, ReturnImmediately: false, TimeoutSecs: 5}
	jtis := benchBufferJtis(b.N)
	got := make(chan int, 1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			events, _ := buf.GetEvents(params)
			if events == nil {
				got <- 0
				return
			}
			got <- len(*events)
		}()
		buf.SubmitEvent(jtis[i])
		if n := <-got; n == 0 {
			b.Fatal("long poll timed out without delivering the submitted event")
		}
		buf.AckEvents(jtis[i : i+1])
	}
}

// BenchmarkPollBufferWakeupSignal measures the bare stream-state-change wake:
// close the current notifier and install a fresh one. The router calls this
// on every stream config change, independent of event flow.
func BenchmarkPollBufferWakeupSignal(b *testing.B) {
	buf := CreateEventPollBuffer(nil, 0, 0)
	defer buf.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Wakeup()
	}
}

// BenchmarkPollBufferAckEvents measures the acknowledgement scan, which is a
// linear search per acked jti over the retained slice. Re-population is
// excluded from the timed region.
func BenchmarkPollBufferAckEvents(b *testing.B) {
	const batch = 100
	buf := CreateEventPollBuffer(nil, 0, 0)
	defer buf.Close()

	jtis := benchBufferJtis(batch)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Re-populate through addEvents rather than SubmitEvents: the submit
		// path is asynchronous, and waiting on the reader goroutine once per
		// iteration would swamp the scan being measured. addEvents installs
		// the same slice state synchronously.
		b.StopTimer()
		buf.addEvents(jtis)
		b.StartTimer()

		buf.AckEvents(jtis)
	}
	b.StopTimer()
	if buf.Cnt() != 0 {
		b.Fatalf("expected an empty buffer after acking, got %d", buf.Cnt())
	}
}

// BenchmarkPushBufferThroughput measures the push path: SubmitEvent to a
// delivered value on Out, the channel hop the push deliverer runs per event.
func BenchmarkPushBufferThroughput(b *testing.B) {
	buf := CreateEventPushBuffer(nil)
	defer buf.Close()

	jtis := benchBufferJtis(b.N)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < b.N; i++ {
			if _, ok := <-buf.Out; !ok {
				b.Errorf("push buffer Out closed after %d of %d events", i, b.N)
				return
			}
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.SubmitEvent(jtis[i])
	}
	<-done
}
