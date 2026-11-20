package buffer

import (
	"testing"
	"testing/synctest"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// This file is the deterministic-time suite for the RFC 8936 long-poll wait —
// one of the four timer paths spec 101 names. Every test runs inside a
// synctest bubble, which buys two things a wall-clock test cannot have:
//
//   - Exact durations. A bubble's clock only advances when every goroutine in
//     it is durably blocked, so "the poll waited 30s" is an equality assertion
//     rather than a tolerance band, and a 30-second timeout costs no real time.
//   - A goroutine-leak assertion for free. synctest.Test does not return until
//     every goroutine in the bubble has exited, and reports a deadlock if one
//     cannot. Since CreateEventPollBuffer spawns its pump goroutine inside the
//     bubble, each of these tests also proves that pump is reclaimed.
//
// The trailing synctest.Wait() in each test makes the second guarantee explicit
// at the point it matters, rather than leaving it to the bubble teardown.

// newBubbleBuffer builds a buffer inside the current bubble and closes it when
// the test ends. The Cleanup runs inside the bubble (synctest.Test guarantees
// this), so the pump goroutine's exit is still observed by the bubble.
func newBubbleBuffer(t *testing.T, defaultTimeoutSecs, maxTimeoutSecs int) *EventPollBuffer {
	t.Helper()
	b := CreateEventPollBuffer(nil, defaultTimeoutSecs, maxTimeoutSecs)
	t.Cleanup(b.Close)
	return b
}

// TestLongPoll_WaitsTheFullTimeoutOnAnEmptyBuffer pins the timeout arm of
// awaitNotify as GetEvents drives it: no events, nobody wakes us, so the poll
// returns empty after exactly the requested timeout and not a nanosecond
// earlier or later.
func TestLongPoll_WaitsTheFullTimeoutOnAnEmptyBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newBubbleBuffer(t, 0, 0)

		start := time.Now()
		jtis, more := b.GetEvents(model.PollParameters{TimeoutSecs: 30})
		elapsed := time.Since(start)

		if jtis != nil || more {
			t.Fatalf("got (%v, %v), want an empty long-poll result", jtis, more)
		}
		if elapsed != 30*time.Second {
			t.Fatalf("long poll returned after %v, want exactly 30s", elapsed)
		}
		synctest.Wait()
	})
}

// TestLongPoll_WakesEarlyOnASubmittedEvent is the early-wake path: an event
// delivered mid-poll must return it immediately rather than making the receiver
// serve out the rest of its timeout. Under a fake clock "immediately" is
// checkable — the poll must return at the exact instant of the submit.
func TestLongPoll_WakesEarlyOnASubmittedEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newBubbleBuffer(t, 0, 0)

		go func() {
			time.Sleep(2 * time.Second)
			b.SubmitEvent("jti-early")
		}()

		start := time.Now()
		jtis, more := b.GetEvents(model.PollParameters{TimeoutSecs: 300})
		elapsed := time.Since(start)

		if jtis == nil || len(*jtis) != 1 || (*jtis)[0] != "jti-early" {
			t.Fatalf("got %v, want the submitted jti", jtis)
		}
		if more {
			t.Fatal("more=true on a single-event result")
		}
		if elapsed != 2*time.Second {
			t.Fatalf("poll returned after %v, want the 2s submit instant — "+
				"a long poll must not serve out its timeout once an event arrives", elapsed)
		}
		synctest.Wait()
	})
}

// TestLongPoll_WakesEarlyOnWakeup covers the other early-wake trigger: a stream
// state change calls Wakeup, which ends the poll with an empty result so the
// caller can re-read the stream's configuration. The distinction from a timeout
// is invisible to the caller by design — what matters is that it happened at
// the wakeup instant.
func TestLongPoll_WakesEarlyOnWakeup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newBubbleBuffer(t, 0, 0)

		go func() {
			time.Sleep(500 * time.Millisecond)
			b.Wakeup()
		}()

		start := time.Now()
		jtis, _ := b.GetEvents(model.PollParameters{TimeoutSecs: 300})
		elapsed := time.Since(start)

		if jtis != nil {
			t.Fatalf("got %v, want an empty result from a wakeup", jtis)
		}
		if elapsed != 500*time.Millisecond {
			t.Fatalf("poll returned after %v, want the 500ms wakeup instant", elapsed)
		}
		synctest.Wait()
	})
}

// TestLongPoll_TimeoutPolicyIsAppliedToTheWait proves the default/clamp policy
// in resolveTimeoutSecs reaches the timer rather than merely being computed:
// each case asserts the duration actually waited. A wall-clock test can only
// afford to check the short cases; the fake clock makes the 300s request as
// cheap as the 1s one.
func TestLongPoll_TimeoutPolicyIsAppliedToTheWait(t *testing.T) {
	cases := []struct {
		name          string
		defaultSecs   int
		maxSecs       int
		requestedSecs int
		wantWait      time.Duration
		wantImmediate bool
	}{
		{name: "omitted timeout uses the buffer default", defaultSecs: 5, maxSecs: 300, requestedSecs: 0, wantWait: 5 * time.Second},
		{name: "request above the cap is clamped", defaultSecs: 5, maxSecs: 2, requestedSecs: 300, wantWait: 2 * time.Second},
		{name: "request below the cap is honoured", defaultSecs: 5, maxSecs: 300, requestedSecs: 7, wantWait: 7 * time.Second},
		{name: "cap disabled honours a large request", defaultSecs: 5, maxSecs: 0, requestedSecs: 900, wantWait: 900 * time.Second},
		{name: "no default and no request returns immediately", defaultSecs: 0, maxSecs: 300, requestedSecs: 0, wantImmediate: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b := newBubbleBuffer(t, tc.defaultSecs, tc.maxSecs)

				start := time.Now()
				b.GetEvents(model.PollParameters{TimeoutSecs: tc.requestedSecs})
				elapsed := time.Since(start)

				want := tc.wantWait
				if tc.wantImmediate {
					want = 0
				}
				if elapsed != want {
					t.Fatalf("poll waited %v, want %v", elapsed, want)
				}
				synctest.Wait()
			})
		})
	}
}

// TestClose_ReclaimsThePumpEvenWithUnreadEvents is a leak regression test, and
// the reason the goroutine-leak gate exists.
//
// The pump goroutine's job is to move JTIs off the `in` channel into the slice
// GetEvents reads. Close closes `in`, which is the pump's signal to stop. If the
// pump instead keeps looping while unread JTIs remain, it re-enters a receive on
// a channel it has already nil'd — and a receive on a nil channel blocks
// forever, stranding the goroutine for the lifetime of the process.
//
// A buffer closed with unread events is not an edge case: it is what happens
// every time a stream is deleted or a node loses its lease with events still
// pending. synctest turns the strand into a reported deadlock instead of a
// goroutine nobody counts.
func TestClose_ReclaimsThePumpEvenWithUnreadEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := CreateEventPollBuffer(nil, 0, 0)

		b.SubmitEvents([]string{"jti-1", "jti-2", "jti-3"})
		synctest.Wait() // let the pump drain `in` into the events slice

		if got := b.Cnt(); got != 3 {
			t.Fatalf("buffer holds %d events, want the 3 submitted", got)
		}

		b.Close() // deliberately without draining: the events stay unread

		// If the pump is stranded, Wait reports the bubble as deadlocked here.
		synctest.Wait()
	})
}

// TestClose_ReclaimsThePumpOnADrainedBuffer is the same assertion on the happy
// path, so a regression in the fix above cannot be mistaken for "Close never
// worked at all".
func TestClose_ReclaimsThePumpOnADrainedBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := CreateEventPollBuffer(nil, 0, 0)

		b.SubmitEvent("jti-1")
		synctest.Wait()

		jtis, _ := b.GetEvents(model.PollParameters{ReturnImmediately: true})
		if jtis == nil || len(*jtis) != 1 {
			t.Fatalf("got %v, want the submitted jti", jtis)
		}
		b.AckEvents(*jtis)

		b.Close()
		synctest.Wait()
	})
}
