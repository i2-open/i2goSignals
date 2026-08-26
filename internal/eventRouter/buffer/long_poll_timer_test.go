package buffer

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestAwaitNotify_EarlyWakeStopsTheDeadlineTimer is the direct proof that a
// long poll woken early by an event leaves no pending timer behind.
//
// The deadline timer is owned by the caller here precisely so a test can
// interrogate it afterwards: Timer.Stop reports true only when it actually
// stopped a live timer, so a post-hoc Stop returning false means the timer was
// already stopped or already fired. Running inside a synctest bubble removes
// the second possibility — the fake clock cannot advance while the bubble has
// a runnable goroutine, so an hour-long deadline provably did not fire during a
// wait that resolved on the notifier.
//
// With a bare time.After (the pre-Go-1.27-hygiene shape) there is no timer to
// stop and the runtime keeps it armed for the full hour.
func TestAwaitNotify_EarlyWakeStopsTheDeadlineTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		notifier := make(chan struct{}, 1)
		deadline := time.NewTimer(time.Hour)

		start := time.Now()
		notifier <- struct{}{}

		if notified := awaitNotify(notifier, deadline); !notified {
			t.Fatal("awaitNotify reported a timeout, want a notification")
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("awaitNotify waited %v, want an immediate return on the notifier", elapsed)
		}
		if deadline.Stop() {
			t.Fatal("the deadline timer was still armed after awaitNotify returned: " +
				"an early-woken long poll must not leave a pending timer")
		}
	})
}

// TestAwaitNotify_DeadlineStopsItsOwnTimer covers the other exit path: when the
// deadline wins, the timer has fired and must not be left for a caller to clean
// up. Stop returning false is the same assertion as above, reached the other way.
func TestAwaitNotify_DeadlineStopsItsOwnTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		notifier := make(chan struct{})
		deadline := time.NewTimer(30 * time.Second)

		start := time.Now()
		if notified := awaitNotify(notifier, deadline); notified {
			t.Fatal("awaitNotify reported a notification, want a timeout")
		}
		if elapsed := time.Since(start); elapsed != 30*time.Second {
			t.Fatalf("awaitNotify waited %v, want the full 30s deadline", elapsed)
		}
		if deadline.Stop() {
			t.Fatal("the deadline timer was still armed after it fired")
		}
	})
}
