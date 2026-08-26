package eventRouter

import (
	"testing"
	"testing/synctest"
	"time"
)

// This file is the deterministic-time suite for the T3 idle keepalive — one of
// the four timer paths spec 101 names. The keepalive's contract is almost
// entirely about *not* firing, which is the hardest kind of behaviour to test
// against a real clock: proving "it did not fire for five minutes" costs five
// minutes, so in practice nobody proves it and the interval goes unchecked.
// Inside a synctest bubble the clock only advances when every goroutine is
// durably blocked, so five idle minutes cost nothing and "did not fire" is a
// checkable assertion rather than a hopeful one.
//
// The emission half of T3 — that a fire produces a real verification SET
// through the operational-event path — is covered by verify_sstp_test.go and
// end-to-end by internal/server/test/push_metrics_test.go. What was untested
// until now is *when* it fires, which is this file.

const testIdleInterval = 5 * time.Minute

// firedWithin reports whether the keepalive fires during the next d of bubble
// time, and at what offset. It advances the clock by sleeping, which inside a
// bubble is instant.
func firedWithin(k *idleKeepalive, d time.Duration) (time.Duration, bool) {
	start := time.Now()
	select {
	case <-k.C():
		return time.Since(start), true
	case <-time.After(d):
		return 0, false
	}
}

// TestIdleKeepalive_FiresOnceTheStreamHasBeenIdleForTheInterval is the base
// case: an armed keepalive on a stream nobody is pushing to fires at exactly
// the configured interval.
func TestIdleKeepalive_FiresOnceTheStreamHasBeenIdleForTheInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleKeepalive(testIdleInterval)
		defer k.Stop()

		at, fired := firedWithin(k, testIdleInterval+time.Second)
		if !fired {
			t.Fatal("idle keepalive never fired on a stream idle past its interval")
		}
		if at != testIdleInterval {
			t.Fatalf("fired after %v, want exactly %v", at, testIdleInterval)
		}
	})
}

// TestIdleKeepalive_ASuccessfulPushPushesTheDeadlineOut is the R1 rule from
// runPushLoop: every accepted push restarts the idle clock. Firing at the
// original deadline anyway would emit a keepalive at a receiver that just
// acknowledged an event — noise, and a wasted JTI.
func TestIdleKeepalive_ASuccessfulPushPushesTheDeadlineOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleKeepalive(testIdleInterval)
		defer k.Stop()

		start := time.Now()

		// A push lands one minute in.
		time.Sleep(time.Minute)
		k.Reset()

		// The original deadline passes with nothing to show for it.
		if _, fired := firedWithin(k, testIdleInterval-time.Minute+time.Second); fired {
			t.Fatal("keepalive fired at the pre-push deadline; the successful push should have reset it")
		}

		if _, fired := firedWithin(k, testIdleInterval); !fired {
			t.Fatal("keepalive never fired after the reset deadline")
		}
		if want, total := time.Minute+testIdleInterval, time.Since(start); total != want {
			t.Fatalf("fired %v after start, want one interval after the push at %v", total, want)
		}
	})
}

// TestIdleKeepalive_ABusyStreamNeverFires is the property the whole feature
// exists for. A stream pushing steadily just inside the interval must never
// synthesise a keepalive, no matter how long it runs. An hour of traffic here
// is free.
func TestIdleKeepalive_ABusyStreamNeverFires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleKeepalive(testIdleInterval)
		defer k.Stop()

		for range 12 { // an hour at one push per interval-minus-a-bit
			if _, fired := firedWithin(k, testIdleInterval-time.Second); fired {
				t.Fatal("keepalive fired on a stream that pushed inside every interval")
			}
			k.Reset()
		}
	})
}

// TestIdleKeepalive_ReArmsAfterFiring covers the fire branch's own Reset: after
// T3 fires, the next keepalive is one full interval later. Without the re-arm
// the timer is spent and an idle stream gets exactly one keepalive ever.
func TestIdleKeepalive_ReArmsAfterFiring(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleKeepalive(testIdleInterval)
		defer k.Stop()

		for i := range 3 {
			at, fired := firedWithin(k, testIdleInterval+time.Second)
			if !fired {
				t.Fatalf("keepalive %d never fired", i+1)
			}
			if at != testIdleInterval {
				t.Fatalf("keepalive %d fired after %v, want %v", i+1, at, testIdleInterval)
			}
			k.Reset()
		}
	})
}

// TestIdleKeepalive_IsSilentThroughRecoveryAndResumesAfter is the
// dispatchPushFailure path: recovery stops the keepalive for its duration and
// re-arms it on resume. Synthesising "are you there?" events at a receiver
// whose /status endpoint we are already polling is pure noise, and the events
// would fail to push anyway.
func TestIdleKeepalive_IsSilentThroughRecoveryAndResumesAfter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleKeepalive(testIdleInterval)
		defer k.Stop()

		k.Stop() // entering recovery

		if _, fired := firedWithin(k, 2*time.Hour); fired {
			t.Fatal("keepalive fired during recovery; it should be stopped for the duration")
		}

		k.Reset() // recovery resumed

		at, fired := firedWithin(k, testIdleInterval+time.Second)
		if !fired {
			t.Fatal("keepalive never fired after recovery resumed; the re-arm was lost")
		}
		if at != testIdleInterval {
			t.Fatalf("fired %v after resume, want a full interval of %v", at, testIdleInterval)
		}
	})
}

// TestIdleKeepalive_DisabledIntervalIsAPermanentNoOp pins the documented "off"
// switch. A non-positive interval yields a nil keepalive whose channel is nil,
// so runPushLoop's select arm can never be chosen — and every method still has
// to be safe to call, because the call sites deliberately do not branch.
func TestIdleKeepalive_DisabledIntervalIsAPermanentNoOp(t *testing.T) {
	for _, interval := range []time.Duration{0, -1, -time.Hour} {
		k := newIdleKeepalive(interval)
		if k != nil {
			t.Fatalf("newIdleKeepalive(%v) returned a live keepalive, want nil (disabled)", interval)
		}
		if k.C() != nil {
			t.Fatalf("a disabled keepalive yielded a non-nil channel; its select arm could fire")
		}
		// Must not panic.
		k.Reset()
		k.Stop()
	}

	synctest.Test(t, func(t *testing.T) {
		k := newIdleKeepalive(0)
		if _, fired := firedWithin(k, 24*time.Hour); fired {
			t.Fatal("a disabled keepalive fired")
		}
	})
}

// TestIdleKeepalive_StopLeavesNoArmedTimer is the leak assertion. Timer.Stop
// reports true only when it actually stopped a live timer, so a second Stop
// returning false proves the first one disarmed it. Under Go 1.27 an abandoned
// armed timer is exactly the shape that keeps a runtime timer alive for its
// full duration after the caller has moved on.
func TestIdleKeepalive_StopLeavesNoArmedTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleKeepalive(testIdleInterval)

		if !k.timer.Stop() {
			t.Fatal("a freshly armed keepalive reported nothing to stop")
		}
		k.Reset()
		k.Stop()
		if k.timer.Stop() {
			t.Fatal("the keepalive was still armed after Stop")
		}
	})
}
