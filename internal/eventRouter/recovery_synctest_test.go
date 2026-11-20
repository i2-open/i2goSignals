package eventRouter

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// This file is the deterministic-time suite for push recovery — one of the four
// timer paths spec 101 names. It differs from recovery_test.go in one important
// way: those tests inject a fake Sleep that advances a fake clock, which proves
// the loop's *arithmetic* but never runs the real delay primitive. Here the
// config is left to fillDefaults, so cfg.Sleep is the production SleepCtx and
// cfg.Clock is the production time.Now — both of which a synctest bubble makes
// deterministic. What is under test is therefore the ladder as it actually
// runs, timer discipline included.
//
// The bubble also settles the question a wall-clock test cannot ask at all:
// whether a recovery loop that is cancelled mid-backoff leaves anything behind.
// synctest.Test reports a deadlock if any goroutine in the bubble outlives it,
// so an abandoned timer wait would fail the test rather than pass unnoticed.

// recordingFetcher answers every probe with the same result and records the
// fake-clock instant of each call. The instants are the ladder.
type recordingFetcher struct {
	at     []time.Duration
	start  time.Time
	result fetchResult
	// after, when non-nil and reached, replaces result from that call onward.
	switchAt int
	after    *fetchResult
}

func (f *recordingFetcher) fetch(context.Context, *model.StreamStateRecord) (*model.StreamStatus, error) {
	f.at = append(f.at, time.Since(f.start))
	if f.after != nil && len(f.at) >= f.switchAt {
		return f.after.status, f.after.err
	}
	return f.result.status, f.result.err
}

// gaps turns recorded call instants into the delays between them.
func gaps(at []time.Duration) []time.Duration {
	if len(at) < 2 {
		return nil
	}
	out := make([]time.Duration, 0, len(at)-1)
	for i := 1; i < len(at); i++ {
		out = append(out, at[i]-at[i-1])
	}
	return out
}

func sameDurations(got, want []time.Duration) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestSleepCtx_WaitsExactlyOrCancelsImmediately pins the shared delay primitive
// every recovery path is built on. The cancellation case is the one that
// matters: it is reached precisely when the pending delay is longest, so a
// SleepCtx that waited out its timer before noticing cancellation would hold
// shutdown for up to MaxDelay.
func TestSleepCtx_WaitsExactlyOrCancelsImmediately(t *testing.T) {
	t.Run("elapses the full duration", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			if !SleepCtx(t.Context(), 5*time.Minute) {
				t.Fatal("SleepCtx reported cancellation on a live context")
			}
			if elapsed := time.Since(start); elapsed != 5*time.Minute {
				t.Fatalf("slept %v, want exactly 5m", elapsed)
			}
		})
	})

	t.Run("returns the instant the context is cancelled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			go func() {
				time.Sleep(2 * time.Second)
				cancel()
			}()

			start := time.Now()
			if SleepCtx(ctx, time.Hour) {
				t.Fatal("SleepCtx reported the sleep completed, want cancellation")
			}
			if elapsed := time.Since(start); elapsed != 2*time.Second {
				t.Fatalf("noticed cancellation after %v, want the 2s cancel instant "+
					"— a shutdown must not wait out the pending backoff", elapsed)
			}
			synctest.Wait()
		})
	})

	t.Run("a non-positive duration still honours cancellation", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if SleepCtx(ctx, 0) {
				t.Fatal("a zero sleep on a cancelled context reported success; " +
					"a retry loop would spin one more time before seeing shutdown")
			}
			if !SleepCtx(t.Context(), 0) {
				t.Fatal("a zero sleep on a live context reported cancellation")
			}
		})
	})
}

// TestRecoveryLoop_TransportBackoffClimbsTheFullLadder is the ladder assertion:
// each probe is one exponential step after the last, doubling from BaseDelay
// until MaxDelay caps it, and the loop gives up only once TransportLimit of
// wall time has actually elapsed. Every number here is an equality — under a
// fake clock there is no jitter to tolerate.
func TestRecoveryLoop_TransportBackoffClimbsTheFullLadder(t *testing.T) {
	h := newTestRouter(t)
	r := h.router
	stream := mustCreateTestStream(t, h, projectIdFromHarness(t, h))

	synctest.Test(t, func(t *testing.T) {
		fetcher := &recordingFetcher{
			start:  time.Now(),
			result: fetchResult{err: errors.New("connection refused")},
		}
		// Everything left at its default so cfg.Sleep is the real SleepCtx.
		cfg := RecoveryConfig{}

		outcome := r.recoveryLoop(t.Context(), stream, RecoveryModeTransportBackoff, fetcher.fetch, cfg)

		if outcome != RecoveryOutcomeDisabled {
			t.Fatalf("outcome %v, want Disabled after exhausting the transport limit", outcome)
		}
		if stream.Status != model.StreamStateDisable {
			t.Errorf("stream left in %v, want disabled", stream.Status)
		}

		wantHead := []time.Duration{
			1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
			16 * time.Second, 32 * time.Second, 64 * time.Second, 128 * time.Second,
			256 * time.Second,
		}
		got := gaps(fetcher.at)
		if len(got) < len(wantHead) {
			t.Fatalf("only %d delays recorded, want at least %d", len(got), len(wantHead))
		}
		if !sameDurations(got[:len(wantHead)], wantHead) {
			t.Fatalf("backoff ladder head is %v, want %v", got[:len(wantHead)], wantHead)
		}
		for i, d := range got[len(wantHead):] {
			if d != 5*time.Minute {
				t.Fatalf("delay %d after the cap is %v, want MaxDelay 5m", i+len(wantHead), d)
			}
		}

		// The give-up condition is elapsed time, not attempt count. The loop
		// probes first and checks the limit afterwards, so the final probe is
		// the one that crosses 6h and every earlier probe is inside it. Pinning
		// both ends is what stops a regression that gives up an hour early or
		// keeps climbing for a day.
		last := fetcher.at[len(fetcher.at)-1]
		prev := fetcher.at[len(fetcher.at)-2]
		if last < 6*time.Hour {
			t.Errorf("final probe at %v, want the first probe at or past the 6h transport limit", last)
		}
		if prev >= 6*time.Hour {
			t.Errorf("probe before last at %v, want it inside the 6h transport limit", prev)
		}
		if total := time.Since(fetcher.start); total != last {
			t.Errorf("loop returned at %v but its last probe was at %v", total, last)
		}
	})
}

// TestRecoveryLoop_AuthBoundedUsesAFixedDelayAndAttemptCap covers the other
// bounded mode. Auth failures do not back off exponentially — a 401 is not
// congestion — so the cadence is flat and the cap counts attempts.
func TestRecoveryLoop_AuthBoundedUsesAFixedDelayAndAttemptCap(t *testing.T) {
	h := newTestRouter(t)
	r := h.router
	stream := mustCreateTestStream(t, h, projectIdFromHarness(t, h))

	synctest.Test(t, func(t *testing.T) {
		fetcher := &recordingFetcher{
			start:  time.Now(),
			result: fetchResult{err: errors.New("401 unauthorized")},
		}

		outcome := r.recoveryLoop(t.Context(), stream, RecoveryModeAuthBounded, fetcher.fetch, RecoveryConfig{})

		if outcome != RecoveryOutcomeDisabled {
			t.Fatalf("outcome %v, want Disabled after the attempt cap", outcome)
		}
		if len(fetcher.at) != 10 {
			t.Fatalf("made %d attempts, want the AuthRetryLimit of 10", len(fetcher.at))
		}
		for i, d := range gaps(fetcher.at) {
			if d != 15*time.Second {
				t.Fatalf("gap %d is %v, want the flat AuthRetryDelay of 15s", i, d)
			}
		}
		if total := time.Since(fetcher.start); total != 9*15*time.Second {
			t.Fatalf("auth recovery spanned %v, want 9 gaps of 15s", total)
		}
	})
}

// TestRecoveryLoop_PausedByRemotePollsAtAFlatCadenceForever pins the uncapped
// mode: a receiver that says "paused" is reachable and healthy, so we re-probe
// at a steady interval indefinitely rather than backing off or giving up. The
// test resumes it after ten probes to prove the loop is still watching.
func TestRecoveryLoop_PausedByRemotePollsAtAFlatCadenceForever(t *testing.T) {
	h := newTestRouter(t)
	r := h.router
	stream := mustCreateTestStream(t, h, projectIdFromHarness(t, h))

	synctest.Test(t, func(t *testing.T) {
		enabled := fetchResult{status: &model.StreamStatus{Status: model.StreamStateEnabled}}
		fetcher := &recordingFetcher{
			start:    time.Now(),
			result:   fetchResult{status: &model.StreamStatus{Status: model.StreamStatePause, Reason: "maintenance"}},
			switchAt: 10,
			after:    &enabled,
		}

		outcome := r.recoveryLoop(t.Context(), stream, RecoveryModePausedByRemote, fetcher.fetch, RecoveryConfig{})

		if outcome != RecoveryOutcomeResumed {
			t.Fatalf("outcome %v, want Resumed once the receiver re-enabled", outcome)
		}
		if len(fetcher.at) != 10 {
			t.Fatalf("probed %d times, want 10", len(fetcher.at))
		}
		for i, d := range gaps(fetcher.at) {
			if d != 30*time.Second {
				t.Fatalf("gap %d is %v, want the flat StatusCheckInterval of 30s", i, d)
			}
		}
	})
}

// TestRecoveryLoop_CancellationEndsTheWaitImmediately is the shutdown path. A
// recovery loop deep in the ladder is sitting on a five-minute sleep; shutdown
// must not wait it out, and must not leave the wait behind. The bubble enforces
// the second half — if recoveryLoop returned while something was still parked on
// its timer, this test would fail as a deadlock rather than pass.
func TestRecoveryLoop_CancellationEndsTheWaitImmediately(t *testing.T) {
	h := newTestRouter(t)
	r := h.router
	stream := mustCreateTestStream(t, h, projectIdFromHarness(t, h))

	synctest.Test(t, func(t *testing.T) {
		fetcher := &recordingFetcher{
			start:  time.Now(),
			result: fetchResult{err: errors.New("connection refused")},
		}
		ctx, cancel := context.WithCancel(t.Context())

		// Long enough to be deep in the capped part of the ladder, where the
		// pending sleep is the full MaxDelay.
		go func() {
			time.Sleep(20 * time.Minute)
			cancel()
		}()

		start := time.Now()
		outcome := r.recoveryLoop(ctx, stream, RecoveryModeTransportBackoff, fetcher.fetch, RecoveryConfig{})
		elapsed := time.Since(start)

		if outcome != RecoveryOutcomeContextDone {
			t.Fatalf("outcome %v, want ContextDone", outcome)
		}
		if elapsed != 20*time.Minute {
			t.Fatalf("recovery returned %v after start, want the 20m cancel instant — "+
				"it waited out the pending backoff instead of observing shutdown", elapsed)
		}
		if stream.Status == model.StreamStateDisable {
			t.Error("a cancelled recovery disabled the stream; shutdown is not a give-up")
		}
		synctest.Wait()
	})
}
