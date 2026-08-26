package server

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
)

// TestSstpDialerDefaultSleepIsTheSharedHelper pins the de-duplication: the SSTP
// dialer and the push recovery loop share one cancellable delay primitive rather
// than each carrying its own near-identical copy, which is how the two drifted
// apart on the d<=0 cancellation check in the first place.
func TestSstpDialerDefaultSleepIsTheSharedHelper(t *testing.T) {
	var cfg SstpDialerConfig
	cfg.fillDefaults()

	if cfg.Sleep == nil {
		t.Fatal("dialer config has no default Sleep")
	}
	want := reflect.ValueOf(eventRouter.SleepCtx).Pointer()
	if got := reflect.ValueOf(cfg.Sleep).Pointer(); got != want {
		t.Fatal("the dialer's default Sleep is not eventRouter.SleepCtx; the two " +
			"ctx-aware sleep helpers have forked again")
	}
}

// TestSleepCtxHonoursCancellationAtZeroDuration covers the behaviour the two
// forked copies disagreed on. A retry loop that computes a zero backoff must
// still see shutdown, not spin one more time before noticing.
func TestSleepCtxHonoursCancellationAtZeroDuration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if eventRouter.SleepCtx(ctx, 0) {
		t.Error("SleepCtx(cancelled, 0) reported the delay completed")
	}
	if eventRouter.SleepCtx(ctx, -time.Second) {
		t.Error("SleepCtx(cancelled, negative) reported the delay completed")
	}
	if eventRouter.SleepCtx(context.Background(), 0) != true {
		t.Error("SleepCtx(live, 0) did not return immediately as completed")
	}
}
