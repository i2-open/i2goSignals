package eventRouter

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStatusFetcher struct {
	calls    atomic.Int32
	results  []fetchResult
	resultMu chan struct{}
}

type fetchResult struct {
	status *model.StreamStatus
	err    error
}

func newFakeFetcher(results ...fetchResult) *fakeStatusFetcher {
	return &fakeStatusFetcher{results: results}
}

func (f *fakeStatusFetcher) fetch(_ context.Context, _ *model.StreamStateRecord) (*model.StreamStatus, error) {
	idx := int(f.calls.Add(1)) - 1
	if idx >= len(f.results) {
		// Return last result repeatedly.
		idx = len(f.results) - 1
	}
	return f.results[idx].status, f.results[idx].err
}

// fakeClock is a deterministic clock for recovery tests. It does NOT advance on its own;
// the test or the fakeSleep advances it.
type fakeClock struct {
	now atomic.Int64 // unix nanoseconds
}

func newFakeClock(start time.Time) *fakeClock {
	c := &fakeClock{}
	c.now.Store(start.UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time { return time.Unix(0, c.now.Load()) }
func (c *fakeClock) Advance(d time.Duration) {
	c.now.Add(int64(d))
}

// fakeSleep advances the clock by d and returns immediately. Honours ctx cancellation.
func makeFakeSleep(clock *fakeClock) func(context.Context, time.Duration) bool {
	return func(ctx context.Context, d time.Duration) bool {
		if ctx.Err() != nil {
			return false
		}
		clock.Advance(d)
		return true
	}
}

func newRecoveryTestConfig(clock *fakeClock) RecoveryConfig {
	return RecoveryConfig{
		StatusCheckInterval: 30 * time.Second,
		BaseDelay:           1 * time.Second,
		BackoffFactor:       2.0,
		MaxDelay:            5 * time.Minute,
		TransportLimit:      6 * time.Hour,
		AuthRetryDelay:      15 * time.Second,
		AuthRetryLimit:      10,
		Clock:               clock.Now,
		Sleep:               makeFakeSleep(clock),
	}
}

func TestRecoveryLoop_ResumesWhenRemoteEnabled(t *testing.T) {
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)
	fetcher := newFakeFetcher(fetchResult{status: &model.StreamStatus{Status: model.StreamStateEnabled}})

	outcome := r.recoveryLoop(context.Background(), stream, RecoveryModeTransportBackoff, fetcher.fetch, cfg)

	assert.Equal(t, RecoveryOutcomeResumed, outcome)
	assert.Equal(t, model.StreamStateEnabled, stream.Status)
	persisted, _ := provider.GetStreamState(stream.StreamConfiguration.Id)
	assert.Equal(t, model.StreamStateEnabled, persisted.Status)
}

func TestRecoveryLoop_DisablesWhenRemoteDisabled(t *testing.T) {
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)
	fetcher := newFakeFetcher(fetchResult{status: &model.StreamStatus{
		Status: model.StreamStateDisable,
		Reason: "operator decommissioned",
	}})

	outcome := r.recoveryLoop(context.Background(), stream, RecoveryModePausedByRemote, fetcher.fetch, cfg)

	assert.Equal(t, RecoveryOutcomeDisabled, outcome)
	assert.Equal(t, model.StreamStateDisable, stream.Status)
	assert.Contains(t, stream.ErrorMsg, "operator decommissioned")
}

func TestRecoveryLoop_PausedByRemoteThenEnabled(t *testing.T) {
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)
	cfg.StatusCheckInterval = 100 * time.Millisecond
	fetcher := newFakeFetcher(
		fetchResult{status: &model.StreamStatus{Status: model.StreamStatePause, Reason: "maintenance"}},
		fetchResult{status: &model.StreamStatus{Status: model.StreamStatePause, Reason: "maintenance"}},
		fetchResult{status: &model.StreamStatus{Status: model.StreamStateEnabled}},
	)

	outcome := r.recoveryLoop(context.Background(), stream, RecoveryModePausedByRemote, fetcher.fetch, cfg)

	assert.Equal(t, RecoveryOutcomeResumed, outcome)
	assert.Equal(t, model.StreamStateEnabled, stream.Status)
	assert.Equal(t, int32(3), fetcher.calls.Load(), "should have polled three times")
}

func TestRecoveryLoop_TransportBackoffExceedsCapDisables(t *testing.T) {
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)
	cfg.BaseDelay = 1 * time.Hour
	cfg.MaxDelay = 1 * time.Hour
	cfg.TransportLimit = 6 * time.Hour
	fetcher := newFakeFetcher(fetchResult{err: errors.New("dial tcp: connection refused")})

	outcome := r.recoveryLoop(context.Background(), stream, RecoveryModeTransportBackoff, fetcher.fetch, cfg)

	assert.Equal(t, RecoveryOutcomeDisabled, outcome)
	assert.Equal(t, model.StreamStateDisable, stream.Status)
	assert.Contains(t, stream.ErrorMsg, "transport recovery exhausted")
	assert.Contains(t, stream.ErrorMsg, "connection refused")
}

func TestRecoveryLoop_AuthBoundedExhaustsAttempts(t *testing.T) {
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)
	cfg.AuthRetryLimit = 3
	fetcher := newFakeFetcher(fetchResult{err: errors.New("401 unauthorized")})

	outcome := r.recoveryLoop(context.Background(), stream, RecoveryModeAuthBounded, fetcher.fetch, cfg)

	assert.Equal(t, RecoveryOutcomeDisabled, outcome)
	assert.Equal(t, model.StreamStateDisable, stream.Status)
	assert.Contains(t, stream.ErrorMsg, "auth recovery exhausted")
	assert.Equal(t, int32(3), fetcher.calls.Load())
}

func TestRecoveryLoop_TransportRecoversWhenStatusBecomesAvailable(t *testing.T) {
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)
	cfg.BaseDelay = 1 * time.Second
	cfg.MaxDelay = 8 * time.Second
	cfg.TransportLimit = 1 * time.Hour
	fetcher := newFakeFetcher(
		fetchResult{err: errors.New("connection refused")},
		fetchResult{err: errors.New("connection refused")},
		fetchResult{status: &model.StreamStatus{Status: model.StreamStateEnabled}},
	)

	outcome := r.recoveryLoop(context.Background(), stream, RecoveryModeTransportBackoff, fetcher.fetch, cfg)

	assert.Equal(t, RecoveryOutcomeResumed, outcome)
	assert.Equal(t, model.StreamStateEnabled, stream.Status)
}

func TestRecoveryLoop_ContextCancelDuringSleep(t *testing.T) {
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)
	// Sleep that respects ctx and returns false on cancel.
	cfg.Sleep = func(ctx context.Context, d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(0):
			return false
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetcher := newFakeFetcher(fetchResult{err: errors.New("connection refused")})
	outcome := r.recoveryLoop(ctx, stream, RecoveryModeTransportBackoff, fetcher.fetch, cfg)

	assert.Equal(t, RecoveryOutcomeContextDone, outcome)
}

func TestRecoveryLoop_PausedSeenThenFetchErrorUsesPausedCadence(t *testing.T) {
	// Once we observe paused, subsequent fetch errors must NOT trip the transport cap —
	// we know the receiver is up.
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)
	cfg.TransportLimit = 1 * time.Minute // small so the test would trip it without the mode switch
	cfg.StatusCheckInterval = 100 * time.Millisecond
	fetcher := newFakeFetcher(
		fetchResult{status: &model.StreamStatus{Status: model.StreamStatePause, Reason: "maintenance"}},
		fetchResult{err: errors.New("transient hiccup")},
		fetchResult{err: errors.New("transient hiccup")},
		fetchResult{status: &model.StreamStatus{Status: model.StreamStateEnabled}},
	)

	outcome := r.recoveryLoop(context.Background(), stream, RecoveryModeTransportBackoff, fetcher.fetch, cfg)

	assert.Equal(t, RecoveryOutcomeResumed, outcome,
		"after paused observed, transient fetch errors must not disable the stream")
}

func TestRecoveryLoop_NilStreamSafe(t *testing.T) {
	r, _ := newTestRouter(t)
	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)

	outcome := r.recoveryLoop(context.Background(), nil, RecoveryModeTransportBackoff, nil, cfg)
	assert.Equal(t, RecoveryOutcomeDisabled, outcome)
}

func TestRecoveryLoop_NilFetcherSafe(t *testing.T) {
	r, provider := newTestRouter(t)
	stream := mustCreateTestStream(t, provider, projectIdFromProvider(t, provider))

	clock := newFakeClock(time.Now())
	cfg := newRecoveryTestConfig(clock)

	outcome := r.recoveryLoop(context.Background(), stream, RecoveryModeTransportBackoff, nil, cfg)
	assert.Equal(t, RecoveryOutcomeDisabled, outcome)
}

func TestNextBackoff(t *testing.T) {
	max := 5 * time.Minute
	got := nextBackoff(1*time.Second, 2.0, max)
	assert.Equal(t, 2*time.Second, got)
	got = nextBackoff(2*time.Minute, 2.0, max)
	assert.Equal(t, 4*time.Minute, got)
	// Cap.
	got = nextBackoff(4*time.Minute, 2.0, max)
	assert.Equal(t, max, got)
}

func TestRecoveryMode_StringCoversAllValues(t *testing.T) {
	for m := RecoveryModePausedByRemote; m <= RecoveryModeAuthBounded; m++ {
		s := m.String()
		assert.NotEmpty(t, s)
		assert.NotEqual(t, "unknown", s)
	}
}

func TestRecoveryOutcome_StringCoversAllValues(t *testing.T) {
	for o := RecoveryOutcomeResumed; o <= RecoveryOutcomeContextDone; o++ {
		s := o.String()
		assert.NotEmpty(t, s)
		assert.NotEqual(t, "unknown", s)
	}
}

func TestLoadRecoveryConfig_AppliesDefaults(t *testing.T) {
	t.Setenv("I2SIG_PUSH_RETRY_BASE_DELAY", "")
	cfg := LoadRecoveryConfig()
	assert.Equal(t, 1*time.Second, cfg.BaseDelay)
	assert.Equal(t, 6*time.Hour, cfg.TransportLimit)
	assert.Equal(t, 10, cfg.AuthRetryLimit)
	assert.Equal(t, 30*time.Second, cfg.StatusCheckInterval)
}

func TestLoadRecoveryConfig_ParsesEnvVars(t *testing.T) {
	t.Setenv("I2SIG_PUSH_RETRY_BASE_DELAY", "500ms")
	t.Setenv("I2SIG_PUSH_RETRY_LIMIT", "1h")
	t.Setenv("I2SIG_PUSH_UNAUTHORIZED_RETRY_LIMIT", "5")
	t.Setenv("I2SIG_PUSH_STATUS_CHECK_INTERVAL", "2s")

	cfg := LoadRecoveryConfig()
	assert.Equal(t, 500*time.Millisecond, cfg.BaseDelay)
	assert.Equal(t, 1*time.Hour, cfg.TransportLimit)
	assert.Equal(t, 5, cfg.AuthRetryLimit)
	assert.Equal(t, 2*time.Second, cfg.StatusCheckInterval)
}

func TestLoadRecoveryConfig_InvalidValuesUseDefaults(t *testing.T) {
	t.Setenv("I2SIG_PUSH_RETRY_BASE_DELAY", "garbage")
	cfg := LoadRecoveryConfig()
	assert.Equal(t, 1*time.Second, cfg.BaseDelay)
}

// Compile-time assert that StatusFetcher remains a valid type identity (catches accidental
// type renames or signature changes that would break slice-6 wiring).
var _ StatusFetcher = (StatusFetcher)(nil)

// keep require imported via at least one usage (other helpers above).
var _ = require.NotNil
