package services

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// fakePurgeCoord is an in-test coordinator with the lease and fencing
// semantics of cluster.ClusterCoordinator for the ping-purge resource.
type fakePurgeCoord struct {
	mu        sync.Mutex
	now       func() time.Time
	owner     string
	until     time.Time
	token     int64
	lastPurge time.Time
	acquires  int
}

func (c *fakePurgeCoord) TryAcquireOrRenewLease(resource, nodeID string, d time.Duration) (bool, int64, time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if resource != PingPurgeLeaseResource {
		return false, 0, time.Time{}, errors.New("unexpected resource " + resource)
	}
	c.acquires++
	now := c.now()
	expired := !c.until.After(now)
	if !expired && c.owner != nodeID {
		return false, 0, time.Time{}, nil
	}
	if expired || c.owner != nodeID {
		c.token++
	}
	c.owner, c.until = nodeID, now.Add(d)
	return true, c.token, c.until, nil
}

func (c *fakePurgeCoord) ReleaseLeaseIfOwned(_, nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.owner == nodeID {
		c.until = c.now()
	}
	return nil
}

func (c *fakePurgeCoord) LastPingPurge() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPurge, nil
}

func (c *fakePurgeCoord) RecordPingPurge(at time.Time, token int64) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if token != c.token {
		return false, nil
	}
	c.lastPurge = at
	return true, nil
}

// steal hands the lease to another node, as a takeover after expiry would.
func (c *fakePurgeCoord) steal(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.owner, c.until = nodeID, c.now().Add(time.Hour)
	c.token++
}

// hookDAO wraps the memory DAO to observe and steer PurgePingWindow.
type hookDAO struct {
	*memory.EventDAOMemory
	mu      sync.Mutex
	windows [][2]time.Time
	after   func(n int) // called after the n-th window (1-based)
	fail    error
}

func (d *hookDAO) PurgePingWindow(ctx context.Context, from, to time.Time) (interfaces.PingPurgeResult, error) {
	if d.fail != nil {
		return interfaces.PingPurgeResult{}, d.fail
	}
	res, err := d.EventDAOMemory.PurgePingWindow(ctx, from, to)
	d.mu.Lock()
	d.windows = append(d.windows, [2]time.Time{from, to})
	n := len(d.windows)
	d.mu.Unlock()
	if d.after != nil {
		d.after(n)
	}
	return res, err
}

func (d *hookDAO) windowCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.windows)
}

var pingT0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func pingRecord(jti string, receivedAt time.Time) *model.EventRecord {
	ev := goSet.SecurityEventToken{Events: map[string]interface{}{events.VerificationEventUri: map[string]interface{}{}}}
	ev.ID = jti
	return &model.EventRecord{Jti: jti, Event: ev, Types: []string{events.VerificationEventUri}, SortTime: receivedAt, ReceivedAt: receivedAt}
}

// seedDeliveredPing stores a ping received at at and delivers it on sid.
func seedDeliveredPing(t *testing.T, d *memory.EventDAOMemory, jti, sid string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	d.SetClock(func() time.Time { return at })
	if err := d.Insert(ctx, pingRecord(jti, at)); err != nil {
		t.Fatalf("insert %s: %v", jti, err)
	}
	if err := d.AddPending(ctx, interfaces.PendingRef{Jti: jti, AckJti: jti, Ping: true}, sid); err != nil {
		t.Fatalf("queue %s: %v", jti, err)
	}
	if _, err := d.Ack(ctx, interfaces.AckBatch{StreamID: sid, Jtis: []string{jti}, AckDate: at}); err != nil {
		t.Fatalf("ack %s: %v", jti, err)
	}
	d.SetClock(nil)
}

func bodyStored(t *testing.T, d interfaces.EventDAO, jti string) bool {
	t.Helper()
	rec, err := d.FindByJTI(context.Background(), jti)
	return err == nil && rec != nil
}

// captureLog routes slog.Default (and so every logger.Sub logger) to a buffer
// for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	var mu sync.Mutex
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func clockAt(at time.Time) func() time.Time { return func() time.Time { return at } }

func TestPingRetentionFromEnv(t *testing.T) {
	cases := []struct {
		name, value string
		set         bool
		want        time.Duration
		warn        bool
	}{
		{name: "unset", want: 24 * time.Hour},
		{name: "zero", value: "0", set: true, want: 0},
		{name: "zero duration", value: "0s", set: true, want: 0},
		{name: "explicit", value: "2h", set: true, want: 2 * time.Hour},
		{name: "unparseable", value: "a day", set: true, want: 24 * time.Hour, warn: true},
		{name: "negative", value: "-1h", set: true, want: 24 * time.Hour, warn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(PingRetentionEnv, tc.value)
			if !tc.set {
				// t.Setenv restores the old value at cleanup; unset it for the call.
				unsetEnv(t, PingRetentionEnv)
			}
			buf := captureLog(t)
			if got := PingRetentionFromEnv(); got != tc.want {
				t.Fatalf("PingRetentionFromEnv() = %v, want %v", got, tc.want)
			}
			gotWarn := strings.Contains(buf.String(), "level=WARN")
			if gotWarn != tc.warn {
				t.Fatalf("WARN logged = %v, want %v; log:\n%s", gotWarn, tc.warn, buf.String())
			}
		})
	}
}

func TestPingPurger_LogPosture(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		buf := captureLog(t)
		NewPingPurger(memory.NewEventDAO(), nil, "n1", PingPurgeOptions{Retention: DefaultPingRetention}).LogPosture()
		if !strings.Contains(buf.String(), "ping retention 24h; purge every 6h, one node per cluster") {
			t.Fatalf("posture line missing; log:\n%s", buf.String())
		}
	})
	t.Run("off", func(t *testing.T) {
		buf := captureLog(t)
		NewPingPurger(memory.NewEventDAO(), nil, "n1", PingPurgeOptions{}).LogPosture()
		if !strings.Contains(buf.String(), "ping purge off (I2SIG_PING_RETENTION=0)") {
			t.Fatalf("off posture line missing; log:\n%s", buf.String())
		}
	})
}

// TestPingPurger_OffRunsNothing: Retention 0 -> Start starts nothing and
// RunOnce does not run.
func TestPingPurger_OffRunsNothing(t *testing.T) {
	d := &hookDAO{EventDAOMemory: memory.NewEventDAO()}
	seedDeliveredPing(t, d.EventDAOMemory, "old", "s1", pingT0)
	coord := &fakePurgeCoord{now: clockAt(pingT0.Add(48 * time.Hour))}
	p := NewPingPurger(d, coord, "n1", PingPurgeOptions{Now: coord.now, FirstRunDelay: time.Millisecond, Check: time.Millisecond})
	p.Start(context.Background())
	time.Sleep(20 * time.Millisecond)
	p.Stop()
	sum, err := p.RunOnce(context.Background())
	if err != nil || sum.Ran {
		t.Fatalf("RunOnce = %+v, %v; want not run", sum, err)
	}
	if d.windowCount() != 0 || coord.acquires != 0 || !bodyStored(t, d, "old") {
		t.Fatalf("purge off still acted: windows=%d acquires=%d", d.windowCount(), coord.acquires)
	}
}

// TestPingPurger_WindowsOldestFirst: a backlog spanning several windows is
// deleted oldest first, the windows tiling [oldest, cutoff).
func TestPingPurger_WindowsOldestFirst(t *testing.T) {
	d := &hookDAO{EventDAOMemory: memory.NewEventDAO()}
	for i, at := range []time.Duration{0, 90 * time.Minute, 3 * time.Hour, 5*time.Hour + 30*time.Minute} {
		seedDeliveredPing(t, d.EventDAOMemory, "p"+string(rune('0'+i)), "s1", pingT0.Add(at))
	}
	now := pingT0.Add(30 * time.Hour)
	seedDeliveredPing(t, d.EventDAOMemory, "young", "s1", now.Add(-time.Hour))
	coord := &fakePurgeCoord{now: clockAt(now)}
	buf := captureLog(t)
	p := NewPingPurger(d, coord, "n1", PingPurgeOptions{Retention: 24 * time.Hour, Window: 2 * time.Hour, Pause: time.Millisecond, Now: coord.now})

	sum, err := p.RunOnce(context.Background())
	if err != nil || !sum.Ran {
		t.Fatalf("RunOnce = %+v, %v", sum, err)
	}
	cutoff := now.Add(-24 * time.Hour)
	if len(d.windows) != 3 || sum.Windows != 3 {
		t.Fatalf("windows = %v (summary %d), want 3", d.windows, sum.Windows)
	}
	from := pingT0
	for i, w := range d.windows {
		wantTo := from.Add(2 * time.Hour)
		if wantTo.After(cutoff) {
			wantTo = cutoff
		}
		if !w[0].Equal(from) || !w[1].Equal(wantTo) {
			t.Fatalf("window %d = [%v, %v), want [%v, %v)", i, w[0], w[1], from, wantTo)
		}
		from = wantTo
	}
	if sum.Bodies != 4 || sum.Deliveries != 4 {
		t.Fatalf("summary = %+v, want 4 bodies and 4 deliveries", sum)
	}
	for _, jti := range []string{"p0", "p1", "p2", "p3"} {
		if bodyStored(t, d, jti) {
			t.Fatalf("%s survived the purge", jti)
		}
	}
	if !bodyStored(t, d, "young") {
		t.Fatal("young ping purged")
	}
	if last, _ := coord.LastPingPurge(); !last.Equal(now) {
		t.Fatalf("last purge = %v, want %v", last, now)
	}
	if !strings.Contains(buf.String(), "Ping purge complete") || !strings.Contains(buf.String(), "bodies=4") {
		t.Fatalf("INFO summary missing; log:\n%s", buf.String())
	}
	if owner, until := coord.owner, coord.until; owner == "n1" && until.After(now) {
		t.Fatal("lease not released after the run")
	}
}

// TestPingPurger_CancelStopsBetweenWindows: a cancelled context stops the run
// between windows and records nothing; a second RunOnce finishes the job.
func TestPingPurger_CancelStopsBetweenWindows(t *testing.T) {
	d := &hookDAO{EventDAOMemory: memory.NewEventDAO()}
	for i := 0; i < 4; i++ {
		seedDeliveredPing(t, d.EventDAOMemory, "p"+string(rune('0'+i)), "s1", pingT0.Add(time.Duration(i)*time.Hour))
	}
	now := pingT0.Add(48 * time.Hour)
	coord := &fakePurgeCoord{now: clockAt(now)}
	ctx, cancel := context.WithCancel(context.Background())
	d.after = func(n int) {
		if n == 1 {
			cancel()
		}
	}
	p := NewPingPurger(d, coord, "n1", PingPurgeOptions{Retention: 24 * time.Hour, Window: time.Hour, Pause: time.Millisecond, Now: coord.now})
	sum, err := p.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce err = %v, want context.Canceled", err)
	}
	if sum.Windows != 1 || d.windowCount() != 1 {
		t.Fatalf("windows = %d (dao %d), want 1", sum.Windows, d.windowCount())
	}
	if last, _ := coord.LastPingPurge(); !last.IsZero() {
		t.Fatalf("cancelled run recorded a purge at %v", last)
	}
	if bodyStored(t, d, "p0") || !bodyStored(t, d, "p3") {
		t.Fatal("first window not purged, or a later one purged")
	}

	d.after = nil
	sum, err = p.RunOnce(context.Background())
	if err != nil || !sum.Ran {
		t.Fatalf("second RunOnce = %+v, %v", sum, err)
	}
	for i := 0; i < 4; i++ {
		if bodyStored(t, d, "p"+string(rune('0'+i))) {
			t.Fatalf("p%d survived the second run", i)
		}
	}
	if last, _ := coord.LastPingPurge(); !last.Equal(now) {
		t.Fatalf("last purge = %v, want %v", last, now)
	}
}

// TestPingPurger_TwoNodesOneRuns: with two nodes sharing one coordinator, only
// the lease holder purges.
func TestPingPurger_TwoNodesOneRuns(t *testing.T) {
	d := &hookDAO{EventDAOMemory: memory.NewEventDAO()}
	seedDeliveredPing(t, d.EventDAOMemory, "old", "s1", pingT0)
	now := pingT0.Add(48 * time.Hour)
	coord := &fakePurgeCoord{now: clockAt(now)}
	opts := PingPurgeOptions{Retention: 24 * time.Hour, Pause: time.Millisecond, Now: coord.now}
	a := NewPingPurger(d, coord, "A", opts)
	b := NewPingPurger(d, coord, "B", opts)

	// A holds the lease (mid-run); B's run does not happen.
	if ok, _, _, _ := coord.TryAcquireOrRenewLease(PingPurgeLeaseResource, "A", time.Minute); !ok {
		t.Fatal("A could not take the lease")
	}
	sum, err := b.RunOnce(context.Background())
	if err != nil || sum.Ran || d.windowCount() != 0 || !bodyStored(t, d, "old") {
		t.Fatalf("B ran while A held the lease: %+v, %v, windows=%d", sum, err, d.windowCount())
	}
	sum, err = a.RunOnce(context.Background())
	if err != nil || !sum.Ran || bodyStored(t, d, "old") {
		t.Fatalf("A (holder) did not purge: %+v, %v", sum, err)
	}
}

// TestPingPurger_LeaseLossStops: a run that loses the lease between windows
// stops and records nothing.
func TestPingPurger_LeaseLossStops(t *testing.T) {
	d := &hookDAO{EventDAOMemory: memory.NewEventDAO()}
	for i := 0; i < 3; i++ {
		seedDeliveredPing(t, d.EventDAOMemory, "p"+string(rune('0'+i)), "s1", pingT0.Add(time.Duration(i)*time.Hour))
	}
	now := pingT0.Add(48 * time.Hour)
	coord := &fakePurgeCoord{now: clockAt(now)}
	d.after = func(n int) {
		if n == 1 {
			coord.steal("B")
		}
	}
	p := NewPingPurger(d, coord, "A", PingPurgeOptions{Retention: 24 * time.Hour, Window: time.Hour, Pause: time.Millisecond, Now: coord.now})
	sum, err := p.RunOnce(context.Background())
	if !errors.Is(err, errPingPurgeLeaseLost) || sum.Windows != 1 {
		t.Fatalf("RunOnce = %+v, %v; want lease lost after 1 window", sum, err)
	}
	if last, _ := coord.LastPingPurge(); !last.IsZero() {
		t.Fatalf("run that lost its lease recorded %v", last)
	}
	if !bodyStored(t, d, "p2") {
		t.Fatal("window after the lease loss was purged")
	}
	if coord.owner != "B" {
		t.Fatalf("lease owner = %q, want B (release must not touch another node's lease)", coord.owner)
	}
}

// TestPingPurger_NextRunDueAfterInterval: the next run is due Interval after
// the recorded last purge, whichever node runs it.
func TestPingPurger_NextRunDueAfterInterval(t *testing.T) {
	d := &hookDAO{EventDAOMemory: memory.NewEventDAO()}
	now := pingT0.Add(48 * time.Hour)
	clock := now
	var mu sync.Mutex
	nowFn := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	set := func(at time.Time) { mu.Lock(); clock = at; mu.Unlock() }
	coord := &fakePurgeCoord{now: nowFn}
	opts := PingPurgeOptions{Retention: 24 * time.Hour, Interval: 6 * time.Hour, Pause: time.Millisecond, Now: nowFn}
	a := NewPingPurger(d, coord, "A", opts)
	b := NewPingPurger(d, coord, "B", opts)

	if sum, err := a.RunOnce(context.Background()); err != nil || !sum.Ran {
		t.Fatalf("A first run = %+v, %v", sum, err)
	}
	set(now.Add(6*time.Hour - time.Minute))
	if sum, err := b.RunOnce(context.Background()); err != nil || sum.Ran {
		t.Fatalf("B ran before Interval elapsed: %+v, %v", sum, err)
	}
	set(now.Add(6 * time.Hour))
	if sum, err := b.RunOnce(context.Background()); err != nil || !sum.Ran {
		t.Fatalf("B did not run once Interval elapsed: %+v, %v", sum, err)
	}
	if last, _ := coord.LastPingPurge(); !last.Equal(now.Add(6 * time.Hour)) {
		t.Fatalf("last purge = %v", last)
	}
}

// TestPingPurger_FailedWindowNotRecorded: a failed window logs WARN and ends
// the run without recording, so the next check retries.
func TestPingPurger_FailedWindowNotRecorded(t *testing.T) {
	d := &hookDAO{EventDAOMemory: memory.NewEventDAO(), fail: errors.New("boom")}
	seedDeliveredPing(t, d.EventDAOMemory, "old", "s1", pingT0)
	now := pingT0.Add(48 * time.Hour)
	coord := &fakePurgeCoord{now: clockAt(now)}
	buf := captureLog(t)
	p := NewPingPurger(d, coord, "n1", PingPurgeOptions{Retention: 24 * time.Hour, Pause: time.Millisecond, Now: coord.now})
	if _, err := p.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce: want the window error")
	}
	if last, _ := coord.LastPingPurge(); !last.IsZero() {
		t.Fatalf("failed run recorded %v", last)
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("no WARN for the failed window; log:\n%s", buf.String())
	}
	d.fail = nil
	if sum, err := p.RunOnce(context.Background()); err != nil || !sum.Ran || bodyStored(t, d, "old") {
		t.Fatalf("retry = %+v, %v", sum, err)
	}
}

// TestPingPurger_NoCoordinator: a nil coordinator (typed nil included) purges
// without a lease and keeps the last purge in memory.
func TestPingPurger_NoCoordinator(t *testing.T) {
	d := memory.NewEventDAO()
	seedDeliveredPing(t, d, "old", "s1", pingT0)
	now := pingT0.Add(48 * time.Hour)
	var typedNil *fakePurgeCoord
	p := NewPingPurger(d, typedNil, "n1", PingPurgeOptions{Retention: 24 * time.Hour, Pause: time.Millisecond, Now: clockAt(now)})
	if sum, err := p.RunOnce(context.Background()); err != nil || !sum.Ran || bodyStored(t, d, "old") {
		t.Fatalf("first run = %+v, %v", sum, err)
	}
	if sum, err := p.RunOnce(context.Background()); err != nil || sum.Ran {
		t.Fatalf("second run before Interval = %+v, %v; want not due", sum, err)
	}
}

// TestPingPurger_StartStop: Stop is safe before Start and idempotent; a
// started purger runs after FirstRunDelay and Stop waits for it.
func TestPingPurger_StartStop(t *testing.T) {
	NewPingPurger(memory.NewEventDAO(), nil, "n1", PingPurgeOptions{Retention: time.Hour}).Stop()

	d := &hookDAO{EventDAOMemory: memory.NewEventDAO()}
	seedDeliveredPing(t, d.EventDAOMemory, "old", "s1", pingT0)
	coord := &fakePurgeCoord{now: time.Now}
	p := NewPingPurger(d, coord, "n1", PingPurgeOptions{Retention: time.Hour, FirstRunDelay: time.Millisecond, Check: time.Millisecond, Pause: time.Millisecond})
	p.Start(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for bodyStored(t, d, "old") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	p.Stop()
	p.Stop()
	if bodyStored(t, d, "old") {
		t.Fatal("started purger never purged")
	}
	n := d.windowCount()
	time.Sleep(10 * time.Millisecond)
	if d.windowCount() != n {
		t.Fatal("purger still running after Stop")
	}
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
}
