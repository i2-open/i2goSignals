package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

// The ping purge (ADR 0048): delivered SSF Verification Events ("pings") are
// deleted, with their bodies, once older than the retention. One node per
// cluster runs it, under PingPurgeLeaseResource, every Interval.
const (
	// PingRetentionEnv names the ping retention setting: a Go duration;
	// "0" turns the purge off.
	PingRetentionEnv = "I2SIG_PING_RETENTION"
	// DefaultPingRetention is the retention when PingRetentionEnv is unset.
	DefaultPingRetention = 24 * time.Hour
	// PingPurgeLeaseResource is the lease one node holds while it purges. The
	// lease row also carries the cluster's last completed purge.
	PingPurgeLeaseResource = "maintenance:ping-purge"
)

const (
	defaultPingPurgeInterval      = 6 * time.Hour
	defaultPingPurgeFirstRunDelay = 5 * time.Minute
	defaultPingPurgeCheck         = 15 * time.Minute
	defaultPingPurgeWindow        = time.Hour
	defaultPingPurgePause         = time.Second
	// pingPurgeLeaseTTL is the purge lease's lifetime; the runner renews it
	// between windows.
	pingPurgeLeaseTTL = 30 * time.Second
)

var pingLog = logger.Sub("PING-PURGE")

// errPingPurgeLeaseLost ends a run whose lease was lost between windows.
var errPingPurgeLeaseLost = errors.New("ping purge lease lost")

// PingRetentionFromEnv reads PingRetentionEnv: unset -> DefaultPingRetention;
// "0" (or any zero duration) -> 0 (purge off); unparseable or negative -> WARN
// and DefaultPingRetention.
func PingRetentionFromEnv() time.Duration {
	raw, ok := os.LookupEnv(PingRetentionEnv)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return DefaultPingRetention
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		pingLog.Warn("Invalid ping retention; using the default",
			"env", PingRetentionEnv, "value", raw, "default", formatPingDuration(DefaultPingRetention))
		return DefaultPingRetention
	}
	return d
}

// PingPurgeCoordinator is the slice of the cluster coordinator the runner
// needs. It is satisfied by cluster.ClusterCoordinator
// (internal/providers/cluster).
type PingPurgeCoordinator interface {
	TryAcquireOrRenewLease(resource, nodeId string, leaseDuration time.Duration) (acquired bool, fencingToken int64, leaseUntil time.Time, err error)
	ReleaseLeaseIfOwned(resource, nodeId string) error
	LastPingPurge() (time.Time, error)
	RecordPingPurge(at time.Time, fencingToken int64) (recorded bool, err error)
}

// PingPurgeOptions configures a PingPurger. Zero fields take their defaults.
type PingPurgeOptions struct {
	Retention     time.Duration    // 0 = purge off (callers pass PingRetentionFromEnv())
	Interval      time.Duration    // zero -> 6h
	FirstRunDelay time.Duration    // zero -> 5m
	Check         time.Duration    // zero -> 15m: how often a node checks whether a run is due
	Window        time.Duration    // zero -> 1h: span of one deleteMany window
	Pause         time.Duration    // zero -> 1s: pause between windows
	Now           func() time.Time // nil -> time.Now
}

// PingPurgeSummary reports one RunOnce.
type PingPurgeSummary struct {
	Ran        bool // false: not due, lease not acquired, or purge off
	Deliveries int64
	Bodies     int64
	Windows    int
	Duration   time.Duration
}

// PingPurger runs the ping purge. Build it with NewPingPurger.
type PingPurger struct {
	eventDAO interfaces.EventDAO
	coord    PingPurgeCoordinator
	nodeID   string
	opts     PingPurgeOptions

	// runMu serialises runs on this node.
	runMu sync.Mutex
	// lastPurge is the last completed purge when there is no coordinator.
	lastPurge time.Time

	mu      sync.Mutex
	started bool
	stopped bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewPingPurger builds the runner. coord may be nil (single node, no
// coordinator): the runner purges without a lease and keeps the last-purge
// time in memory.
func NewPingPurger(eventDAO interfaces.EventDAO, coord PingPurgeCoordinator, nodeID string, opts PingPurgeOptions) *PingPurger {
	if opts.Interval <= 0 {
		opts.Interval = defaultPingPurgeInterval
	}
	if opts.FirstRunDelay <= 0 {
		opts.FirstRunDelay = defaultPingPurgeFirstRunDelay
	}
	if opts.Check <= 0 {
		opts.Check = defaultPingPurgeCheck
	}
	if opts.Window <= 0 {
		opts.Window = defaultPingPurgeWindow
	}
	if opts.Pause <= 0 {
		opts.Pause = defaultPingPurgePause
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Retention < 0 {
		opts.Retention = 0
	}
	if isNilCoordinator(coord) {
		coord = nil
	}
	return &PingPurger{eventDAO: eventDAO, coord: coord, nodeID: nodeID, opts: opts}
}

// isNilCoordinator reports a nil interface or one holding a nil pointer, so a
// typed-nil coordinator is treated as none.
func isNilCoordinator(c PingPurgeCoordinator) bool {
	if c == nil {
		return true
	}
	v := reflect.ValueOf(c)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// LogPosture logs the purge posture in one INFO line, beside the server's
// retention-posture line.
func (p *PingPurger) LogPosture() {
	if p.opts.Retention == 0 {
		pingLog.Info("ping purge off (I2SIG_PING_RETENTION=0)", "doc", "docs/operations.md#event-retention")
		return
	}
	pingLog.Info(fmt.Sprintf("ping retention %s; purge every %s, one node per cluster",
		formatPingDuration(p.opts.Retention), formatPingDuration(p.opts.Interval)),
		"doc", "docs/operations.md#event-retention")
}

// formatPingDuration drops the trailing zero units: 24h0m0s -> 24h.
func formatPingDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Start launches the check loop: the first check after FirstRunDelay, then
// one every Check. It is a no-op when Retention is 0, after Stop, or when
// already started.
func (p *PingPurger) Start(ctx context.Context) {
	if p.opts.Retention == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started || p.stopped {
		return
	}
	p.started = true
	loopCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.done = make(chan struct{})
	go p.loop(loopCtx, p.done)
}

// Stop ends the check loop and waits for an in-flight window to finish. It is
// idempotent and safe before Start.
func (p *PingPurger) Stop() {
	p.mu.Lock()
	p.stopped = true
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func (p *PingPurger) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	timer := time.NewTimer(p.opts.FirstRunDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if _, err := p.RunOnce(ctx); err != nil && ctx.Err() == nil {
			pingLog.Debug("Ping purge run ended early; the next check retries", "error", err)
		}
		timer.Reset(p.opts.Check)
	}
}

// RunOnce makes one due-check and, when due, one run (ADR 0048): acquire the
// lease, delete the windows from the oldest stored ping up to now-Retention
// oldest first, then record the purge and release the lease. A run stopped by
// ctx, a lost lease or a failed window records nothing, so the next check
// retries.
func (p *PingPurger) RunOnce(ctx context.Context) (PingPurgeSummary, error) {
	var sum PingPurgeSummary
	if p.opts.Retention == 0 || p.eventDAO == nil {
		return sum, nil
	}
	p.runMu.Lock()
	defer p.runMu.Unlock()

	now := p.opts.Now()
	last, err := p.lastPurgeAt()
	if err != nil {
		pingLog.Warn("Ping purge: cannot read the last purge", "error", err)
		return sum, err
	}
	if !last.IsZero() && now.Before(last.Add(p.opts.Interval)) {
		return sum, nil
	}

	var token int64
	if p.coord != nil {
		acquired, tok, _, err := p.coord.TryAcquireOrRenewLease(PingPurgeLeaseResource, p.nodeID, pingPurgeLeaseTTL)
		if err != nil {
			pingLog.Warn("Ping purge: lease acquire failed", "error", err)
			return sum, err
		}
		if !acquired {
			return sum, nil
		}
		token = tok
		defer func() {
			if err := p.coord.ReleaseLeaseIfOwned(PingPurgeLeaseResource, p.nodeID); err != nil {
				pingLog.Warn("Ping purge: lease release failed", "error", err)
			}
		}()
	}
	sum.Ran = true

	cutoff := now.Add(-p.opts.Retention)
	// A window in flight finishes even when ctx is cancelled (Stop waits for
	// it); ctx is honoured between windows.
	windowCtx := context.WithoutCancel(ctx)
	from, ok, err := p.eventDAO.OldestPingStoredAt(windowCtx)
	if err != nil {
		pingLog.Warn("Ping purge: cannot find the oldest ping", "error", err)
		return sum, err
	}
	for ok && from.Before(cutoff) {
		if sum.Windows > 0 {
			if err := p.between(ctx, token); err != nil {
				sum.Duration = p.opts.Now().Sub(now)
				return sum, err
			}
		}
		to := from.Add(p.opts.Window)
		if to.After(cutoff) {
			to = cutoff
		}
		res, err := p.eventDAO.PurgePingWindow(windowCtx, from, to)
		sum.Deliveries += res.Deliveries
		sum.Bodies += res.Bodies
		if err != nil {
			sum.Duration = p.opts.Now().Sub(now)
			pingLog.Warn("Ping purge window failed; the run ends unrecorded",
				"from", from, "to", to, "error", err)
			return sum, err
		}
		sum.Windows++
		from = to
	}

	if p.coord != nil {
		recorded, err := p.coord.RecordPingPurge(now, token)
		if err != nil {
			pingLog.Warn("Ping purge: cannot record the purge", "error", err)
			return sum, err
		}
		if !recorded {
			pingLog.Warn("Ping purge: lease superseded; the purge is not recorded")
			return sum, errPingPurgeLeaseLost
		}
	} else {
		p.lastPurge = now
	}
	sum.Duration = p.opts.Now().Sub(now)
	pingLog.Info("Ping purge complete",
		"deliveries", sum.Deliveries,
		"bodies", sum.Bodies,
		"windows", sum.Windows,
		"duration", sum.Duration,
		"cutoff", cutoff)
	return sum, nil
}

// between pauses between windows and renews the lease; it fails when ctx is
// done or the lease was lost.
func (p *PingPurger) between(ctx context.Context, token int64) error {
	t := time.NewTimer(p.opts.Pause)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if p.coord == nil {
		return nil
	}
	acquired, tok, _, err := p.coord.TryAcquireOrRenewLease(PingPurgeLeaseResource, p.nodeID, pingPurgeLeaseTTL)
	if err != nil {
		pingLog.Warn("Ping purge: lease renewal failed; the run ends unrecorded", "error", err)
		return err
	}
	if !acquired || tok != token {
		pingLog.Warn("Ping purge: lease lost; the run ends unrecorded")
		return errPingPurgeLeaseLost
	}
	return nil
}

func (p *PingPurger) lastPurgeAt() (time.Time, error) {
	if p.coord == nil {
		return p.lastPurge, nil
	}
	return p.coord.LastPingPurge()
}
