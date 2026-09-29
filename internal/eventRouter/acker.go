package eventRouter

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/prometheus/client_golang/prometheus"
)

// Send/ack decoupling (#336, spec-111 Stage 2).
//
// A delivery runner used to gate its next batch on the previous batch's ack
// write. The acker takes that write off the send path. It keeps a bounded
// in-flight set of JTIs per stream: a JTI joins when it is taken for sending
// and leaves once its ack is durably applied or it is handed back as
// unacked. Completions queue their acked JTIs, and one goroutine drains the
// queue every coalescing window, or sooner once the queue reaches its size
// cap, applying one AckEvents (the #335 one-trip write) per drain. The send
// loop goes on while an ack is being written; the in-flight bound is the
// back-pressure.
//
// The at-least-once contract is unchanged (ADR 0038): a JTI is acked only
// after the receiver accepted it, and one sent but not yet acked is still
// pending in the store, so a crash or a lost lease redelivers it through the
// existing recovery path. Stop flushes the queue first, so a clean stop
// redelivers nothing it already had acked by the receiver.

const (
	// defaultDeliveryInFlightMax is the I2SIG_DELIVERY_INFLIGHT_MAX default:
	// twice the largest push batch the ADR 0037 ceiling allows (4 x 32), so
	// one full batch can be on the wire while the previous one's ack is
	// written. It is also the most SETs a crash can redeliver per stream.
	defaultDeliveryInFlightMax = 256
	// defaultAckCoalesceWindow is the I2SIG_ACK_COALESCE_WINDOW default.
	defaultAckCoalesceWindow = 5 * time.Millisecond
)

// deliveryInFlightMax resolves I2SIG_DELIVERY_INFLIGHT_MAX. An unset or
// invalid value gives the default.
func deliveryInFlightMax() int {
	if val := os.Getenv("I2SIG_DELIVERY_INFLIGHT_MAX"); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			return i
		}
		eventLogger.Warn("Ignoring invalid I2SIG_DELIVERY_INFLIGHT_MAX (want a positive integer)", "value", val)
	}
	return defaultDeliveryInFlightMax
}

// ackCoalesceWindow resolves I2SIG_ACK_COALESCE_WINDOW. 0 acks inline, as
// before #336. An unset or invalid value gives the default.
func ackCoalesceWindow() time.Duration {
	if val := os.Getenv("I2SIG_ACK_COALESCE_WINDOW"); val != "" {
		if d, err := time.ParseDuration(val); err == nil && d >= 0 {
			return d
		}
		eventLogger.Warn("Ignoring invalid I2SIG_ACK_COALESCE_WINDOW (want a non-negative duration)", "value", val)
	}
	return defaultAckCoalesceWindow
}

var (
	deliveryInFlightGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "delivery_inflight",
		Help:      "JTIs a delivery runner has taken for sending and not yet acked or handed back.",
	}, []string{"stream_id", "transport"})
	ackBatchSizeHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "delivery_ack_batch_size",
		Help:      "JTIs applied per coalesced delivery ack write.",
		Buckets:   []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
	}, []string{"transport"})
	pollClaimedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "poll_claimed_inflight",
		Help:      "JTIs an RFC 8936 poll stream has returned under an unexpired claim and not yet had acked (#337).",
	}, []string{"stream_id"})
)

// DeliveryCollectors returns the acker's Prometheus collectors for the
// server's registry.
func DeliveryCollectors() []prometheus.Collector {
	return []prometheus.Collector{deliveryInFlightGauge, ackBatchSizeHist, pollClaimedGauge}
}

// ackerConfig configures one acker.
type ackerConfig struct {
	sid       string
	transport string // metric label: "push" or "sstp"
	// apply writes one coalesced ack. An error wrapping
	// services.ErrStaleFencingToken fences the acker.
	apply func(ctx context.Context, jtis []string) error
	// onApplied, when set, runs after each apply with its JTIs and outcome,
	// before they leave the in-flight set.
	onApplied func(jtis []string, err error)
	// window is the coalescing window; 0 applies every completion inline.
	window time.Duration
	// max bounds the in-flight set. A reservation larger than max is let in
	// alone, so one batch always fits.
	max int
	// sizeCap drains the queue before the window ends once it holds this
	// many JTIs. 0 means max/2.
	sizeCap int
}

// acker is the bounded in-flight set and coalescing acker of one stream's
// delivery runner. Its apply context is fixed at construction.
type acker struct {
	cfg ackerConfig
	ctx context.Context

	mu       sync.Mutex
	inflight map[string]struct{}
	queue    []string
	fenceErr error
	// space is closed, and replaced, whenever the in-flight set shrinks.
	space  chan struct{}
	fenced chan struct{}
	closed bool

	// applyMu serialises applies, so a flush and a drain never write the same
	// JTIs twice or out of order.
	applyMu sync.Mutex
	kick    chan struct{}
	stop    chan struct{}
	done    chan struct{}
}

func newAcker(ctx context.Context, cfg ackerConfig) *acker {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.max < 1 {
		cfg.max = 1
	}
	if cfg.sizeCap < 1 {
		cfg.sizeCap = cfg.max / 2
		if cfg.sizeCap < 1 {
			cfg.sizeCap = 1
		}
	}
	a := &acker{
		cfg:      cfg,
		ctx:      ctx,
		inflight: map[string]struct{}{},
		space:    make(chan struct{}),
		fenced:   make(chan struct{}),
		kick:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if cfg.window > 0 {
		go a.run()
	} else {
		close(a.done)
	}
	return a
}

// run is the drain goroutine: one apply per window, or sooner on a kick.
func (a *acker) run() {
	defer close(a.done)
	t := time.NewTimer(a.cfg.window)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-a.ctx.Done():
			// Router shutdown: nothing more can be written on this context.
			// Whatever is queued stays pending and is redelivered.
			return
		case <-a.kick:
		case <-t.C:
		}
		_ = a.drain()
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(a.cfg.window)
	}
}

// reserve adds jtis to the in-flight set before they are sent and returns
// the ones it added: a JTI already in flight is dropped, since it is being
// sent or acked already. It waits while the set is full, and returns ctx's
// error if ctx ends first, or the fence error once the acker is fenced.
func (a *acker) reserve(ctx context.Context, jtis []string) ([]string, error) {
	for {
		a.mu.Lock()
		if a.fenceErr != nil {
			err := a.fenceErr
			a.mu.Unlock()
			return nil, err
		}
		fresh := make([]string, 0, len(jtis))
		seen := make(map[string]struct{}, len(jtis))
		for _, jti := range jtis {
			if _, ok := a.inflight[jti]; ok {
				continue
			}
			if _, ok := seen[jti]; ok {
				continue
			}
			seen[jti] = struct{}{}
			fresh = append(fresh, jti)
		}
		if len(fresh) == 0 {
			a.mu.Unlock()
			return nil, nil
		}
		if len(a.inflight) == 0 || len(a.inflight)+len(fresh) <= a.cfg.max {
			for _, jti := range fresh {
				a.inflight[jti] = struct{}{}
			}
			a.gaugeLocked()
			a.mu.Unlock()
			return fresh, nil
		}
		space := a.space
		a.mu.Unlock()
		a.nudge()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-a.fenced:
		case <-space:
		}
	}
}

// inFlight reports whether jti is in the in-flight set. Backfill uses it so
// a JTI sent and awaiting its ack is not read back from the store and resent.
func (a *acker) inFlight(jti string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.inflight[jti]
	return ok
}

// size is the in-flight count.
func (a *acker) size() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.inflight)
}

// complete records a batch's outcome: acked JTIs join the ack queue (and the
// in-flight set, if they were not reserved) and stay in flight until their
// ack is applied; released JTIs were not acked and leave the set at once,
// still pending in the store. With a zero window the ack is applied here and
// its error returned. Otherwise the error is the fence error, once an earlier
// drain was fenced.
func (a *acker) complete(acked, released []string) error {
	a.mu.Lock()
	for _, jti := range released {
		delete(a.inflight, jti)
	}
	if a.fenceErr != nil {
		for _, jti := range acked {
			delete(a.inflight, jti)
		}
		err := a.fenceErr
		a.shrankLocked()
		a.mu.Unlock()
		if len(acked) > 0 && a.cfg.onApplied != nil {
			a.cfg.onApplied(acked, err)
		}
		return err
	}
	for _, jti := range acked {
		a.inflight[jti] = struct{}{}
	}
	a.queue = append(a.queue, acked...)
	full := len(a.queue) >= a.cfg.sizeCap
	closed := a.closed
	a.shrankLocked()
	a.mu.Unlock()
	// After close the flush loop is gone, so a late completion drains inline
	// rather than sitting in a queue nobody will apply.
	if a.cfg.window <= 0 || closed {
		return a.drain()
	}
	if full {
		a.nudge()
	}
	return nil
}

// flush applies whatever is queued now and returns the apply's error.
func (a *acker) flush() error {
	return a.drain()
}

// close stops the drain goroutine and flushes what is queued: a runner stop
// applies the acks it already has. JTIs still reserved but never completed
// stay pending for the successor.
func (a *acker) close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()
	if a.cfg.window > 0 {
		close(a.stop)
	}
	<-a.done
	err := a.drain()
	deliveryInFlightGauge.DeleteLabelValues(a.cfg.sid, a.cfg.transport)
	return err
}

// fencedCh is closed once an apply is refused on a stale fencing token.
func (a *acker) fencedCh() <-chan struct{} {
	return a.fenced
}

// drain applies the queued acks in one write.
func (a *acker) drain() error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	a.mu.Lock()
	batch := a.queue
	a.queue = nil
	a.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	err := a.cfg.apply(a.ctx, batch)
	ackBatchSizeHist.WithLabelValues(a.cfg.transport).Observe(float64(len(batch)))
	if a.cfg.onApplied != nil {
		a.cfg.onApplied(batch, err)
	}
	a.mu.Lock()
	for _, jti := range batch {
		delete(a.inflight, jti)
	}
	if err != nil && errors.Is(err, services.ErrStaleFencingToken) && a.fenceErr == nil {
		a.fenceErr = err
		close(a.fenced)
	}
	a.shrankLocked()
	a.mu.Unlock()
	return err
}

func (a *acker) nudge() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// shrankLocked wakes reservations waiting for room and updates the gauge.
func (a *acker) shrankLocked() {
	close(a.space)
	a.space = make(chan struct{})
	a.gaugeLocked()
}

func (a *acker) gaugeLocked() {
	deliveryInFlightGauge.WithLabelValues(a.cfg.sid, a.cfg.transport).Set(float64(len(a.inflight)))
}
