package eventRouter

import (
	"container/heap"
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
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
	return []prometheus.Collector{deliveryInFlightGauge, ackBatchSizeHist, pollClaimedGauge, ackWritesTotal, ackBatchesTotal, readsBeforeAckTotal}
}

// ackerConfig configures one acker.
type ackerConfig struct {
	sid       string
	transport string // metric label: "push" or "sstp"
	// apply writes one coalesced ack. An error wrapping errNotLeaseOwner
	// means this node's lease tenure ran out before the write: nothing was
	// written, and the batch is kept for the next drain (#364).
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
	// space is closed, and replaced, whenever the in-flight set shrinks.
	space  chan struct{}
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
// error if ctx ends first.
func (a *acker) reserve(ctx context.Context, jtis []string) ([]string, error) {
	for {
		a.mu.Lock()
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
// its error returned.
func (a *acker) complete(acked, released []string) error {
	a.mu.Lock()
	for _, jti := range released {
		delete(a.inflight, jti)
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
	if errors.Is(err, errNotLeaseOwner) {
		// The lease manager refused the write: this node's tenure ran out
		// before a renewal confirmed it (#364). Nothing was written. While
		// the drain loop runs, the batch goes back to the front of the queue
		// and stays in flight, so it is written by the first drain after the
		// next successful heartbeat; a full in-flight set holds the sender
		// back meanwhile. With no drain loop (a zero window, or a closed
		// acker) the JTIs leave the set instead and stay pending in the
		// store, to be redelivered: a duplicate at most, never a loss.
		a.mu.Lock()
		if a.cfg.window > 0 && !a.closed {
			a.queue = append(batch, a.queue...)
			a.mu.Unlock()
			return err
		}
		for _, jti := range batch {
			delete(a.inflight, jti)
		}
		a.shrankLocked()
		a.mu.Unlock()
		if a.cfg.onApplied != nil {
			a.cfg.onApplied(batch, err)
		}
		return err
	}
	ackBatchSizeHist.WithLabelValues(a.cfg.transport).Observe(float64(len(batch)))
	if a.cfg.onApplied != nil {
		a.cfg.onApplied(batch, err)
	}
	a.mu.Lock()
	for _, jti := range batch {
		delete(a.inflight, jti)
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

// DeliveryQueue (#363, spec #112).
//
// One deliveryQueue per target stream owns the stream's held pending
// references (inbound JTI, acknowledgement JTI, enqueue time), the JWS this
// node served for each while it is in flight (for the outbound copy), and the
// acknowledgement write. It is the only caller of EventService.AckBatch and
// EventService.ResetPendingAckJti: every delivery mode hands its
// acknowledgements here and each batch is one Ack call.
//
// The queue holds no map from wire JTI to inbound JTI. A receiver's
// acknowledgement JTIs go to the store as received (deliveries.ackJti is what
// Ack matches), and the queue drops any held reference whose AckJti is in the
// batch. The coalescing acker above is the push and SSTP-client runners'
// in-flight bound; its apply lands here.

var (
	ackWritesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "ack_writes_total",
		Help:      "Acknowledgement writes (EventService.AckBatch calls) made by the delivery queues.",
	})
	ackBatchesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "ack_batches_total",
		Help:      "Acknowledgement batches handed to the delivery queues: one per push batch, poll request or SSTP frame that acknowledged anything.",
	})
	// readsBeforeAckTotal counts coordinator calls made on the acknowledgement
	// path before its AckBatch (#364). The design value is zero: the
	// leaseManager answers ownership from memory.
	readsBeforeAckTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "reads_before_ack_total",
		Help:      "Store or coordinator calls made on the acknowledgement path before its write (design value 0).",
	})
)

// queuedRef is one held reference (hook 2 of community #352).
type queuedRef struct {
	ref       interfaces.PendingRef // Jti, AckJti, EnqueuedAt
	handedOut time.Time             // first hand-out by this node; zero until then
	served    string                // the JWS served, kept while in flight
	// copyRec is the outbound copy stored with the acknowledgement when this
	// node signed and served the SET itself (nil for a forwarded SET).
	copyRec *model.EventRecord
	idx     int // position in the enqueue-time heap
}

// refHeap is a min-heap of held references by EnqueuedAt.
type refHeap []*queuedRef

func (h refHeap) Len() int { return len(h) }
func (h refHeap) Less(i, j int) bool {
	return h[i].ref.EnqueuedAt.Before(h[j].ref.EnqueuedAt)
}
func (h refHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx = i
	h[j].idx = j
}
func (h *refHeap) Push(x any) {
	qr := x.(*queuedRef)
	qr.idx = len(*h)
	*h = append(*h, qr)
}
func (h *refHeap) Pop() any {
	old := *h
	n := len(old)
	qr := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	qr.idx = -1
	return qr
}

// deliveryQueue is one target stream's delivery queue.
type deliveryQueue struct {
	r      *router
	sid    string // stream document id: deliveries.sid
	window int    // most references held

	mu     sync.Mutex
	refs   map[string]*queuedRef // held references by inbound JTI
	oldest refHeap
	depth  int64
	beyond time.Time
	// onRemove is the single removal point's observer (#352): it sees every
	// held reference that leaves on an acknowledgement, and whether it was a
	// receiver acknowledgement (false: a discard). Called under q.mu.
	onRemove func(qr queuedRef, receiverAck bool)
}

func newDeliveryQueue(r *router, sid string, window int) *deliveryQueue {
	if window < 1 {
		window = 1
	}
	return &deliveryQueue{r: r, sid: sid, window: window, refs: map[string]*queuedRef{}}
}

// queueWindow is the most references one queue holds: the most a wake-driven
// backfill reads in one pass.
func (r *router) queueWindow() int {
	n := r.backfillBatch * maxWakeBackfillBatches
	if n <= 0 {
		n = 100 * maxWakeBackfillBatches
	}
	return n
}

// queueFor returns sid's delivery queue, creating it on first use.
func (r *router) queueFor(sid string) *deliveryQueue {
	if q, ok := r.queues.Load(sid); ok {
		return q.(*deliveryQueue)
	}
	q, _ := r.queues.LoadOrStore(sid, newDeliveryQueue(r, sid, r.queueWindow()))
	return q.(*deliveryQueue)
}

// dropQueue forgets sid's queue (stream removed).
func (r *router) dropQueue(sid string) {
	r.queues.Delete(sid)
}

// holdLocked holds ref unless it is held already. count adds it to depth (a
// reference from ingest or a wake; a pending read sets depth from its total).
func (q *deliveryQueue) holdLocked(ref interfaces.PendingRef, count bool) {
	if ref.AckJti == "" {
		ref.AckJti = ref.Jti
	}
	if qr, ok := q.refs[ref.Jti]; ok {
		// A pending read is the store's word on the acknowledgement JTI (a
		// reset or a route-mode change may have rewritten it).
		if !count && qr.ref.AckJti != ref.AckJti {
			qr.ref.AckJti = ref.AckJti
			qr.served, qr.copyRec = "", nil
		}
		return
	}
	if count {
		q.depth++
	}
	if len(q.refs) >= q.window {
		if !ref.EnqueuedAt.IsZero() && (q.beyond.IsZero() || ref.EnqueuedAt.Before(q.beyond)) {
			q.beyond = ref.EnqueuedAt
		}
		return
	}
	qr := &queuedRef{ref: ref}
	q.refs[ref.Jti] = qr
	heap.Push(&q.oldest, qr)
}

// load seeds the queue from a pending read: depth and beyond are re-seeded
// from the store and every reference of the page is held (window allowing).
func (q *deliveryQueue) load(ctx context.Context, page interfaces.PendingPage) {
	q.mu.Lock()
	q.depth = page.Total
	q.beyond = page.OldestBeyond
	for _, ref := range page.Refs {
		q.holdLocked(ref, false)
	}
	q.mu.Unlock()
	q.ensureForward(ctx)
}

// accept holds references from ingest or a wake, with no store read.
func (q *deliveryQueue) accept(ctx context.Context, refs []interfaces.PendingRef) {
	if len(refs) == 0 {
		return
	}
	q.mu.Lock()
	for _, ref := range refs {
		q.holdLocked(ref, true)
	}
	q.mu.Unlock()
	q.ensureForward(ctx)
}

// acceptLocked is accept for a caller that holds r.mu (at least RLock), such
// as the fan-out wake: it reads the stream record without re-locking r.mu and
// runs the rare Forward rewrite (a store write) off the caller's lock.
func (q *deliveryQueue) acceptLocked(ctx context.Context, refs []interfaces.PendingRef) {
	if len(refs) == 0 {
		return
	}
	q.mu.Lock()
	for _, ref := range refs {
		q.holdLocked(ref, true)
	}
	q.mu.Unlock()
	stream := q.r.streamRecordLocked(q.sid)
	if stream == nil || stream.GetRouteMode() != model.RouteModeForward {
		return
	}
	for _, ref := range refs {
		if ref.AckJti != ref.Jti {
			go q.ensureForward(ctx)
			return
		}
	}
}

// reset drops every held reference (reset, stream clear, route-mode change);
// the next pending read re-seeds the queue.
func (q *deliveryQueue) reset() {
	q.mu.Lock()
	q.refs = map[string]*queuedRef{}
	q.oldest = nil
	q.depth = 0
	q.beyond = time.Time{}
	q.mu.Unlock()
}

// routeModeChanged drops the held references after a route-mode change; the
// next pending read re-seeds them with the store's acknowledgement JTIs. A
// change to Forward first rewrites every pending row of the stream to
// ackJti = jti (ResetPendingAckJti), so a Forward SET is acked by the inbound
// JTI it carries.
func (q *deliveryQueue) routeModeChanged(ctx context.Context) {
	q.reset()
	stream := q.stream()
	if stream == nil || stream.GetRouteMode() != model.RouteModeForward {
		return
	}
	if _, err := q.r.eventService.ResetPendingAckJti(ctx, q.sid); err != nil {
		eventLogger.Warn("QUEUE: Error resetting acknowledgement JTIs after a change to Forward", "sid", q.sid, "error", err)
	}
}

// stream returns the router's copy of the queue's stream record, or nil.
func (q *deliveryQueue) stream() *model.StreamStateRecord {
	return q.r.streamRecord(q.sid)
}

// ensureForward is the Forward half of a route-mode change: a Forward stream
// sends the inbound SET as received, so a held reference whose AckJti differs
// from its Jti was written under a re-signing mode. The queue rewrites every
// pending row of the stream once (ResetPendingAckJti) and its held references
// locally.
func (q *deliveryQueue) ensureForward(ctx context.Context) {
	stream := q.stream()
	if stream == nil || stream.GetRouteMode() != model.RouteModeForward {
		return
	}
	q.mu.Lock()
	stale := false
	for _, qr := range q.refs {
		if qr.ref.AckJti != qr.ref.Jti {
			stale = true
			break
		}
	}
	q.mu.Unlock()
	if !stale {
		return
	}
	if _, err := q.r.eventService.ResetPendingAckJti(ctx, q.sid); err != nil {
		eventLogger.Warn("QUEUE: Error resetting acknowledgement JTIs for a Forward stream", "sid", q.sid, "error", err)
		return
	}
	q.mu.Lock()
	for _, qr := range q.refs {
		if qr.ref.AckJti != qr.ref.Jti {
			qr.ref.AckJti = qr.ref.Jti
			qr.served, qr.copyRec = "", nil
		}
	}
	q.mu.Unlock()
}

// AckJtiOf returns the acknowledgement JTI a SET with inboundJti carries on
// this stream: the held reference's (the value written with the row). A
// reference the queue does not hold (beyond the window) takes the row
// writer's value for the stream's route mode.
func (q *deliveryQueue) AckJtiOf(inboundJti string, stream *model.StreamStateRecord) string {
	q.mu.Lock()
	qr, ok := q.refs[inboundJti]
	q.mu.Unlock()
	if ok {
		return qr.ref.AckJti
	}
	if stream == nil {
		if stream = q.stream(); stream == nil {
			return inboundJti
		}
	}
	return stream.AckJti(inboundJti)
}

// Served records the JWS this node signed for inboundJti and is about to hand
// out, and builds the outbound copy stored with its acknowledgement. A
// forwarded SET (AckJti == Jti) stores no copy.
func (q *deliveryQueue) Served(rec *model.EventRecord, signed *goSet.SecurityEventToken, jws string) {
	if rec == nil {
		return
	}
	q.mu.Lock()
	_, held := q.refs[rec.Jti]
	q.mu.Unlock()
	ackJti := ""
	if !held {
		// Resolved outside q.mu: the stream lookup takes the router lock.
		ackJti = q.AckJtiOf(rec.Jti, nil)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	qr, ok := q.refs[rec.Jti]
	if !ok {
		// A SET served from a buffer the queue did not seed (a wake or the
		// poll buffer) is held now under the stream's acknowledgement JTI
		// (what ingest wrote), so its acknowledgement drops it and stores
		// its copy.
		if ackJti == "" {
			ackJti = rec.Jti
		}
		q.holdLocked(interfaces.PendingRef{Jti: rec.Jti, AckJti: ackJti, EnqueuedAt: rec.SortTime}, false)
		if qr, ok = q.refs[rec.Jti]; !ok {
			return
		}
	}
	qr.served = jws
	if qr.ref.AckJti == qr.ref.Jti || signed == nil {
		qr.copyRec = nil
		return
	}
	qr.copyRec = &model.EventRecord{
		Jti:         qr.ref.AckJti,
		OriginalJti: qr.ref.Jti,
		Sid:         q.sid,
		Operational: false,
		Event:       *signed,
		Original:    jws,
		Types:       rec.Types,
		SortTime:    rec.SortTime,
	}
}

// MarkHandedOut stamps handedOut on each held reference that has none. Called
// when the push request is sent, when Claim returns references (poll and SSTP
// acceptor), and when the SSTP dialer sends its frame.
func (q *deliveryQueue) MarkHandedOut(ackJtis []string, at time.Time) {
	if len(ackJtis) == 0 {
		return
	}
	want := make(map[string]struct{}, len(ackJtis))
	for _, a := range ackJtis {
		want[a] = struct{}{}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, qr := range q.refs {
		if _, ok := want[qr.ref.AckJti]; ok && qr.handedOut.IsZero() {
			qr.handedOut = at
		}
	}
}

// Backlog reports the stream's whole backlog from memory (hook 3). oldest is
// the zero time when depth is 0.
func (q *deliveryQueue) Backlog() (depth int64, oldest time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.depth <= 0 {
		return 0, time.Time{}
	}
	oldest = q.beyond
	if len(q.oldest) > 0 {
		if h := q.oldest[0].ref.EnqueuedAt; !h.IsZero() && (oldest.IsZero() || h.Before(oldest)) {
			oldest = h
		}
	}
	return q.depth, oldest
}

// removeLocked is the single point a held reference leaves the queue on an
// acknowledgement. receiverAck is false for a discard.
func (q *deliveryQueue) removeLocked(qr *queuedRef, receiverAck bool) {
	delete(q.refs, qr.ref.Jti)
	if qr.idx >= 0 && qr.idx < len(q.oldest) && q.oldest[qr.idx] == qr {
		heap.Remove(&q.oldest, qr.idx)
	}
	if q.onRemove != nil {
		q.onRemove(*qr, receiverAck)
	}
}

// AckInbound acknowledges SETs by inbound JTI: the push and SSTP-client
// runners' accepted SETs (receiverAck) and subject-filter discards. Each held
// reference is acknowledged under its AckJti, with its outbound copy when
// this node served it and receiverAck is set. One Ack call.
func (q *deliveryQueue) AckInbound(ctx context.Context, inbound []string, receiverAck bool) (int64, error) {
	if len(inbound) == 0 {
		return 0, nil
	}
	var stream *model.StreamStateRecord
	ackJtis := make([]string, 0, len(inbound))
	var copies []*model.EventRecord
	q.mu.Lock()
	for _, jti := range inbound {
		qr, ok := q.refs[jti]
		if !ok {
			q.mu.Unlock()
			if stream == nil {
				stream = q.stream()
			}
			a := jti
			if stream != nil {
				a = stream.AckJti(jti)
			}
			q.mu.Lock()
			ackJtis = append(ackJtis, a)
			continue
		}
		ackJtis = append(ackJtis, qr.ref.AckJti)
		if receiverAck && qr.copyRec != nil {
			copies = append(copies, qr.copyRec)
		}
	}
	q.mu.Unlock()
	n, err := q.write(ctx, ackJtis, copies)
	if err != nil {
		return n, err
	}
	q.mu.Lock()
	for _, jti := range inbound {
		if qr, ok := q.refs[jti]; ok {
			q.removeLocked(qr, receiverAck)
		}
	}
	q.mu.Unlock()
	return n, nil
}

// AckWire acknowledges a receiver's acknowledgement JTIs (poll acks and
// setErrs, SSTP acceptor acks) as received, in one Ack call, and drops the
// held references whose AckJti is in the batch. setErrs store no copy. It
// returns the inbound JTIs of the dropped references, for the caller's
// buffer.
func (q *deliveryQueue) AckWire(ctx context.Context, acks []string, setErrs []string) ([]string, int64, error) {
	if len(acks) == 0 && len(setErrs) == 0 {
		return nil, 0, nil
	}
	isAck := make(map[string]bool, len(acks)+len(setErrs))
	for _, a := range setErrs {
		isAck[a] = false
	}
	for _, a := range acks {
		isAck[a] = true
	}
	all := make([]string, 0, len(isAck))
	for a := range isAck {
		all = append(all, a)
	}
	var copies []*model.EventRecord
	q.mu.Lock()
	for _, qr := range q.refs {
		if ok, in := isAck[qr.ref.AckJti]; in && ok && qr.copyRec != nil {
			copies = append(copies, qr.copyRec)
		}
	}
	q.mu.Unlock()
	n, err := q.write(ctx, all, copies)
	if err != nil {
		return nil, n, err
	}
	var inbound []string
	q.mu.Lock()
	for _, qr := range q.refs {
		if _, in := isAck[qr.ref.AckJti]; in {
			inbound = append(inbound, qr.ref.Jti)
			q.removeLocked(qr, true)
		}
	}
	q.mu.Unlock()
	return inbound, n, nil
}

// write is the queue's one acknowledgement write: the ownership check, the
// retention expiry (#360), then one AckBatch with the copies.
//
// Ownership is answered by the router's leaseManager from memory (#364): no
// store or coordinator call precedes the AckBatch, and the region up to it is
// tracked so one that did would be counted in
// goSignals_router_reads_before_ack_total. A node whose tenure has run out
// writes nothing and returns errNotLeaseOwner; the SETs stay pending.
func (q *deliveryQueue) write(ctx context.Context, ackJtis []string, copies []*model.EventRecord) (int64, error) {
	if len(ackJtis) == 0 {
		return 0, nil
	}
	ackBatchesTotal.Inc()
	q.r.locks.enterAck()
	if !q.r.stillOwnsAck(q.sid) {
		q.r.locks.exitAck()
		eventLogger.Debug("ROUTER: lease tenure ended, acknowledgement batch skipped", "sid", q.sid, "count", len(ackJtis))
		return 0, errNotLeaseOwner
	}
	ackDate := time.Now()
	var expireAt *time.Time
	if q.r.retentionWindow != nil {
		expireAt = ackExpireAt(q.r.retentionWindow, q.stream(), ackDate)
	}
	q.r.locks.exitAck()
	ackWritesTotal.Inc()
	n, err := q.r.eventService.AckBatch(ctx, interfaces.AckBatch{StreamID: q.sid, Jtis: ackJtis, AckDate: ackDate, ExpireAt: expireAt, Copies: copies})
	if err != nil {
		return n, err
	}
	q.mu.Lock()
	q.depth -= n
	if q.depth < 0 {
		q.depth = 0
	}
	if q.depth == 0 {
		q.beyond = time.Time{}
	}
	q.mu.Unlock()
	return n, nil
}
