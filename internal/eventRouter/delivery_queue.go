package eventRouter

import (
	"container/heap"
	"context"
	"sync"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

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
// batch. The coalescing acker (acker.go) is the push and SSTP-client runners'
// in-flight bound; its apply lands here.

// waitSample is one acknowledged SET's hand-out timing, kept until the
// acknowledging call has released q.mu and can resolve the stream's tfr.
type waitSample struct {
	enqueued, handedOut, acked time.Time
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
	// samples are the wait timings of references removed on a receiver
	// acknowledgement and not yet observed (#352).
	samples []waitSample

	// claims are the stream's poll and SSTP-acceptor claims (#337, #363).
	claims queueClaims
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
// this stream (AckJtisOf for one JTI), or "" when it has no row or its row
// could not be read.
func (q *deliveryQueue) AckJtiOf(inboundJti string) string {
	return q.AckJtisOf([]string{inboundJti})[0]
}

// AckJtisOf returns, in order, the acknowledgement JTI each inbound JTI
// carries on this stream (ackJtisOf). Nothing is derived (#363, S2): an
// entry with no row, or whose row could not be read (logged), is left "",
// and every sign site skips it, so that SET stays unacknowledged and is
// handed out on a later read under its stored JTI.
func (q *deliveryQueue) AckJtisOf(inbound []string) []string {
	out, err := q.ackJtisOf(q.ctx(), inbound)
	if err != nil {
		eventLogger.Warn("QUEUE: Error reading stored acknowledgement JTIs; leaving the SETs pending", "sid", q.sid, "count", len(inbound), "error", err)
	}
	return out
}

// ackJtisOf is the one place the queue resolves acknowledgement JTIs (#363,
// S2: rows keep the ackJti written at ingest; nothing is re-derived). A held
// reference answers from memory; the rest come from their stored rows (or
// undrained WAL entries, through the read-through) in one read. A JTI with
// neither is left empty: it is not acknowledged. On a read error the
// unresolved entries are left empty and the error returned.
func (q *deliveryQueue) ackJtisOf(ctx context.Context, inbound []string) ([]string, error) {
	out := make([]string, len(inbound))
	var missing []string
	q.mu.Lock()
	for i, jti := range inbound {
		if qr, ok := q.refs[jti]; ok {
			out[i] = qr.ref.AckJti
			continue
		}
		missing = append(missing, jti)
	}
	q.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}
	stored, err := q.r.eventService.StoredAckJtis(ctx, q.sid, missing)
	if err != nil {
		return out, err
	}
	for i, jti := range inbound {
		if out[i] == "" {
			out[i] = stored[jti]
		}
	}
	return out, nil
}

// ctx is the router's context, or Background for a bare test router.
func (q *deliveryQueue) ctx() context.Context {
	if q.r.ctx != nil {
		return q.r.ctx
	}
	return context.Background()
}

// RefOf returns the reference held for inboundJti, with its acknowledgement
// JTI and enqueue time; a reference the queue does not hold carries
// AckJtiOf's value ("" when its row could not be read) and no enqueue time.
func (q *deliveryQueue) RefOf(inboundJti string) interfaces.PendingRef {
	q.mu.Lock()
	qr, ok := q.refs[inboundJti]
	var ref interfaces.PendingRef
	if ok {
		ref = qr.ref
	}
	q.mu.Unlock()
	if ok {
		return ref
	}
	return interfaces.PendingRef{Jti: inboundJti, AckJti: q.AckJtiOf(inboundJti)}
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
		// The JTI the SET was signed with is its acknowledgement JTI; without
		// a signed token it is resolved outside q.mu (the stream lookup takes
		// the router lock).
		if signed != nil && signed.ID != "" {
			ackJti = signed.ID
		} else if ackJti = q.AckJtiOf(rec.Jti); ackJti == "" {
			return
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	qr, ok := q.refs[rec.Jti]
	if !ok {
		// A SET served from a buffer the queue did not seed (a wake or the
		// poll buffer) is held now under the stream's acknowledgement JTI
		// (what ingest wrote), so its acknowledgement drops it and stores
		// its copy. One dropped since the check above takes the JTI it was
		// signed with; with none it is not held (it stays pending).
		if ackJti == "" {
			if signed == nil || signed.ID == "" {
				return
			}
			ackJti = signed.ID
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

// Backlog reports the stream's whole backlog, its depth and oldest enqueue
// time, from memory with no store read: this is what the community #352
// backlog gauges read. oldest is the zero time when depth is 0.
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
	// Only a SET this node handed out is timed: a subject-filter discard was
	// never sent, and a SET handed out by a previous owner has no hand-out
	// time here (owner failover), so neither is observed (#352).
	if receiverAck && !qr.handedOut.IsZero() {
		q.samples = append(q.samples, waitSample{enqueued: qr.ref.EnqueuedAt, handedOut: qr.handedOut, acked: time.Now()})
	}
}

// observeWaits records the queue and acknowledgement time of the references
// removed since the last call. Called without q.mu: the stream lookup takes
// the router lock.
func (q *deliveryQueue) observeWaits() {
	q.mu.Lock()
	samples := q.samples
	q.samples = nil
	q.mu.Unlock()
	if len(samples) == 0 {
		return
	}
	stream := q.stream()
	if stream == nil {
		return
	}
	tfr := tfrOf(stream)
	qt := queueTimeHist.WithLabelValues(tfr)
	at := ackTimeHist.WithLabelValues(tfr)
	for _, s := range samples {
		if !s.enqueued.IsZero() {
			qt.Observe(max(0, s.handedOut.Sub(s.enqueued).Seconds()))
		}
		at.Observe(max(0, s.acked.Sub(s.handedOut).Seconds()))
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
	ackJtis := make([]string, 0, len(inbound))
	var copies []*model.EventRecord
	var unheld []string
	q.mu.Lock()
	for _, jti := range inbound {
		qr, ok := q.refs[jti]
		if !ok {
			unheld = append(unheld, jti)
			continue
		}
		ackJtis = append(ackJtis, qr.ref.AckJti)
		if receiverAck && qr.copyRec != nil {
			copies = append(copies, qr.copyRec)
		}
	}
	q.mu.Unlock()
	if len(unheld) > 0 {
		// Beyond the window: the stored rows' ackJti, in one read. A failed
		// read leaves the references pending; they are delivered again.
		stored, err := q.ackJtisOf(ctx, unheld)
		if err != nil {
			return 0, err
		}
		for _, a := range stored {
			// A JTI with no row has nothing to acknowledge (#363, S2).
			if a != "" {
				ackJtis = append(ackJtis, a)
			}
		}
	}
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
	q.observeWaits()
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
	q.observeWaits()
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
	q.r.locks.enterAck()
	if !q.r.stillOwnsAck(q.sid) {
		q.r.locks.exitAck()
		eventLogger.Debug("ROUTER: lease tenure ended, acknowledgement batch skipped", "sid", q.sid, "count", len(ackJtis))
		return 0, errNotLeaseOwner
	}
	// Counted once ownership is confirmed: a skipped batch is retried, and
	// counting both attempts would report one batch as two.
	ackBatchesTotal.Inc()
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
