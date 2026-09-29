package eventRouter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/groupcommit"
	"github.com/i2-open/i2goSignals/internal/wal"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Local-durability ingest (I2SIG_STORE_WAL=local, ADR 0045).
//
// When the router is given a WAL, an inbound batch is acknowledged once its
// candidate records and planned fan-out are fsynced to the node-local log. A
// drain worker then writes them to the shared store with the same one-trip
// AddEventsWithPending call the majority path uses (ADR 0043), meters the
// accepted SETs and wakes their targets, and only then truncates the log.
// Without a WAL (the default) none of this runs.
//
// Lifecycle (#341). On start, entries left in the log by a previous run are
// replayed to the store before ingest accepts anything: until they are drained
// an inbound SET gets ErrStoreUnavailable (503 + Retry-After, #333). On
// graceful stop, Shutdown closes ingest, drains the log to the store (bounded
// by I2SIG_STORE_WAL_DRAIN_TIMEOUT) and only then stops the delivery runners,
// which release their stream leases as they exit (#334). The next lease holder
// therefore sees everything this node acked (ADR 0038). On timeout the residue
// stays on disk for this node's next start.

const (
	walDrainBackoffMin = 50 * time.Millisecond
	walDrainBackoffMax = 5 * time.Second
	// walReadEntries bounds how many log entries one drain pass reads.
	walReadEntries = 256
)

// walTarget is the durable form of a fanoutTarget.
type walTarget struct {
	Mode  string   `bson:"mode"`
	Key   string   `bson:"key"`
	DocID string   `bson:"docId"`
	Sid   string   `bson:"sid"`
	Jtis  []string `bson:"jtis"`
}

// walEntry is one acknowledged inbound batch: the candidate records to store
// and the outbound streams they were planned onto. At is the append time (unix
// nanoseconds) the drain-lag gauge is measured from; zero in entries written
// before it existed.
type walEntry struct {
	Sid     string               `bson:"sid"`
	Records []*model.EventRecord `bson:"records"`
	Targets []walTarget          `bson:"targets,omitempty"`
	At      int64                `bson:"at,omitempty"`
}

var (
	// errWalIngestClosed refuses a SET that arrives after graceful stop began.
	errWalIngestClosed = errors.New("local WAL: ingest closed for shutdown")
	// errWalReplaying refuses a SET while a previous run's WAL is replayed.
	errWalReplaying = errors.New("local WAL: replaying entries from a previous run")
)

// walMetrics are the local-WAL Prometheus collectors (US 24).
type walMetrics struct {
	depth         prometheus.Gauge
	drainLag      prometheus.Gauge
	drained       prometheus.Counter
	replayed      prometheus.Counter
	drainDuration prometheus.Histogram
	ringFedServed prometheus.Counter
}

func newWalMetrics() *walMetrics {
	return &walMetrics{
		depth: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "goSignals", Subsystem: "wal", Name: "depth",
			Help: "Entries (acknowledged inbound batches) in the local WAL not yet drained to the store.",
		}),
		drainLag: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "goSignals", Subsystem: "wal", Name: "drain_lag_seconds",
			Help: "Age of the oldest undrained local WAL entry, refreshed on every drain attempt; 0 when the WAL is empty.",
		}),
		drained: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "goSignals", Subsystem: "wal", Name: "drained_total",
			Help: "SETs drained from the local WAL to the store (a JTI already stored counts as drained).",
		}),
		replayed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "goSignals", Subsystem: "wal", Name: "replayed_total",
			Help: "SETs found in the local WAL at start-up and replayed to the store before ingest resumed.",
		}),
		drainDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "goSignals", Subsystem: "wal", Name: "drain_duration_seconds",
			Help:    "Duration of one local WAL drain batch: the store write plus the log truncate.",
			Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}),
		ringFedServed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "goSignals", Subsystem: "wal", Name: "ring_fed_served_total",
			Help: "SET bodies served to delivery from the local WAL before the drain stored them (I2SIG_STORE_WAL_RING_FED).",
		}),
	}
}

func (m *walMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.depth, m.drainLag, m.drained, m.replayed, m.drainDuration, m.ringFedServed}
}

// walMetricsDefault is the process's local-WAL metric set; a router picks it
// up when its WAL starts. Tests swap it for a private one.
var walMetricsDefault = newWalMetrics()

// walNow and walSleep are the clock and backoff wait a WAL takes when it
// starts; tests swap them before building a router.
var (
	walNow   = time.Now
	walSleep = SleepCtx
)

// WALCollectors returns the local-WAL Prometheus collectors for the server's
// registry. They stay at zero in the default majority mode.
func WALCollectors() []prometheus.Collector { return walMetricsDefault.collectors() }

// localWal is the router's local-durability state. buffered holds the JTIs
// appended to the log and not yet drained, so a repeat delivery of a buffered
// SET is swallowed as a duplicate the way the store would swallow it.
type localWal struct {
	log      wal.Log
	mu       sync.Mutex
	buffered map[string]struct{}
	// ingest orders appends against graceful stop: handleEventsLocal holds it
	// shared across its check and append, and closeIngest takes it exclusively,
	// so no append lands after the final drain began.
	ingest sync.RWMutex
	closed bool // guarded by ingest
	// replaying is true until every entry up to replayThrough (the last entry
	// found in the log at start) is drained; ingest is refused meanwhile.
	replaying     atomic.Bool
	replayThrough uint64
	wake          chan struct{}
	stop          chan struct{} // closed to stop the drain worker between passes
	done          chan struct{} // closed when the drain worker has exited
	// ctx scopes store calls made by the drain; cancelled only once the
	// graceful-stop drain is over (or has run out of time).
	ctx          context.Context
	cancel       context.CancelFunc
	maxBatch     int
	drainTimeout time.Duration
	// now and sleep drive the graceful-stop drain deadline and retry backoff;
	// time.Now and SleepCtx in production, injected by tests.
	now      func() time.Time
	sleep    func(context.Context, time.Duration) bool
	metrics  *walMetrics
	shutdown sync.Once
}

func (r *router) startLocalWal(log wal.Log) {
	ctx, cancel := context.WithCancel(context.Background())
	lw := &localWal{
		log:      log,
		buffered: map[string]struct{}{},
		wake:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
		maxBatch: groupcommit.ConfigFromEnv().Max,
		now:      walNow,
		sleep:    walSleep,
		metrics:  walMetricsDefault,
	}
	if lw.maxBatch <= 0 {
		lw.maxBatch = groupcommit.DefaultMax
	}
	timeout, err := wal.DrainTimeoutFromEnv()
	if err != nil {
		eventLogger.Warn("ROUTER: invalid local WAL drain timeout; using the default", "error", err, "default", timeout)
	}
	lw.drainTimeout = timeout
	// Rebuild the buffered-JTI set from whatever is still in the log (acked
	// before a restart and not yet drained).
	var from uint64
	var replay []*walEntry
	for {
		entries, err := log.ReadFrom(from, walReadEntries)
		if err != nil {
			eventLogger.Error("ROUTER: local WAL read failed at startup", "error", err)
			break
		}
		if len(entries) == 0 {
			break
		}
		for _, e := range entries {
			if we, err := decodeWalEntry(e.Data); err == nil {
				for _, rec := range we.Records {
					lw.buffered[rec.Jti] = struct{}{}
				}
				if r.walRT != nil {
					replay = append(replay, we)
				}
			}
			lw.replayThrough = e.Seq
			from = e.Seq + 1
		}
	}
	if lw.replayThrough > 0 {
		// A previous run acked these and stopped before draining them (a crash,
		// or a graceful-stop drain that ran out of time). Replay them before
		// ingest resumes (US 23).
		lw.replaying.Store(true)
		eventLogger.Warn("ROUTER: local WAL holds entries from a previous run; replaying before accepting ingest", "depth", log.Depth())
	}
	r.wal = lw
	r.refreshWalGauges(lw)
	eventLogger.Info("ROUTER: local-durability ingest enabled (I2SIG_STORE_WAL=local)", "buffered", log.Depth(), "drainTimeout", lw.drainTimeout)
	if r.walRT != nil {
		// Ring-fed (#342): the runners read undrained entries from memory, so
		// a replayed entry is deliverable now, not once the replay stores it.
		for _, we := range replay {
			r.ringFeed(we)
		}
		eventLogger.Info("ROUTER: ring-fed delivery enabled; runners read the local WAL before the drain", "env", wal.EnvRingFed, "replayed", len(replay))
	}
	go r.runWalDrain()
	lw.signal()
}

func (lw *localWal) signal() {
	select {
	case lw.wake <- struct{}{}:
	default:
	}
}

// shutdownLocalWal is the graceful-stop half of the lifecycle (US 22). It
// closes ingest, stops the drain worker between passes, drains what is left
// to the store within the drain timeout, and closes the log. Shutdown calls
// it before stopping the delivery runners, so every stream lease is still
// held while entries remain and is released only after the drain. On timeout
// the residue stays in the log for the next start. Idempotent.
func (r *router) shutdownLocalWal() {
	lw := r.wal
	if lw == nil {
		return
	}
	lw.shutdown.Do(func() {
		lw.ingest.Lock()
		lw.closed = true
		lw.ingest.Unlock()

		deadline := lw.now().Add(lw.drainTimeout)
		// A real-time bound as well, so a store call that hangs cannot hold
		// shutdown past the timeout whatever clock drives the deadline.
		ctx, cancel := context.WithTimeout(lw.ctx, lw.drainTimeout)
		defer cancel()

		close(lw.stop)
		select {
		case <-lw.done:
		case <-ctx.Done():
			lw.cancel()
			<-lw.done
		}
		r.finalWalDrain(ctx, lw, deadline)
		lw.cancel()
		if err := lw.log.Close(); err != nil && !errors.Is(err, wal.ErrClosed) {
			eventLogger.Warn("ROUTER: local WAL close failed", "error", err)
		}
	})
}

// finalWalDrain drains the log synchronously until it is empty or the
// deadline passes, retrying store failures with the drain backoff.
func (r *router) finalWalDrain(ctx context.Context, lw *localWal, deadline time.Time) {
	backoff := walDrainBackoffMin
	for {
		depth := lw.log.Depth()
		if depth == 0 {
			eventLogger.Info("ROUTER: local WAL drained to the store; releasing stream leases")
			return
		}
		if ctx.Err() != nil || !lw.now().Before(deadline) {
			eventLogger.Error("ROUTER: local WAL drain timed out at shutdown; undrained SETs stay on disk and are replayed on the next start",
				"depth", depth, "timeout", lw.drainTimeout, "env", wal.EnvDrainTimeout)
			return
		}
		_, err := r.drainWalOnce(ctx)
		if errors.Is(err, wal.ErrClosed) {
			eventLogger.Error("ROUTER: local WAL closed before the shutdown drain finished", "depth", depth)
			return
		}
		if err != nil {
			eventLogger.Warn("ROUTER: local WAL shutdown drain failed; retrying", "error", err, "backoff", backoff, "depth", depth)
			lw.sleep(ctx, backoff)
			backoff = min(2*backoff, walDrainBackoffMax)
			continue
		}
		backoff = walDrainBackoffMin
	}
}

// waitOrStop sleeps d unless the drain worker is told to stop first.
func (lw *localWal) waitOrStop(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-lw.stop:
		return false
	}
}

// refreshWalGauges sets the depth and drain-lag gauges from the log.
func (r *router) refreshWalGauges(lw *localWal) {
	depth := lw.log.Depth()
	lw.metrics.depth.Set(float64(depth))
	if depth == 0 {
		lw.metrics.drainLag.Set(0)
		return
	}
	oldest, err := lw.log.ReadFrom(0, 1)
	if err != nil || len(oldest) == 0 {
		return
	}
	if we, err := decodeWalEntry(oldest[0].Data); err == nil && we.At > 0 {
		lw.metrics.drainLag.Set(max(0, lw.now().Sub(time.Unix(0, we.At)).Seconds()))
	}
}

func encodeWalEntry(e *walEntry) ([]byte, error) { return bson.Marshal(e) }

func decodeWalEntry(b []byte) (*walEntry, error) {
	var e walEntry
	if err := bson.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// handleEventsLocal is the local-durability ingest path. results is
// index-aligned with candidates; a nil entry may be acked.
// ingestsLocally reports whether a SET arriving on the ingress stream takes
// the local-WAL path (issue #343): only when this deployment runs
// I2SIG_STORE_WAL=local (r.wal non-nil) AND the stream's durability is local.
// For an SSTP pair the pair record carries the knob. A stream asking for local
// on a majority deployment runs at majority and is WARNed about once.
func (r *router) ingestsLocally(streamState, sstpPair *model.StreamStateRecord) bool {
	rec := streamState
	if sstpPair != nil {
		rec = sstpPair
	}
	if rec == nil || !rec.Durability.IsLocal() {
		return false
	}
	if r.wal != nil {
		return true
	}
	if _, warned := r.durabilityWarned.LoadOrStore(rec.StreamConfiguration.Id, struct{}{}); !warned {
		eventLogger.Warn("ROUTER: stream durability=local ignored: this deployment is not in local mode (I2SIG_STORE_WAL); running at majority",
			"sid", rec.StreamConfiguration.Id)
	}
	return false
}

func (r *router) handleEventsLocal(candidates []*model.EventRecord, sid string, importOnly bool, excludeSstpTxSid string, results []error) []error {
	lw := r.wal

	// Nothing is acked once graceful stop has begun, or while a previous run's
	// WAL is still being replayed: the transmitter gets 503 + Retry-After and
	// resends (#333).
	lw.ingest.RLock()
	defer lw.ingest.RUnlock()
	var refuse error
	switch {
	case lw.closed:
		refuse = errWalIngestClosed
	case lw.replaying.Load():
		refuse = errWalReplaying
	}
	if refuse != nil {
		for i := range results {
			results[i] = fmt.Errorf("%w: %w", ErrStoreUnavailable, refuse)
		}
		return results
	}

	// Reserve the JTIs this call will append. A JTI already buffered (or
	// repeated within the batch) is a duplicate: acked, not appended again.
	lw.mu.Lock()
	fresh := make([]*model.EventRecord, 0, len(candidates))
	for _, rec := range candidates {
		if _, dup := lw.buffered[rec.Jti]; dup {
			continue
		}
		lw.buffered[rec.Jti] = struct{}{}
		fresh = append(fresh, rec)
	}
	lw.mu.Unlock()
	if len(fresh) == 0 {
		return results
	}

	var targets []*fanoutTarget
	if !importOnly {
		r.mu.RLock()
		targets = r.planFanoutLocked(fresh, excludeSstpTxSid)
		r.mu.RUnlock()
	}
	entry := &walEntry{Sid: sid, Records: fresh, Targets: make([]walTarget, 0, len(targets)), At: lw.now().UnixNano()}
	for _, t := range targets {
		entry.Targets = append(entry.Targets, walTarget{Mode: t.mode, Key: t.key, DocID: t.docID, Sid: t.sid, Jtis: t.jtis})
	}

	data, err := encodeWalEntry(entry)
	if err == nil {
		_, err = lw.log.Append([][]byte{data})
	}
	if err != nil {
		lw.mu.Lock()
		for _, rec := range fresh {
			delete(lw.buffered, rec.Jti)
		}
		lw.mu.Unlock()
		eventLogger.Error("ROUTER: local WAL append failed; SETs not acknowledged", "sid", sid, "count", len(fresh), "error", err)
		for i := range results {
			results[i] = fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
		}
		return results
	}
	lw.metrics.depth.Set(float64(lw.log.Depth()))
	if r.walRT != nil {
		r.ringFeed(entry)
	}
	lw.signal()
	return results
}

// ringFeed makes a WAL entry readable through the ring-fed overlay and wakes
// its targets (#342). The wake happens here, once, and never again at drain:
// a buffer re-woken with a JTI its runner already delivered and acked would
// deliver it a second time.
func (r *router) ringFeed(e *walEntry) {
	r.walRT.overlay.add(e)
	if len(e.Targets) == 0 {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, t := range e.Targets {
		r.wakeTargetLocked(&fanoutTarget{mode: t.Mode, key: t.Key, docID: t.DocID, sid: t.Sid, jtis: t.Jtis}, t.Jtis)
	}
}

// runWalDrain is the background drain worker. It stops between passes when
// lw.stop closes, so graceful stop never abandons a store write mid-flight.
func (r *router) runWalDrain() {
	lw := r.wal
	defer close(lw.done)
	backoff := walDrainBackoffMin
	for {
		select {
		case <-lw.stop:
			return
		default:
		}
		more, err := r.drainWalOnce(lw.ctx)
		if lw.ctx.Err() != nil {
			return
		}
		if err != nil {
			eventLogger.Warn("ROUTER: local WAL drain failed; retrying", "error", err, "backoff", backoff, "depth", lw.log.Depth())
			if !lw.waitOrStop(backoff) {
				return
			}
			backoff = min(2*backoff, walDrainBackoffMax)
			continue
		}
		backoff = walDrainBackoffMin
		if more {
			continue
		}
		select {
		case <-lw.stop:
			return
		case <-lw.wake:
		}
	}
}

// errWalRecordsUnstored reports that some drained records were not stored
// and remain in the log for the next attempt.
var errWalRecordsUnstored = errors.New("local WAL: records not yet stored")

// drainWalOnce moves the oldest log entries (up to maxBatch records) to the
// store in one AddEventsWithPending call. It truncates the log only through
// entries whose every record was stored (or already existed). more reports
// that a full pass succeeded and entries may remain.
func (r *router) drainWalOnce(ctx context.Context) (more bool, err error) {
	lw := r.wal
	raw, err := lw.log.ReadFrom(0, walReadEntries)
	if err != nil {
		return false, err
	}
	if len(raw) == 0 {
		r.endReplayIfDrained(lw)
		return false, nil
	}
	started := lw.now()
	defer func() {
		lw.metrics.drainDuration.Observe(lw.now().Sub(started).Seconds())
		r.refreshWalGauges(lw)
	}()

	type drained struct {
		seq   uint64
		entry *walEntry
		start int // offset of the entry's records in candidates
	}
	var batch []drained
	var candidates []*model.EventRecord
	var lastSeq uint64
	for _, e := range raw {
		we, derr := decodeWalEntry(e.Data)
		if derr != nil {
			// The checksum passed, so this is not a torn write; it can never be
			// decoded, and holding it would stop the drain for good.
			eventLogger.Error("ROUTER: undecodable local WAL entry dropped", "seq", e.Seq, "error", derr)
			lastSeq = e.Seq
			continue
		}
		if len(batch) > 0 && len(candidates)+len(we.Records) > lw.maxBatch {
			break
		}
		batch = append(batch, drained{seq: e.Seq, entry: we, start: len(candidates)})
		candidates = append(candidates, we.Records...)
		lastSeq = e.Seq
	}

	pending := map[string][]string{}
	for _, d := range batch {
		for _, t := range d.entry.Targets {
			pending[t.DocID] = append(pending[t.DocID], t.Jtis...)
		}
	}

	sid := ""
	if len(batch) > 0 {
		sid = batch[0].entry.Sid
	}
	recs, errs := r.eventService.AddEventsWithPending(ctx, candidates, sid, pending)

	// Meter and wake per entry, exactly as the majority path does per batch.
	streams := map[string]*model.StreamStateRecord{}
	truncateTo := uint64(0)
	blocked := false
	var doneJtis []string
	var doneEntries []*walEntry
	var drainedN, replayedN int
	for _, d := range batch {
		n := len(d.entry.Records)
		eRecs, eErrs := recs[d.start:d.start+n], errs[d.start:d.start+n]
		stored := true
		for i := range eErrs {
			if eErrs[i] != nil && !errors.Is(eErrs[i], interfaces.ErrDuplicateJTI) {
				stored = false
			}
		}
		r.commitWalEntry(ctx, d.entry, eRecs, eErrs, streams)
		if !stored {
			blocked = true
		}
		if !blocked {
			truncateTo = d.seq
			doneEntries = append(doneEntries, d.entry)
			for _, rec := range d.entry.Records {
				doneJtis = append(doneJtis, rec.Jti)
			}
			drainedN += n
			if d.seq <= lw.replayThrough {
				replayedN += n
			}
		}
	}
	if !blocked {
		// Undecodable entries after the last drained one are covered too.
		truncateTo = lastSeq
	}
	if truncateTo > 0 {
		if r.walRT != nil {
			// Acks and clears taken from the overlay reach the store before
			// the log lets go of the entry; on failure the entry is retried.
			if herr := r.walRT.applyHeld(ctx, doneEntries); herr != nil {
				return false, fmt.Errorf("local WAL: applying held acks: %w", herr)
			}
		}
		if terr := lw.log.Truncate(truncateTo); terr != nil {
			return false, terr
		}
		if r.walRT != nil {
			for _, e := range doneEntries {
				r.walRT.overlay.remove(e)
			}
		}
		lw.mu.Lock()
		for _, jti := range doneJtis {
			delete(lw.buffered, jti)
		}
		lw.mu.Unlock()
		lw.metrics.drained.Add(float64(drainedN))
		if replayedN > 0 {
			lw.metrics.replayed.Add(float64(replayedN))
		}
		if truncateTo >= lw.replayThrough {
			r.endReplayIfDrained(lw)
		}
	}
	if blocked {
		return false, errWalRecordsUnstored
	}
	return true, nil
}

// commitWalEntry meters the entry's newly stored SETs as ingress and egress
// and wakes their targets. A record that came back as a duplicate or a store
// failure is skipped; a failed one is retried by the next pass, where a record
// already stored this pass comes back as a duplicate and is not re-metered.
func (r *router) commitWalEntry(ctx context.Context, e *walEntry, recs []*model.EventRecord, errs []error, streams map[string]*model.StreamStateRecord) {
	stream, seen := streams[e.Sid]
	if !seen {
		s, _, err := r.resolveIngressStream(ctx, e.Sid)
		if err != nil {
			eventLogger.Warn("ROUTER: ingress stream not found draining local WAL; ingress not metered", "sid", e.Sid, "error", err)
			s = nil
		}
		streams[e.Sid] = s
		stream = s
	}
	accepted := make(map[string]*model.EventRecord, len(recs))
	for i, rec := range recs {
		if errs[i] != nil || rec == nil {
			continue
		}
		if stream != nil {
			ev := rec.Event
			r.IncrementCounter(stream, &ev, true)
			r.observeMeteredEvent(stream.StreamConfiguration.Id, DirectionIngress, &ev)
		}
		accepted[rec.Jti] = rec
	}
	if len(accepted) == 0 || len(e.Targets) == 0 {
		return
	}
	if r.walRT != nil {
		// Ring-fed: the targets were woken at append (ringFeed); only meter.
		for _, t := range e.Targets {
			for _, jti := range t.Jtis {
				if rec, ok := accepted[jti]; ok {
					r.observeMeteredEvent(t.Sid, DirectionEgress, &rec.Event)
				}
			}
		}
		return
	}
	targets := make([]*fanoutTarget, len(e.Targets))
	for i, t := range e.Targets {
		targets[i] = &fanoutTarget{mode: t.Mode, key: t.Key, docID: t.DocID, sid: t.Sid, jtis: t.Jtis}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.commitFanoutLocked(targets, accepted)
}

// endReplayIfDrained lifts the start-up ingest gate once every entry found in
// the log at start has been drained.
func (r *router) endReplayIfDrained(lw *localWal) {
	if lw.replaying.CompareAndSwap(true, false) {
		eventLogger.Info("ROUTER: local WAL replay complete; accepting ingest")
	}
}
