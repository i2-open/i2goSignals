package eventRouter

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/groupcommit"
	"github.com/i2-open/i2goSignals/internal/wal"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
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
// and the outbound streams they were planned onto.
type walEntry struct {
	Sid     string               `bson:"sid"`
	Records []*model.EventRecord `bson:"records"`
	Targets []walTarget          `bson:"targets,omitempty"`
}

// localWal is the router's local-durability state. buffered holds the JTIs
// appended to the log and not yet drained, so a repeat delivery of a buffered
// SET is swallowed as a duplicate the way the store would swallow it.
type localWal struct {
	log      wal.Log
	mu       sync.Mutex
	buffered map[string]struct{}
	wake     chan struct{}
	done     chan struct{}
	maxBatch int
	closer   sync.Once
}

func (r *router) startLocalWal(log wal.Log) {
	lw := &localWal{
		log:      log,
		buffered: map[string]struct{}{},
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		maxBatch: groupcommit.ConfigFromEnv().Max,
	}
	if lw.maxBatch <= 0 {
		lw.maxBatch = groupcommit.DefaultMax
	}
	// Rebuild the buffered-JTI set from whatever is still in the log (acked
	// before a restart and not yet drained).
	var from uint64
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
			}
			from = e.Seq + 1
		}
	}
	r.wal = lw
	eventLogger.Info("ROUTER: local-durability ingest enabled (I2SIG_STORE_WAL=local)", "buffered", log.Depth())
	go r.runWalDrain()
	lw.signal()
}

func (lw *localWal) signal() {
	select {
	case lw.wake <- struct{}{}:
	default:
	}
}

// stopLocalWal stops the drain worker and closes the log. Anything not yet
// drained stays in the log for the next start.
func (r *router) stopLocalWal() {
	lw := r.wal
	if lw == nil {
		return
	}
	r.cancel()
	<-lw.done
	lw.closer.Do(func() {
		if err := lw.log.Close(); err != nil {
			eventLogger.Warn("ROUTER: local WAL close failed", "error", err)
		}
	})
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
func (r *router) handleEventsLocal(candidates []*model.EventRecord, sid string, importOnly bool, excludeSstpTxSid string, results []error) []error {
	lw := r.wal

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
	entry := &walEntry{Sid: sid, Records: fresh, Targets: make([]walTarget, 0, len(targets))}
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
	lw.signal()
	return results
}

func (r *router) runWalDrain() {
	lw := r.wal
	defer close(lw.done)
	backoff := walDrainBackoffMin
	for {
		more, err := r.drainWalOnce()
		if r.ctx.Err() != nil {
			return
		}
		if err != nil {
			eventLogger.Warn("ROUTER: local WAL drain failed; retrying", "error", err, "backoff", backoff, "depth", lw.log.Depth())
			if !SleepCtx(r.ctx, backoff) {
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
		case <-r.ctx.Done():
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
func (r *router) drainWalOnce() (more bool, err error) {
	lw := r.wal
	raw, err := lw.log.ReadFrom(0, walReadEntries)
	if err != nil {
		return false, err
	}
	if len(raw) == 0 {
		return false, nil
	}

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
	recs, errs := r.eventService.AddEventsWithPending(r.ctx, candidates, sid, pending)

	// Meter and wake per entry, exactly as the majority path does per batch.
	streams := map[string]*model.StreamStateRecord{}
	truncateTo := uint64(0)
	blocked := false
	var doneJtis []string
	for _, d := range batch {
		n := len(d.entry.Records)
		eRecs, eErrs := recs[d.start:d.start+n], errs[d.start:d.start+n]
		stored := true
		for i := range eErrs {
			if eErrs[i] != nil && !errors.Is(eErrs[i], interfaces.ErrDuplicateJTI) {
				stored = false
			}
		}
		r.commitWalEntry(d.entry, eRecs, eErrs, streams)
		if !stored {
			blocked = true
		}
		if !blocked {
			truncateTo = d.seq
			for _, rec := range d.entry.Records {
				doneJtis = append(doneJtis, rec.Jti)
			}
		}
	}
	if !blocked {
		// Undecodable entries after the last drained one are covered too.
		truncateTo = lastSeq
	}
	if truncateTo > 0 {
		if terr := lw.log.Truncate(truncateTo); terr != nil {
			return false, terr
		}
		lw.mu.Lock()
		for _, jti := range doneJtis {
			delete(lw.buffered, jti)
		}
		lw.mu.Unlock()
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
func (r *router) commitWalEntry(e *walEntry, recs []*model.EventRecord, errs []error, streams map[string]*model.StreamStateRecord) {
	stream, seen := streams[e.Sid]
	if !seen {
		s, _, err := r.resolveIngressStream(r.ctx, e.Sid)
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
	targets := make([]*fanoutTarget, len(e.Targets))
	for i, t := range e.Targets {
		targets[i] = &fanoutTarget{mode: t.Mode, key: t.Key, docID: t.DocID, sid: t.Sid, jtis: t.Jtis}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.commitFanoutLocked(targets, accepted)
}
