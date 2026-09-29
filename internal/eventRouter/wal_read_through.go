package eventRouter

import (
	"context"
	"sort"
	"sync"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Ring-fed delivery (I2SIG_STORE_WAL_RING_FED, #342).
//
// In local mode (ADR 0045) a SET is acked once it is fsynced to the WAL, and
// the drain lands it in the store afterwards. Without ring-feeding the
// delivery runners only see it after that drain, so the drain lag is added
// to every delivery. With ring-feeding the router puts walReadThrough in
// front of the EventService's DAO: until an entry is drained, its records and
// pending markers are served from memory, merged with the store's, and the
// runners are woken when the entry is appended rather than when it is drained.
//
// Acks for a SET that is still only in the WAL are held here and applied to
// the store by the drain right after it writes the SET (drainWalOnce), before
// the entry is truncated. A pending clear is held the same way. Runner reads
// filter held acks out, so a SET acked from the overlay is never offered
// again, whether the store already has its marker or not.

// overlayMark is one undrained SET queued on one stream.
type overlayMark struct {
	acked   bool
	ackDate time.Time
	removed bool // cleared by ClearPendingForStream before the drain
}

func (m *overlayMark) live() bool { return !m.acked && !m.removed }

// walOverlay is the in-memory view of the undrained WAL entries.
type walOverlay struct {
	mu      sync.RWMutex
	records map[string]*model.EventRecord      // jti -> record
	pending map[string]map[string]*overlayMark // stream doc id -> jti -> mark
}

func newWalOverlay() *walOverlay {
	return &walOverlay{
		records: map[string]*model.EventRecord{},
		pending: map[string]map[string]*overlayMark{},
	}
}

// add makes an appended (or replayed) entry visible to delivery.
func (o *walOverlay) add(e *walEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, rec := range e.Records {
		o.records[rec.Jti] = rec
	}
	for _, t := range e.Targets {
		marks := o.pending[t.DocID]
		if marks == nil {
			marks = map[string]*overlayMark{}
			o.pending[t.DocID] = marks
		}
		for _, jti := range t.Jtis {
			if _, ok := marks[jti]; !ok {
				marks[jti] = &overlayMark{}
			}
		}
	}
}

// remove drops a drained entry: from here on the store serves it.
func (o *walOverlay) remove(e *walEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, rec := range e.Records {
		delete(o.records, rec.Jti)
	}
	for _, t := range e.Targets {
		marks := o.pending[t.DocID]
		for _, jti := range t.Jtis {
			delete(marks, jti)
		}
		if len(marks) == 0 {
			delete(o.pending, t.DocID)
		}
	}
}

// heldOps are the acks and clears taken against an entry's SETs before it
// was drained, which the drain applies to the store after writing them.
type heldOps struct {
	acks    map[string]map[time.Time][]string // stream -> ackDate -> jtis
	removes map[string][]string               // stream -> jtis
}

// held collects the held acks and clears for entries.
func (o *walOverlay) held(entries []*walEntry) heldOps {
	ops := heldOps{acks: map[string]map[time.Time][]string{}, removes: map[string][]string{}}
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, e := range entries {
		for _, t := range e.Targets {
			marks := o.pending[t.DocID]
			for _, jti := range t.Jtis {
				m := marks[jti]
				switch {
				case m == nil:
				case m.acked:
					byDate := ops.acks[t.DocID]
					if byDate == nil {
						byDate = map[time.Time][]string{}
						ops.acks[t.DocID] = byDate
					}
					byDate[m.ackDate] = append(byDate[m.ackDate], jti)
				case m.removed:
					ops.removes[t.DocID] = append(ops.removes[t.DocID], jti)
				}
			}
		}
	}
	return ops
}

// walReadThrough is the EventDAO decorator that serves undrained WAL entries
// to the delivery runners. Everything it does not override goes to the store.
type walReadThrough struct {
	interfaces.EventDAO
	overlay *walOverlay
	metrics *walMetrics
}

func newWalReadThrough(base interfaces.EventDAO, metrics *walMetrics) *walReadThrough {
	return &walReadThrough{EventDAO: base, overlay: newWalOverlay(), metrics: metrics}
}

// GetPendingForStream merges the stream's undrained SETs with the store's
// pending markers, ascending by jti (the store's delivery order, ADR 0040),
// without duplicates and without SETs whose ack or clear is held.
func (d *walReadThrough) GetPendingForStream(ctx context.Context, streamID string, limit int32) ([]string, int64, error) {
	d.overlay.mu.RLock()
	marks := d.overlay.pending[streamID]
	live := make([]string, 0, len(marks))
	hidden := map[string]struct{}{}
	for jti, m := range marks {
		if m.live() {
			live = append(live, jti)
		} else {
			hidden[jti] = struct{}{}
		}
	}
	d.overlay.mu.RUnlock()

	baseLimit := limit
	if limit > 0 {
		// Over-read by the SETs the filter may drop, so a full page stays full.
		baseLimit = limit + int32(len(hidden))
	}
	jtis, total, err := d.EventDAO.GetPendingForStream(ctx, streamID, baseLimit)
	if err != nil {
		return nil, 0, err
	}
	if len(marks) == 0 {
		return jtis, total, nil
	}

	seen := make(map[string]struct{}, len(jtis)+len(live))
	merged := make([]string, 0, len(jtis)+len(live))
	for _, jti := range jtis {
		if _, skip := hidden[jti]; skip {
			total--
			continue
		}
		seen[jti] = struct{}{}
		merged = append(merged, jti)
	}
	for _, jti := range live {
		if _, dup := seen[jti]; dup {
			continue
		}
		merged = append(merged, jti)
		total++
	}
	sort.Strings(merged)
	if limit > 0 && int32(len(merged)) > limit {
		merged = merged[:limit]
	}
	return merged, max(total, int64(len(merged))), nil
}

// FindByJTI serves an undrained SET from the overlay, else the store.
func (d *walReadThrough) FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error) {
	d.overlay.mu.RLock()
	rec := d.overlay.records[jti]
	d.overlay.mu.RUnlock()
	if rec != nil {
		d.metrics.ringFedServed.Inc()
		cp := *rec
		return &cp, nil
	}
	return d.EventDAO.FindByJTI(ctx, jti)
}

// FindByJTIs serves the undrained SETs from the overlay and reads only the
// rest from the store; the result follows the order of jtis.
func (d *walReadThrough) FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error) {
	found := make(map[string]*model.EventRecord, len(jtis))
	var rest []string
	d.overlay.mu.RLock()
	for _, jti := range jtis {
		if rec := d.overlay.records[jti]; rec != nil {
			cp := *rec
			found[jti] = &cp
		} else {
			rest = append(rest, jti)
		}
	}
	d.overlay.mu.RUnlock()
	if len(found) == 0 {
		return d.EventDAO.FindByJTIs(ctx, jtis)
	}
	d.metrics.ringFedServed.Add(float64(len(found)))
	if len(rest) > 0 {
		recs, err := d.EventDAO.FindByJTIs(ctx, rest)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			if rec != nil {
				found[rec.Jti] = rec
			}
		}
	}
	out := make([]*model.EventRecord, 0, len(found))
	for _, jti := range jtis {
		if rec, ok := found[jti]; ok {
			out = append(out, rec)
			delete(found, jti)
		}
	}
	return out, nil
}

// AckDelivered holds the ack of every undrained SET queued on the stream —
// recorded before the store call, so a drain that writes the SET after this
// point still applies it — and acks the rest in the store. The result is the
// union of both.
func (d *walReadThrough) AckDelivered(ctx context.Context, jtis []string, streamID string, ackDate time.Time) ([]string, error) {
	var held []string
	d.overlay.mu.Lock()
	if marks := d.overlay.pending[streamID]; marks != nil {
		for _, jti := range jtis {
			if m := marks[jti]; m != nil && m.live() {
				m.acked = true
				m.ackDate = ackDate
				held = append(held, jti)
			}
		}
	}
	d.overlay.mu.Unlock()

	acked, err := d.EventDAO.AckDelivered(ctx, jtis, streamID, ackDate)
	if err != nil {
		return held, err
	}
	if len(held) == 0 {
		return acked, nil
	}
	seen := make(map[string]struct{}, len(acked))
	for _, jti := range acked {
		seen[jti] = struct{}{}
	}
	for _, jti := range held {
		if _, dup := seen[jti]; !dup {
			acked = append(acked, jti)
		}
	}
	return acked, nil
}

// ClearPendingForStream clears the store's markers and holds a clear for the
// stream's undrained SETs, which the drain applies after writing them.
func (d *walReadThrough) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	var n int64
	d.overlay.mu.Lock()
	for _, m := range d.overlay.pending[streamID] {
		if m.live() {
			m.removed = true
			n++
		}
	}
	d.overlay.mu.Unlock()
	cleared, err := d.EventDAO.ClearPendingForStream(ctx, streamID)
	return cleared + n, err
}

// applyHeld writes the held acks and clears for entries to the store. The
// drain calls it after the store write and before truncating the entries; an
// error keeps them in the log (and their holds in the overlay) for the next
// pass.
func (d *walReadThrough) applyHeld(ctx context.Context, entries []*walEntry) error {
	ops := d.overlay.held(entries)
	for streamID, byDate := range ops.acks {
		for ackDate, jtis := range byDate {
			if _, err := d.EventDAO.AckDelivered(ctx, jtis, streamID, ackDate); err != nil {
				return err
			}
		}
	}
	for streamID, jtis := range ops.removes {
		if _, err := d.EventDAO.RemovePendingMany(ctx, jtis, streamID); err != nil {
			return err
		}
	}
	return nil
}
