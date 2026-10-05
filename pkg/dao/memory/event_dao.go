package memory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// delivery is one deliveries row: the memory twin of the Mongo deliveries
// document, keyed by (stream, inbound JTI).
type delivery struct {
	Jti       string
	AckJti    string
	State     string
	CreatedAt time.Time
	AckDate   time.Time
	ExpireAt  *time.Time
}

type EventDAOMemory struct {
	mu     sync.RWMutex
	events map[string]*model.EventRecord
	// deliveries holds one row per (stream, inbound JTI): streamId -> jti -> row.
	deliveries map[string]map[string]*delivery
	// byAck is the (stream, ackJti) -> inbound JTIs lookup Ack uses.
	byAck map[string]map[string]map[string]struct{}
	// now is the adapter clock (createdAt for a reference written with a
	// zero EnqueuedAt).
	now func() time.Time

	// sweepAfterTime / sweepAfterJti are the SweepExpired body-scan
	// watermark: the next pass resumes after (sortTime, jti). Zero values
	// start from the oldest body. In-process only, guarded by mu.
	sweepAfterTime time.Time
	sweepAfterJti  string

	// Persistence
	persistDir string
	useDisk    bool
}

func NewEventDAO() *EventDAOMemory {
	return &EventDAOMemory{
		events:     make(map[string]*model.EventRecord),
		deliveries: make(map[string]map[string]*delivery),
		byAck:      make(map[string]map[string]map[string]struct{}),
		now:        time.Now,
	}
}

// SetClock replaces the adapter clock; tests use it to pin createdAt.
func (d *EventDAOMemory) SetClock(now func() time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	d.now = now
}

func (d *EventDAOMemory) SetPersistDir(dir string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.persistDir = dir
	if dir != "" {
		d.useDisk = true
		// Ensure events directory exists
		_ = os.MkdirAll(filepath.Join(dir, "events"), 0755)
	} else {
		d.useDisk = false
	}
}

func (d *EventDAOMemory) Insert(_ context.Context, record *model.EventRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.insertLocked(record)
}

// InsertMany stores records in order under a single lock acquisition; the
// returned slice is index-aligned with records (nil or ErrDuplicateJTI).
func (d *EventDAOMemory) InsertMany(_ context.Context, records []*model.EventRecord) ([]error, error) {
	if len(records) == 0 {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	results := make([]error, len(records))
	for i, rec := range records {
		results[i] = d.insertLocked(rec)
	}
	return results, nil
}

// InsertWithPending stores records and their pending references under one
// lock (ADR 0043): a reference is written only for a record that was actually
// stored, so a duplicate JTI never leaves a delivery intent behind. A
// reference row that already exists for (stream, JTI) is left untouched.
func (d *EventDAOMemory) InsertWithPending(_ context.Context, records []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	if len(records) == 0 {
		return nil, nil
	}
	streams := interfaces.StreamsByJti(pending)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	results := make([]error, len(records))
	for i, rec := range records {
		if results[i] = d.insertLocked(rec); results[i] != nil {
			continue
		}
		for _, t := range streams[rec.Jti] {
			d.insertPendingLocked(t.StreamID, t.Ref, now)
		}
	}
	return results, nil
}

// insertLocked applies the single-record insert semantics; d.mu must be held.
func (d *EventDAOMemory) insertLocked(record *model.EventRecord) error {
	// JTI is the persistence-layer dedup key. Reject the new write and leave
	// the existing record untouched (matches Mongo's reject-new-write semantic).
	if _, exists := d.events[record.Jti]; exists {
		return interfaces.ErrDuplicateJTI
	}

	if d.useDisk {
		if err := d.saveEventToDiskLocked(record); err == nil {
			// Memory optimization: with the body on disk the in-memory copy
			// drops Original (FindByJTI/FindByJTIs reload it). Strip a COPY,
			// never the caller's record: under concurrent ingest the caller
			// still owns that pointer and routing reads it while the body
			// write is in flight (ADR 0038, EventService.Candidates), so
			// mutating it here would be a write racing those reads.
			// We keep Event for filtering/matching as it's often used.
			stored := *record
			stored.Original = ""
			d.events[stored.Jti] = &stored
			return nil
		}
	}

	d.events[record.Jti] = record
	return nil
}

func (d *EventDAOMemory) FindByJTI(_ context.Context, jti string) (*model.EventRecord, error) {
	d.mu.RLock()
	eventRec, ok := d.events[jti]
	d.mu.RUnlock()

	if ok {
		// If Original is empty but we are using disk, try to reload it
		if eventRec.Original == "" && d.useDisk {
			loaded, err := d.loadEventFromDisk(jti)
			if err == nil {
				return loaded, nil
			}
		}
		copyRec := *eventRec
		return &copyRec, nil
	}
	return nil, nil
}

func (d *EventDAOMemory) FindByJTIs(_ context.Context, jtis []string) ([]*model.EventRecord, error) {
	d.mu.RLock()
	var records []*model.EventRecord
	for _, jti := range jtis {
		if eventRec, ok := d.events[jti]; ok {
			copyRec := *eventRec
			records = append(records, &copyRec)
		}
	}
	useDisk := d.useDisk
	d.mu.RUnlock()

	// Same reload as FindByJTI: with disk persistence the in-memory record
	// drops Original, which forward-mode delivery sends verbatim.
	if useDisk {
		for i, rec := range records {
			if rec.Original == "" {
				if loaded, err := d.loadEventFromDisk(rec.Jti); err == nil {
					records[i] = loaded
				}
			}
		}
	}
	return records, nil
}

func (d *EventDAOMemory) FindByTimeRange(_ context.Context, from time.Time, to *time.Time, filter func(*model.EventRecord) bool) ([]*model.EventRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Truncate resetDate to second precision to match JWT NumericDate behavior
	fromTruncated := from.Truncate(time.Second)

	var sortedEvents []*model.EventRecord
	for _, event := range d.events {
		// Check time range
		inRange := event.SortTime.Equal(fromTruncated) || event.SortTime.After(fromTruncated)
		if to != nil {
			toTruncated := to.Truncate(time.Second)
			inRange = inRange && (event.SortTime.Equal(toTruncated) || event.SortTime.Before(toTruncated))
		}

		// A stored outbound copy is never replayed by a reset.
		if inRange && event.OriginalJti == "" {
			if filter == nil || filter(event) {
				sortedEvents = append(sortedEvents, event)
			}
		}
	}

	// Sort events by JTI to ensure consistent ordering (KSUIDs are sortable by time)
	sort.Slice(sortedEvents, func(i, j int) bool {
		return sortedEvents[i].Jti < sortedEvents[j].Jti
	})

	return sortedEvents, nil
}

// rowLocked returns the (streamID, jti) row or nil; d.mu must be held.
func (d *EventDAOMemory) rowLocked(streamID, jti string) *delivery {
	return d.deliveries[streamID][jti]
}

// putRowLocked stores row for streamID and indexes its ackJti; d.mu must be held.
func (d *EventDAOMemory) putRowLocked(streamID string, row *delivery) {
	rows := d.deliveries[streamID]
	if rows == nil {
		rows = make(map[string]*delivery)
		d.deliveries[streamID] = rows
	}
	rows[row.Jti] = row
	d.indexAckLocked(streamID, row.AckJti, row.Jti)
}

func (d *EventDAOMemory) indexAckLocked(streamID, ackJti, jti string) {
	acks := d.byAck[streamID]
	if acks == nil {
		acks = make(map[string]map[string]struct{})
		d.byAck[streamID] = acks
	}
	set := acks[ackJti]
	if set == nil {
		set = make(map[string]struct{})
		acks[ackJti] = set
	}
	set[jti] = struct{}{}
}

func (d *EventDAOMemory) unindexAckLocked(streamID, ackJti, jti string) {
	acks := d.byAck[streamID]
	if acks == nil {
		return
	}
	if set := acks[ackJti]; set != nil {
		delete(set, jti)
		if len(set) == 0 {
			delete(acks, ackJti)
		}
	}
	if len(acks) == 0 {
		delete(d.byAck, streamID)
	}
}

// setAckJtiLocked changes row's ackJti, keeping the lookup in step.
func (d *EventDAOMemory) setAckJtiLocked(streamID string, row *delivery, ackJti string) {
	if row.AckJti == ackJti {
		return
	}
	d.unindexAckLocked(streamID, row.AckJti, row.Jti)
	row.AckJti = ackJti
	d.indexAckLocked(streamID, ackJti, row.Jti)
}

// deleteRowLocked removes the (streamID, jti) row; d.mu must be held.
func (d *EventDAOMemory) deleteRowLocked(streamID string, row *delivery) {
	rows := d.deliveries[streamID]
	if rows == nil {
		return
	}
	delete(rows, row.Jti)
	if len(rows) == 0 {
		delete(d.deliveries, streamID)
	}
	d.unindexAckLocked(streamID, row.AckJti, row.Jti)
}

func refAckJti(ref interfaces.PendingRef) string {
	if ref.AckJti == "" {
		return ref.Jti
	}
	return ref.AckJti
}

func refCreatedAt(ref interfaces.PendingRef, now time.Time) time.Time {
	if ref.EnqueuedAt.IsZero() {
		return now
	}
	return ref.EnqueuedAt
}

// insertPendingLocked inserts a pending row for ref only when no row exists
// for (streamID, ref.Jti) in either state, and reports whether it did.
func (d *EventDAOMemory) insertPendingLocked(streamID string, ref interfaces.PendingRef, now time.Time) bool {
	if d.rowLocked(streamID, ref.Jti) != nil {
		return false
	}
	d.putRowLocked(streamID, &delivery{
		Jti:       ref.Jti,
		AckJti:    refAckJti(ref),
		State:     interfaces.DeliveryStatePending,
		CreatedAt: refCreatedAt(ref, now),
	})
	return true
}

// upsertPendingLocked applies AddPending to one reference: the row becomes
// pending with ref's ackJti, ackDate and expireAt cleared; createdAt is set on
// insert, re-set when the row was delivered, and kept when it was pending.
func (d *EventDAOMemory) upsertPendingLocked(streamID string, ref interfaces.PendingRef, now time.Time) {
	row := d.rowLocked(streamID, ref.Jti)
	if row == nil {
		d.insertPendingLocked(streamID, ref, now)
		return
	}
	if row.State != interfaces.DeliveryStatePending {
		row.CreatedAt = refCreatedAt(ref, now)
	}
	row.State = interfaces.DeliveryStatePending
	row.AckDate = time.Time{}
	row.ExpireAt = nil
	d.setAckJtiLocked(streamID, row, refAckJti(ref))
}

// AddPending records a delivery intent for ref on streamID. The reference is
// written independently of the event body — the body may not be stored yet,
// or may never be, because ingest issues the two writes concurrently (ADR
// 0038). Every delivery path treats a pending JTI with no body as a skip.
func (d *EventDAOMemory) AddPending(_ context.Context, ref interfaces.PendingRef, streamID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.upsertPendingLocked(streamID, ref, d.now())
	return nil
}

// AddPendingMany is AddPending for a batch under one lock acquisition.
func (d *EventDAOMemory) AddPendingMany(_ context.Context, refs []interfaces.PendingRef, streamID string) error {
	if len(refs) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	for _, ref := range refs {
		d.upsertPendingLocked(streamID, ref, now)
	}
	return nil
}

// EnsurePending queues jti on each stream of ackJtis that holds no row for it
// in either state (#331); an existing row is left untouched.
func (d *EventDAOMemory) EnsurePending(_ context.Context, jti string, ackJtis map[string]string) ([]string, error) {
	if len(ackJtis) == 0 {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	var queued []string
	for streamID, ackJti := range ackJtis {
		if d.insertPendingLocked(streamID, interfaces.PendingRef{Jti: jti, AckJti: ackJti}, now) {
			queued = append(queued, streamID)
		}
	}
	return queued, nil
}

// pendingSortedLocked returns streamID's pending rows in ascending jti order.
func (d *EventDAOMemory) pendingSortedLocked(streamID string) []*delivery {
	var out []*delivery
	for _, row := range d.deliveries[streamID] {
		if row.State == interfaces.DeliveryStatePending {
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Jti < out[j].Jti })
	return out
}

// GetPendingForStream returns one page of streamID's pending references in
// ascending jti order, matching the Mongo DAO. jtis are UUIDv7
// (goSet.GenerateJti), so ascending jti IS ascending issue order; delivery
// order is a contract receivers reason about (ADR 0040), so both providers
// publish the same one. A limit <= 0 reads 10 references.
func (d *EventDAOMemory) GetPendingForStream(_ context.Context, streamID string, limit int32) (interfaces.PendingPage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	pending := d.pendingSortedLocked(streamID)
	page := interfaces.PendingPage{Refs: []interfaces.PendingRef{}, Total: int64(len(pending))}
	if len(pending) == 0 {
		return page, nil
	}
	maxEvents := int(limit)
	if maxEvents <= 0 {
		maxEvents = 10
	}
	n := min(maxEvents, len(pending))
	for _, row := range pending[:n] {
		page.Refs = append(page.Refs, interfaces.PendingRef{Jti: row.Jti, AckJti: row.AckJti, EnqueuedAt: row.CreatedAt})
	}
	for _, row := range pending[n:] {
		if page.OldestBeyond.IsZero() || row.CreatedAt.Before(page.OldestBeyond) {
			page.OldestBeyond = row.CreatedAt
		}
	}
	return page, nil
}

// RemovePendingMany deletes every pending row of streamID whose JTI is in
// jtis under a single lock acquisition and returns the removed entries.
func (d *EventDAOMemory) RemovePendingMany(_ context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	if len(jtis) == 0 {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	var removed []interfaces.DeliverableEvent
	for _, jti := range jtis {
		row := d.rowLocked(streamID, jti)
		if row == nil || row.State != interfaces.DeliveryStatePending {
			continue
		}
		d.deleteRowLocked(streamID, row)
		removed = append(removed, row.deliverable(streamID))
	}
	return removed, nil
}

// ClearPendingForStream deletes streamID's pending rows; delivered rows stay.
func (d *EventDAOMemory) ClearPendingForStream(_ context.Context, streamID string) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var count int64
	for _, row := range d.deliveries[streamID] {
		if row.State == interfaces.DeliveryStatePending {
			d.deleteRowLocked(streamID, row)
			count++
		}
	}
	return count, nil
}

// Ack moves every pending row of batch.StreamID whose ackJti is in batch.Jtis
// to delivered and stores batch.Copies (a duplicate counts as stored), under
// one lock: the conditional update is exactly-once across callers.
func (d *EventDAOMemory) Ack(_ context.Context, batch interfaces.AckBatch) (int64, error) {
	if len(batch.Jtis) == 0 && len(batch.Copies) == 0 {
		return 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, rec := range batch.Copies {
		if rec == nil {
			continue
		}
		_ = d.insertLocked(rec) // ErrDuplicateJTI: the first stored copy wins
	}
	var acked int64
	acks := d.byAck[batch.StreamID]
	for _, ackJti := range batch.Jtis {
		for jti := range acks[ackJti] {
			row := d.rowLocked(batch.StreamID, jti)
			if row == nil || row.State != interfaces.DeliveryStatePending {
				continue
			}
			row.State = interfaces.DeliveryStateDelivered
			row.AckDate = batch.AckDate
			if batch.ExpireAt != nil {
				exp := *batch.ExpireAt
				row.ExpireAt = &exp
			} else {
				row.ExpireAt = nil
			}
			acked++
		}
	}
	return acked, nil
}

// ResetPendingAckJti sets ackJti = jti on streamID's pending rows whose ackJti
// differs; delivered rows are untouched.
func (d *EventDAOMemory) ResetPendingAckJti(_ context.Context, streamID string) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var modified int64
	for _, row := range d.deliveries[streamID] {
		if row.State == interfaces.DeliveryStatePending && row.AckJti != row.Jti {
			d.setAckJtiLocked(streamID, row, row.Jti)
			modified++
		}
	}
	return modified, nil
}

// SweepExpired removes every reference with expireAt <= now, then examines at
// most maxBodies event bodies with sortTime < bodyCutoff, in ascending
// (sortTime, jti) order from the in-process watermark, and deletes each one
// whose reference key (OriginalJti when set, else Jti) has no deliveries row in
// either state. The scan wraps to the oldest body once it reaches the end.
func (d *EventDAOMemory) SweepExpired(_ context.Context, now time.Time, bodyCutoff time.Time, maxBodies int) (interfaces.SweepResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var result interfaces.SweepResult
	for streamID, rows := range d.deliveries {
		for _, row := range rows {
			if row.ExpireAt != nil && !row.ExpireAt.After(now) {
				d.deleteRowLocked(streamID, row)
				result.References++
			}
		}
	}
	if maxBodies <= 0 {
		return result, nil
	}

	referenced := make(map[string]struct{})
	for _, rows := range d.deliveries {
		for jti := range rows {
			referenced[jti] = struct{}{}
		}
	}

	var candidates []*model.EventRecord
	for _, rec := range d.events {
		if rec.SortTime.Before(bodyCutoff) {
			candidates = append(candidates, rec)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].SortTime.Equal(candidates[j].SortTime) {
			return candidates[i].SortTime.Before(candidates[j].SortTime)
		}
		return candidates[i].Jti < candidates[j].Jti
	})

	// Resume strictly after the watermark; wrap with the remaining budget.
	start := sort.Search(len(candidates), func(i int) bool {
		c := candidates[i]
		if !c.SortTime.Equal(d.sweepAfterTime) {
			return c.SortTime.After(d.sweepAfterTime)
		}
		return c.Jti > d.sweepAfterJti
	})
	n := maxBodies
	if n > len(candidates) {
		n = len(candidates)
	}
	examined := make([]*model.EventRecord, 0, n)
	for i := 0; i < n; i++ {
		examined = append(examined, candidates[(start+i)%len(candidates)])
	}
	if n == 0 || start+n == len(candidates) {
		// Reached the end of the eligible range: start over next pass.
		d.sweepAfterTime, d.sweepAfterJti = time.Time{}, ""
	} else {
		last := examined[n-1]
		d.sweepAfterTime, d.sweepAfterJti = last.SortTime, last.Jti
	}

	for _, rec := range examined {
		key := rec.Jti
		if rec.OriginalJti != "" {
			key = rec.OriginalJti
		}
		if _, ok := referenced[key]; ok {
			continue
		}
		delete(d.events, rec.Jti)
		if d.useDisk {
			d.deleteEventFromDiskLocked(rec.Jti)
		}
		result.Bodies++
	}
	return result, nil
}

// MigrateLegacyDeliveries has nothing to carry in memory: the persisted files
// already load into the deliveries map, so the old collections are "gone".
func (d *EventDAOMemory) MigrateLegacyDeliveries(_ context.Context, _ func(streamID string, ackDate time.Time) *time.Time) (interfaces.MigrationResult, error) {
	return interfaces.MigrationResult{Dropped: true}, nil
}

func (row *delivery) deliverable(streamID string) interfaces.DeliverableEvent {
	return interfaces.DeliverableEvent{Jti: row.Jti, StreamId: streamID, AckJti: row.AckJti, CreatedAt: row.CreatedAt}
}

func (row *delivery) delivered(streamID string) interfaces.DeliveredEvent {
	out := interfaces.DeliveredEvent{DeliverableEvent: row.deliverable(streamID), AckDate: row.AckDate}
	if row.ExpireAt != nil {
		exp := *row.ExpireAt
		out.ExpireAt = &exp
	}
	return out
}

// ListDeliveredForStream returns streamID's delivered rows (ADR 0055).
func (d *EventDAOMemory) ListDeliveredForStream(_ context.Context, streamID string) ([]interfaces.DeliveredEvent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	out := []interfaces.DeliveredEvent{}
	for _, row := range d.deliveries[streamID] {
		if row.State == interfaces.DeliveryStateDelivered {
			out = append(out, row.delivered(streamID))
		}
	}
	return out, nil
}

// RemoveDelivered drops streamID's delivered row for jti. The global body is
// left intact — refcount-gated deletion is DeleteBodyIfUnreferenced's job.
func (d *EventDAOMemory) RemoveDelivered(_ context.Context, jti string, streamID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if row := d.rowLocked(streamID, jti); row != nil && row.State == interfaces.DeliveryStateDelivered {
		d.deleteRowLocked(streamID, row)
	}
	return nil
}

// DeleteBodyIfUnreferenced deletes the global body for jti only when no row in
// either state references it (refcount 0).
func (d *EventDAOMemory) DeleteBodyIfUnreferenced(_ context.Context, jti string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.events[jti]; !ok {
		return false, nil
	}
	for _, rows := range d.deliveries {
		if _, ok := rows[jti]; ok {
			return false, nil
		}
	}

	delete(d.events, jti)
	if d.useDisk {
		d.deleteEventFromDiskLocked(jti)
	}
	return true, nil
}

// CountRetainedForStream returns the count of delivered rows for streamID —
// the daily occupancy sampler's retained_count.
func (d *EventDAOMemory) CountRetainedForStream(_ context.Context, streamID string) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var n int64
	for _, row := range d.deliveries[streamID] {
		if row.State == interfaces.DeliveryStateDelivered {
			n++
		}
	}
	return n, nil
}

func (d *EventDAOMemory) WatchPending(ctx context.Context, _ func(ref interfaces.PendingRef, streamID string)) error {
	// The memory provider's notifying wrapper reports pending writes; the
	// bare adapter has no change feed.
	<-ctx.Done()
	return nil
}

// Persistence helpers

func (d *EventDAOMemory) saveEventToDiskLocked(record *model.EventRecord) error {
	if d.persistDir == "" {
		return nil
	}
	path := filepath.Join(d.persistDir, "events", record.Jti+".set")
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (d *EventDAOMemory) deleteEventFromDiskLocked(jti string) {
	if d.persistDir == "" {
		return
	}
	path := filepath.Join(d.persistDir, "events", jti+".set")
	_ = os.Remove(path)
}

func (d *EventDAOMemory) loadEventFromDisk(jti string) (*model.EventRecord, error) {
	if d.persistDir == "" {
		return nil, os.ErrNotExist
	}
	path := filepath.Join(d.persistDir, "events", jti+".set")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record model.EventRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// GetState returns a copy of the store in its persisted shape: pending rows as
// DeliverableEvent and delivered rows as DeliveredEvent, each list in
// ascending jti order.
func (d *EventDAOMemory) GetState() (events map[string]*model.EventRecord, pending map[string][]interfaces.DeliverableEvent, delivered map[string][]interfaces.DeliveredEvent) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	events = make(map[string]*model.EventRecord)
	for k, v := range d.events {
		copyRec := *v
		events[k] = &copyRec
	}

	pending = make(map[string][]interfaces.DeliverableEvent)
	delivered = make(map[string][]interfaces.DeliveredEvent)
	for streamID, rows := range d.deliveries {
		jtis := make([]string, 0, len(rows))
		for jti := range rows {
			jtis = append(jtis, jti)
		}
		sort.Strings(jtis)
		for _, jti := range jtis {
			row := rows[jti]
			if row.State == interfaces.DeliveryStatePending {
				pending[streamID] = append(pending[streamID], row.deliverable(streamID))
			} else {
				delivered[streamID] = append(delivered[streamID], row.delivered(streamID))
			}
		}
	}
	return events, pending, delivered
}

// SetState replaces the store from its persisted shape. A nil argument keeps
// the current contents of that part (for pending / delivered: the rows in that
// state). An entry loaded without ackJti gets ackJti = jti, and one without
// createdAt gets the load time. A JTI listed both pending and delivered for a
// stream is kept pending (at-least-once).
func (d *EventDAOMemory) SetState(events map[string]*model.EventRecord, pending map[string][]interfaces.DeliverableEvent, delivered map[string][]interfaces.DeliveredEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if events != nil {
		d.events = events
	}
	if pending == nil && delivered == nil {
		return
	}
	now := d.now()
	old := d.deliveries
	d.deliveries = make(map[string]map[string]*delivery)
	d.byAck = make(map[string]map[string]map[string]struct{})
	for streamID, rows := range old {
		for _, row := range rows {
			if row.State == interfaces.DeliveryStatePending && pending == nil ||
				row.State == interfaces.DeliveryStateDelivered && delivered == nil {
				d.putRowLocked(streamID, row)
			}
		}
	}
	loaded := func(ev interfaces.DeliverableEvent) *delivery {
		row := &delivery{Jti: ev.Jti, AckJti: ev.AckJti, CreatedAt: ev.CreatedAt}
		if row.AckJti == "" {
			row.AckJti = row.Jti
		}
		if row.CreatedAt.IsZero() {
			row.CreatedAt = now
		}
		return row
	}
	for streamID, list := range delivered {
		for _, ev := range list {
			row := loaded(ev.DeliverableEvent)
			row.State = interfaces.DeliveryStateDelivered
			row.AckDate = ev.AckDate
			if ev.ExpireAt != nil {
				exp := *ev.ExpireAt
				row.ExpireAt = &exp
			}
			d.replaceRowLocked(streamID, row)
		}
	}
	for streamID, list := range pending {
		for _, ev := range list {
			row := loaded(ev)
			row.State = interfaces.DeliveryStatePending
			d.replaceRowLocked(streamID, row)
		}
	}
}

// replaceRowLocked stores row, first removing any row for the same
// (streamID, jti) so the ackJti lookup stays exact.
func (d *EventDAOMemory) replaceRowLocked(streamID string, row *delivery) {
	if prev := d.rowLocked(streamID, row.Jti); prev != nil {
		d.deleteRowLocked(streamID, prev)
	}
	d.putRowLocked(streamID, row)
}
