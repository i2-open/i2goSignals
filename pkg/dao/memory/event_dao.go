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

type EventDAOMemory struct {
	mu              sync.RWMutex
	events          map[string]*model.EventRecord
	pendingEvents   map[string][]interfaces.DeliverableEvent // streamId -> events
	deliveredEvents map[string][]interfaces.DeliveredEvent   // streamId -> events

	// Persistence
	persistDir string
	useDisk    bool
}

func NewEventDAO() *EventDAOMemory {
	return &EventDAOMemory{
		events:          make(map[string]*model.EventRecord),
		pendingEvents:   make(map[string][]interfaces.DeliverableEvent),
		deliveredEvents: make(map[string][]interfaces.DeliveredEvent),
	}
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

		if inRange {
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

// AddPending records a delivery intent for jti on streamID. The pending marker
// is written independently of the event body — the body may not be stored yet,
// or may never be, because ingest issues the two writes concurrently (ADR
// 0038). This mirrors the Mongo DAO, whose pendingEvents insert has never
// consulted the events collection. Every delivery path treats a pending JTI
// with no body as a skip: it is neither delivered nor acked.
func (d *EventDAOMemory) AddPending(_ context.Context, jti string, streamID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pendingEvents[streamID] = append(d.pendingEvents[streamID], interfaces.DeliverableEvent{
		Jti:      jti,
		StreamId: streamID,
	})
	return nil
}

// AddPendingMany is AddPending for a batch, appending in the given order. As
// with AddPending, a JTI whose body is not (yet) stored is still recorded.
func (d *EventDAOMemory) AddPendingMany(_ context.Context, jtis []string, streamID string) error {
	if len(jtis) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, jti := range jtis {
		d.pendingEvents[streamID] = append(d.pendingEvents[streamID], interfaces.DeliverableEvent{
			Jti:      jti,
			StreamId: streamID,
		})
	}
	return nil
}

func (d *EventDAOMemory) GetPendingForStream(_ context.Context, streamID string, limit int32) (jtis []string, total int64, err error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	pending, ok := d.pendingEvents[streamID]
	if !ok || len(pending) == 0 {
		return []string{}, 0, nil
	}

	maxEvents := limit
	if maxEvents <= 0 {
		maxEvents = 10
	}

	// Sort by jti, matching the Mongo DAO's explicit ascending-jti sort. jtis
	// are UUIDv7 (goSet.GenerateJti), so ascending jti IS ascending issue
	// order. Delivery order is a contract receivers reason about (ADR 0040),
	// so both providers must publish the same one — insertion order here would
	// make the contract hold on Mongo and quietly not hold on memory.
	ordered := make([]string, len(pending))
	for i, event := range pending {
		ordered[i] = event.Jti
	}
	sort.Strings(ordered)

	var jtiList []string
	for i, jti := range ordered {
		if int32(i) >= maxEvents {
			break
		}
		jtiList = append(jtiList, jti)
	}

	return jtiList, int64(len(pending)), nil
}

func (d *EventDAOMemory) RemovePending(_ context.Context, jti string, streamID string) (*interfaces.DeliverableEvent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Remove from pending
	if pending, ok := d.pendingEvents[streamID]; ok {
		var newPending []interfaces.DeliverableEvent
		var acknowledged *interfaces.DeliverableEvent
		for _, event := range pending {
			if event.Jti == jti {
				evt := event
				acknowledged = &evt
			} else {
				newPending = append(newPending, event)
			}
		}
		d.pendingEvents[streamID] = newPending
		return acknowledged, nil
	}
	return nil, nil
}

// RemovePendingMany removes every pending entry of streamID whose JTI is in
// jtis under a single lock acquisition and returns the removed entries.
func (d *EventDAOMemory) RemovePendingMany(_ context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	if len(jtis) == 0 {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	pending, ok := d.pendingEvents[streamID]
	if !ok {
		return nil, nil
	}
	want := make(map[string]struct{}, len(jtis))
	for _, jti := range jtis {
		want[jti] = struct{}{}
	}
	var removed []interfaces.DeliverableEvent
	var newPending []interfaces.DeliverableEvent
	for _, event := range pending {
		if _, acked := want[event.Jti]; acked {
			removed = append(removed, event)
		} else {
			newPending = append(newPending, event)
		}
	}
	d.pendingEvents[streamID] = newPending
	return removed, nil
}

// RetractPending removes the last-appended pending entry for each JTI and
// leaves any earlier entry for the same JTI in its original position (ADR
// 0038), so retracting a speculative delivery intent cannot drop an older
// intent that is still awaiting delivery.
func (d *EventDAOMemory) RetractPending(_ context.Context, jtis []string, streamID string) error {
	if len(jtis) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	pending, ok := d.pendingEvents[streamID]
	if !ok {
		return nil
	}
	drop := make(map[int]struct{}, len(jtis))
	for _, jti := range jtis {
		for i := len(pending) - 1; i >= 0; i-- {
			if _, taken := drop[i]; taken || pending[i].Jti != jti {
				continue
			}
			drop[i] = struct{}{}
			break
		}
	}
	if len(drop) == 0 {
		return nil
	}
	kept := make([]interfaces.DeliverableEvent, 0, len(pending)-len(drop))
	for i, event := range pending {
		if _, dropped := drop[i]; dropped {
			continue
		}
		kept = append(kept, event)
	}
	d.pendingEvents[streamID] = kept
	return nil
}

func (d *EventDAOMemory) ClearPendingForStream(_ context.Context, streamID string) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	count := int64(len(d.pendingEvents[streamID]))
	delete(d.pendingEvents, streamID)
	return count, nil
}

func (d *EventDAOMemory) MarkDelivered(_ context.Context, event *interfaces.DeliverableEvent, ackDate time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	delivered := interfaces.DeliveredEvent{
		DeliverableEvent: *event,
		AckDate:          ackDate,
	}
	d.deliveredEvents[event.StreamId] = append(d.deliveredEvents[event.StreamId], delivered)
	return nil
}

// MarkDeliveredMany appends every event to its stream's delivered list under a
// single lock acquisition.
func (d *EventDAOMemory) MarkDeliveredMany(_ context.Context, events []interfaces.DeliverableEvent, ackDate time.Time) error {
	if len(events) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, event := range events {
		d.deliveredEvents[event.StreamId] = append(d.deliveredEvents[event.StreamId], interfaces.DeliveredEvent{
			DeliverableEvent: event,
			AckDate:          ackDate,
		})
	}
	return nil
}

// ListDeliveredForStream returns a copy of streamID's delivered events (ADR 0055).
func (d *EventDAOMemory) ListDeliveredForStream(_ context.Context, streamID string) ([]interfaces.DeliveredEvent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	delivered := d.deliveredEvents[streamID]
	out := make([]interfaces.DeliveredEvent, len(delivered))
	copy(out, delivered)
	return out, nil
}

// RemoveDelivered drops streamID's delivered entry for jti. The global body is
// left intact — refcount-gated deletion is DeleteBodyIfUnreferenced's job.
func (d *EventDAOMemory) RemoveDelivered(_ context.Context, jti string, streamID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	delivered, ok := d.deliveredEvents[streamID]
	if !ok {
		return nil
	}
	kept := delivered[:0:0]
	for _, evt := range delivered {
		if evt.Jti != jti {
			kept = append(kept, evt)
		}
	}
	if len(kept) == 0 {
		delete(d.deliveredEvents, streamID)
	} else {
		d.deliveredEvents[streamID] = kept
	}
	return nil
}

// DeleteBodyIfUnreferenced deletes the global body for jti only when no stream
// references it in pending or delivered (refcount 0).
func (d *EventDAOMemory) DeleteBodyIfUnreferenced(_ context.Context, jti string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.events[jti]; !ok {
		return false, nil
	}
	for _, pending := range d.pendingEvents {
		for _, evt := range pending {
			if evt.Jti == jti {
				return false, nil
			}
		}
	}
	for _, delivered := range d.deliveredEvents {
		for _, evt := range delivered {
			if evt.Jti == jti {
				return false, nil
			}
		}
	}

	delete(d.events, jti)
	if d.useDisk {
		d.deleteEventFromDiskLocked(jti)
	}
	return true, nil
}

// CountRetainedForStream returns the count of post-ack-retained (delivered)
// JTIs for streamID — the daily occupancy sampler's retained_count.
func (d *EventDAOMemory) CountRetainedForStream(_ context.Context, streamID string) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return int64(len(d.deliveredEvents[streamID])), nil
}

func (d *EventDAOMemory) WatchPending(ctx context.Context, _ func(jti string, streamID string)) error {
	// Mock implementation: for now, we don't need to do anything here
	// since HandleEvent already updates local buffers in the router.
	// In a real mock test, we might want to simulate external events.
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

func (d *EventDAOMemory) GetState() (events map[string]*model.EventRecord, pending map[string][]interfaces.DeliverableEvent, delivered map[string][]interfaces.DeliveredEvent) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	events = make(map[string]*model.EventRecord)
	for k, v := range d.events {
		copyRec := *v
		events[k] = &copyRec
	}

	pending = make(map[string][]interfaces.DeliverableEvent)
	for k, v := range d.pendingEvents {
		copySlice := make([]interfaces.DeliverableEvent, len(v))
		copy(copySlice, v)
		pending[k] = copySlice
	}

	delivered = make(map[string][]interfaces.DeliveredEvent)
	for k, v := range d.deliveredEvents {
		copySlice := make([]interfaces.DeliveredEvent, len(v))
		copy(copySlice, v)
		delivered[k] = copySlice
	}

	return events, pending, delivered
}

func (d *EventDAOMemory) SetState(events map[string]*model.EventRecord, pending map[string][]interfaces.DeliverableEvent, delivered map[string][]interfaces.DeliveredEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if events != nil {
		d.events = events
	}
	if pending != nil {
		d.pendingEvents = pending
	}
	if delivered != nil {
		d.deliveredEvents = delivered
	}
}
