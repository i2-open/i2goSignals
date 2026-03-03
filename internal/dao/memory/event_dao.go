package memory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
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

	if d.useDisk {
		err := d.saveEventToDiskLocked(record)
		if err == nil {
			// Memory optimization: clear large fields if on disk
			// We keep Event for filtering/matching as it's often used
			record.Original = ""
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
	defer d.mu.RUnlock()

	var records []*model.EventRecord
	for _, jti := range jtis {
		if eventRec, ok := d.events[jti]; ok {
			copyRec := *eventRec
			records = append(records, &copyRec)
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

func (d *EventDAOMemory) AddPending(_ context.Context, jti string, streamID bson.ObjectID) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.events[jti]; ok {
		streamIdHex := streamID.Hex()
		deliverable := interfaces.DeliverableEvent{
			Jti:      jti,
			StreamId: streamID,
		}
		d.pendingEvents[streamIdHex] = append(d.pendingEvents[streamIdHex], deliverable)
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

	var jtiList []string
	for i, event := range pending {
		if int32(i) >= maxEvents {
			break
		}
		jtiList = append(jtiList, event.Jti)
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

	streamID := event.StreamId.Hex()
	delivered := interfaces.DeliveredEvent{
		DeliverableEvent: *event,
		AckDate:          ackDate,
	}
	d.deliveredEvents[streamID] = append(d.deliveredEvents[streamID], delivered)
	return nil
}

func (d *EventDAOMemory) WatchPending(ctx context.Context, _ func(jti string, streamID bson.ObjectID)) error {
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
