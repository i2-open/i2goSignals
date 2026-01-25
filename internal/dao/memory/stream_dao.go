package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/model"
)

type StreamDAOMemory struct {
	mu      sync.RWMutex
	streams map[string]*model.StreamStateRecord
}

func NewStreamDAO() interfaces.StreamDAO {
	return &StreamDAOMemory{
		streams: make(map[string]*model.StreamStateRecord),
	}
}

func (d *StreamDAOMemory) Create(ctx context.Context, state *model.StreamStateRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	newState := *state
	d.streams[state.StreamConfiguration.Id] = &newState
	return nil
}

func (d *StreamDAOMemory) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if state, ok := d.streams[id]; ok {
		// Deep copy the struct to avoid data races
		copyState := *state
		// If there are pointers inside StreamConfiguration, they might still race if not deep-copied.
		// For now, copying the top-level struct should resolve the direct race on Status/ErrorMsg.
		return &copyState, nil
	}
	return nil, errors.New("stream not found")
}

func (d *StreamDAOMemory) Update(ctx context.Context, state *model.StreamStateRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.streams[state.StreamConfiguration.Id]; !exists {
		return errors.New("not found")
	}
	// Copy the provided state into a new object to avoid sharing pointers
	newState := *state
	d.streams[state.StreamConfiguration.Id] = &newState
	return nil
}

func (d *StreamDAOMemory) Delete(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.streams[id]; !exists {
		return errors.New("not found")
	}
	delete(d.streams, id)
	return nil
}

func (d *StreamDAOMemory) List(ctx context.Context) ([]model.StreamStateRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var recs []model.StreamStateRecord
	for _, state := range d.streams {
		recs = append(recs, *state)
	}
	return recs, nil
}

func (d *StreamDAOMemory) FindByProjectID(ctx context.Context, projectID string) ([]model.StreamStateRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var recs []model.StreamStateRecord
	for _, state := range d.streams {
		if state.ProjectId == projectID {
			recs = append(recs, *state)
		}
	}
	return recs, nil
}

func (d *StreamDAOMemory) FindReceiverStreams(ctx context.Context) ([]model.StreamStateRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var recs []model.StreamStateRecord
	for _, state := range d.streams {
		if state.IsReceiver() {
			recs = append(recs, *state)
		}
	}
	return recs, nil
}

func (d *StreamDAOMemory) UpdateStatus(ctx context.Context, id string, status string, errorMsg string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if state, ok := d.streams[id]; ok {
		state.Status = status
		state.ErrorMsg = errorMsg
		return nil
	}
	return errors.New("not found")
}
