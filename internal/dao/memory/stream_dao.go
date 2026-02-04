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

	d.streams[state.StreamConfiguration.Id] = state.DeepCopy()
	return nil
}

func (d *StreamDAOMemory) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if state, ok := d.streams[id]; ok {
		return state.DeepCopy(), nil
	}
	return nil, errors.New("stream not found")
}

func (d *StreamDAOMemory) Update(ctx context.Context, state *model.StreamStateRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.streams[state.StreamConfiguration.Id]; !exists {
		return errors.New("not found")
	}
	d.streams[state.StreamConfiguration.Id] = state.DeepCopy()
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
		recs = append(recs, *state.DeepCopy())
	}
	return recs, nil
}

func (d *StreamDAOMemory) FindByProjectID(ctx context.Context, projectID string) ([]model.StreamStateRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var recs []model.StreamStateRecord
	for _, state := range d.streams {
		if state.ProjectId == projectID {
			recs = append(recs, *state.DeepCopy())
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
			recs = append(recs, *state.DeepCopy())
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

func (d *StreamDAOMemory) GetState() map[string]*model.StreamStateRecord {
	d.mu.RLock()
	defer d.mu.RUnlock()

	res := make(map[string]*model.StreamStateRecord)
	for k, v := range d.streams {
		res[k] = v.DeepCopy()
	}
	return res
}

func (d *StreamDAOMemory) SetState(state map[string]*model.StreamStateRecord) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.streams = state
}
