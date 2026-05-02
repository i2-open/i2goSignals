package memory

import (
	"context"
	"errors"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

type StreamDAOMemory struct {
	store *StateManager[string, model.StreamStateRecord]
}

func NewStreamDAO() interfaces.StreamDAO {
	return &StreamDAOMemory{
		store: NewStateManager[string, model.StreamStateRecord](func(s *model.StreamStateRecord) *model.StreamStateRecord {
			return s.DeepCopy()
		}),
	}
}

func (d *StreamDAOMemory) Create(ctx context.Context, state *model.StreamStateRecord) error {
	d.store.Set(state.StreamConfiguration.Id, state)
	return nil
}

func (d *StreamDAOMemory) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	if state, ok := d.store.Get(id); ok {
		return state, nil
	}
	return nil, errors.New("stream not found")
}

func (d *StreamDAOMemory) Update(ctx context.Context, state *model.StreamStateRecord) error {
	if !d.store.Exists(state.StreamConfiguration.Id) {
		return errors.New("not found")
	}
	d.store.Set(state.StreamConfiguration.Id, state)
	return nil
}

func (d *StreamDAOMemory) Delete(ctx context.Context, id string) error {
	if !d.store.Delete(id) {
		return errors.New("not found")
	}
	return nil
}

func (d *StreamDAOMemory) List(ctx context.Context) ([]model.StreamStateRecord, error) {
	allStreams := d.store.GetAll()
	recs := make([]model.StreamStateRecord, 0, len(allStreams))
	for _, state := range allStreams {
		recs = append(recs, *state)
	}
	return recs, nil
}

func (d *StreamDAOMemory) FindByProjectID(ctx context.Context, projectID string) ([]model.StreamStateRecord, error) {
	matches := d.store.FindAll(func(state *model.StreamStateRecord) bool {
		return state.ProjectId == projectID
	})
	recs := make([]model.StreamStateRecord, 0, len(matches))
	for _, state := range matches {
		recs = append(recs, *state)
	}
	return recs, nil
}

func (d *StreamDAOMemory) FindReceiverStreams(ctx context.Context) ([]model.StreamStateRecord, error) {
	matches := d.store.FindAll(func(state *model.StreamStateRecord) bool {
		return state.IsReceiver()
	})
	recs := make([]model.StreamStateRecord, 0, len(matches))
	for _, state := range matches {
		recs = append(recs, *state)
	}
	return recs, nil
}

func (d *StreamDAOMemory) UpdateStatus(ctx context.Context, id string, status string, errorMsg string) error {
	if state, ok := d.store.Get(id); ok {
		state.Status = status
		state.ErrorMsg = errorMsg
		d.store.Set(id, state)
		return nil
	}
	return errors.New("not found")
}

func (d *StreamDAOMemory) UpdateRemoteAddress(ctx context.Context, id string, addr *model.RemoteIP) error {
	if state, ok := d.store.Get(id); ok {
		state.RemoteAddress = addr
		d.store.Set(id, state)
		return nil
	}
	return errors.New("not found")
}

func (d *StreamDAOMemory) GetState() map[string]*model.StreamStateRecord {
	return d.store.GetAll()
}

func (d *StreamDAOMemory) SetState(state map[string]*model.StreamStateRecord) {
	d.store.SetAll(state)
}
