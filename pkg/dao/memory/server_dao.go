package memory

import (
	"context"
	"errors"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type ServerDAOMemory struct {
	store *StateManager[string, model.Server]
}

func NewServerDAO() interfaces.ServerDAO {
	return &ServerDAOMemory{
		store: NewStateManager[string, model.Server](func(s *model.Server) *model.Server {
			return s.DeepCopy()
		}),
	}
}

func (d *ServerDAOMemory) Create(ctx context.Context, server *model.Server) error {
	if server.Alias == "" {
		return errors.New("alias is required")
	}

	// Check for duplicate alias
	if existing, found := d.store.FindFirst(func(s *model.Server) bool {
		return s.Alias == server.Alias
	}); found && existing != nil {
		return errors.New("server with this alias already exists")
	}

	if server.Id.IsZero() {
		server.Id = bson.NewObjectID()
	}

	d.store.Set(server.Id.Hex(), server)
	return nil
}

func (d *ServerDAOMemory) FindByID(ctx context.Context, id string) (*model.Server, error) {
	if server, ok := d.store.Get(id); ok {
		return server, nil
	}
	return nil, interfaces.ErrNotFound
}

func (d *ServerDAOMemory) FindByAlias(ctx context.Context, alias string) (*model.Server, error) {
	if server, ok := d.store.FindFirst(func(s *model.Server) bool {
		return s.Alias == alias
	}); ok {
		return server, nil
	}
	return nil, interfaces.ErrNotFound
}

func (d *ServerDAOMemory) Update(ctx context.Context, server *model.Server) error {
	id := server.Id.Hex()
	if !d.store.Exists(id) {
		return interfaces.ErrNotFound
	}

	// Check if alias is being changed to an existing one
	if existing, found := d.store.FindFirst(func(s *model.Server) bool {
		return s.Id != server.Id && s.Alias == server.Alias
	}); found && existing != nil {
		return errors.New("server with this alias already exists")
	}

	d.store.Set(id, server)
	return nil
}

func (d *ServerDAOMemory) Delete(ctx context.Context, id string) error {
	if !d.store.Delete(id) {
		return interfaces.ErrNotFound
	}
	return nil
}

func (d *ServerDAOMemory) List(ctx context.Context) ([]model.Server, error) {
	allServers := d.store.GetAll()
	servers := make([]model.Server, 0, len(allServers))
	for _, s := range allServers {
		servers = append(servers, *s)
	}
	return servers, nil
}

func (d *ServerDAOMemory) GetState() map[string]*model.Server {
	return d.store.GetAll()
}

func (d *ServerDAOMemory) SetState(state map[string]*model.Server) {
	d.store.SetAll(state)
}
