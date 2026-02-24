package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/model"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type ServerDAOMemory struct {
	mu      sync.RWMutex
	servers map[string]*model.Server
}

func NewServerDAO() interfaces.ServerDAO {
	return &ServerDAOMemory{
		servers: make(map[string]*model.Server),
	}
}

func (d *ServerDAOMemory) Create(ctx context.Context, server *model.Server) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if server.Alias == "" {
		return errors.New("alias is required")
	}

	for _, s := range d.servers {
		if s.Alias == server.Alias {
			return errors.New("server with this alias already exists")
		}
	}

	if server.Id.IsZero() {
		server.Id = bson.NewObjectID()
	}

	d.servers[server.Id.Hex()] = server.DeepCopy()
	return nil
}

func (d *ServerDAOMemory) FindByID(ctx context.Context, id string) (*model.Server, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if server, ok := d.servers[id]; ok {
		return server.DeepCopy(), nil
	}
	return nil, interfaces.ErrNotFound
}

func (d *ServerDAOMemory) FindByAlias(ctx context.Context, alias string) (*model.Server, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, server := range d.servers {
		if server.Alias == alias {
			return server.DeepCopy(), nil
		}
	}
	return nil, interfaces.ErrNotFound
}

func (d *ServerDAOMemory) Update(ctx context.Context, server *model.Server) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	id := server.Id.Hex()
	if _, exists := d.servers[id]; !exists {
		return interfaces.ErrNotFound
	}

	// Check if alias is being changed to an existing one
	for _, s := range d.servers {
		if s.Id != server.Id && s.Alias == server.Alias {
			return errors.New("server with this alias already exists")
		}
	}

	d.servers[id] = server.DeepCopy()
	return nil
}

func (d *ServerDAOMemory) Delete(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.servers[id]; !exists {
		return interfaces.ErrNotFound
	}
	delete(d.servers, id)
	return nil
}

func (d *ServerDAOMemory) List(ctx context.Context) ([]model.Server, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var servers []model.Server
	for _, s := range d.servers {
		servers = append(servers, *s.DeepCopy())
	}
	return servers, nil
}

func (d *ServerDAOMemory) GetState() map[string]*model.Server {
	d.mu.RLock()
	defer d.mu.RUnlock()

	res := make(map[string]*model.Server)
	for k, v := range d.servers {
		res[k] = v.DeepCopy()
	}
	return res
}

func (d *ServerDAOMemory) SetState(state map[string]*model.Server) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.servers = state
}
