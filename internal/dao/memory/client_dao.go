package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ClientDAOMemory struct {
	mu      sync.RWMutex
	clients map[string]*model.SsfClient
}

func NewClientDAO() interfaces.ClientDAO {
	return &ClientDAOMemory{
		clients: make(map[string]*model.SsfClient),
	}
}

func (d *ClientDAOMemory) Insert(ctx context.Context, client *model.SsfClient) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if client.Id.IsZero() {
		client.Id = primitive.NewObjectID()
	}
	clientId := client.Id.Hex()
	d.clients[clientId] = client
	return nil
}

func (d *ClientDAOMemory) FindByID(ctx context.Context, id string) (*model.SsfClient, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if client, ok := d.clients[id]; ok {
		copy := *client
		return &copy, nil
	}
	return nil, errors.New("client not found")
}

func (d *ClientDAOMemory) FindByProjectID(ctx context.Context, projectID string) ([]*model.SsfClient, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var clients []*model.SsfClient
	for _, client := range d.clients {
		// Check if projectID is in the client's ProjectIds list
		for _, pid := range client.ProjectIds {
			if pid == projectID {
				copy := *client
				clients = append(clients, &copy)
				break
			}
		}
	}
	return clients, nil
}

func (d *ClientDAOMemory) Delete(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.clients[id]; !exists {
		return errors.New("client not found")
	}
	delete(d.clients, id)
	return nil
}
