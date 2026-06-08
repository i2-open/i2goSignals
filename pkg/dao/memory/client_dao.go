package memory

import (
	"context"
	"errors"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type ClientDAOMemory struct {
	store *StateManager[string, model.SsfClient]
}

func NewClientDAO() interfaces.ClientDAO {
	return &ClientDAOMemory{
		store: NewStateManager[string, model.SsfClient](func(c *model.SsfClient) *model.SsfClient {
			copyClient := *c
			return &copyClient
		}),
	}
}

func (d *ClientDAOMemory) Insert(_ context.Context, client *model.SsfClient) error {
	if client.Id.IsZero() {
		client.Id = bson.NewObjectID()
	}
	clientId := client.Id.Hex()
	d.store.Set(clientId, client)
	return nil
}

func (d *ClientDAOMemory) FindByID(_ context.Context, id string) (*model.SsfClient, error) {
	if client, ok := d.store.Get(id); ok {
		return client, nil
	}
	return nil, errors.New("client not found")
}

func (d *ClientDAOMemory) FindByProjectID(_ context.Context, projectID string) ([]*model.SsfClient, error) {
	clients := d.store.FindAll(func(client *model.SsfClient) bool {
		// Check if projectID is in the client's ProjectIds list
		for _, pid := range client.ProjectIds {
			if pid == projectID {
				return true
			}
		}
		return false
	})
	return clients, nil
}

func (d *ClientDAOMemory) Delete(_ context.Context, id string) error {
	if !d.store.Delete(id) {
		return errors.New("client not found")
	}
	return nil
}

func (d *ClientDAOMemory) GetState() map[string]*model.SsfClient {
	return d.store.GetAll()
}

func (d *ClientDAOMemory) SetState(state map[string]*model.SsfClient) {
	d.store.SetAll(state)
}
