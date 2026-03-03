package mongo

import (
	"context"
	"errors"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var cLog = logger.Sub("CLIENT_DAO")

type ClientDAOMongo struct {
	collection *mongo.Collection
}

func NewClientDAO(collection *mongo.Collection) interfaces.ClientDAO {
	return &ClientDAOMongo{collection: collection}
}

func (d *ClientDAOMongo) Insert(ctx context.Context, client *model.SsfClient) error {
	_, err := d.collection.InsertOne(ctx, client)
	if err != nil {
		cLog.Error("Error inserting client", "error", err)
	}
	return err
}

func (d *ClientDAOMongo) FindByID(ctx context.Context, id string) (*model.SsfClient, error) {
	docId, err := ParseObjectID(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": docId}
	var client model.SsfClient
	err = d.collection.FindOne(ctx, filter).Decode(&client)
	if err != nil {
		err = HandleFindError(err, errors.New("client not found"))
		if err.Error() != "client not found" {
			cLog.Error("Error finding client", "id", id, "error", err)
		}
		return nil, err
	}
	return &client, nil
}

func (d *ClientDAOMongo) FindByProjectID(ctx context.Context, projectID string) ([]*model.SsfClient, error) {
	filter := bson.M{"project_id": projectID}
	cursor, err := d.collection.Find(ctx, filter)
	if err != nil {
		cLog.Error("Error finding clients by project", "projectID", projectID, "error", err)
		return nil, err
	}

	var clients []*model.SsfClient
	err = cursor.All(ctx, &clients)
	if err != nil {
		cLog.Error("Error parsing clients", "error", err)
		return nil, err
	}
	return clients, nil
}

func (d *ClientDAOMongo) Delete(ctx context.Context, id string) error {
	docId, err := ParseObjectID(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": docId}
	res, err := d.collection.DeleteOne(ctx, filter)
	if err != nil {
		cLog.Error("Error deleting client", "id", id, "error", err)
		return err
	}

	return HandleDeleteResult(res, errors.New("client not found"))
}
