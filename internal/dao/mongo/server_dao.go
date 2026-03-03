package mongo

import (
	"context"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var svLog = logger.Sub("SERVER_DAO")

type ServerDAOMongo struct {
	collection *mongo.Collection
}

func NewServerDAO(collection *mongo.Collection) interfaces.ServerDAO {
	return &ServerDAOMongo{collection: collection}
}

func (d *ServerDAOMongo) Create(ctx context.Context, server *model.Server) error {
	_, err := d.collection.InsertOne(ctx, server)
	if err != nil {
		svLog.Error("Error inserting server", "error", err)
	}
	return err
}

func (d *ServerDAOMongo) FindByID(ctx context.Context, id string) (*model.Server, error) {
	docId, err := ParseObjectID(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": docId}
	var server model.Server
	err = d.collection.FindOne(ctx, filter).Decode(&server)
	if err != nil {
		err = HandleFindError(err, interfaces.ErrNotFound)
		if err != interfaces.ErrNotFound {
			svLog.Error("Error finding server", "id", id, "error", err)
		}
		return nil, err
	}
	return &server, nil
}

func (d *ServerDAOMongo) FindByAlias(ctx context.Context, alias string) (*model.Server, error) {
	filter := bson.M{"alias": alias}
	var server model.Server
	err := d.collection.FindOne(ctx, filter).Decode(&server)
	if err != nil {
		err = HandleFindError(err, interfaces.ErrNotFound)
		if err != interfaces.ErrNotFound {
			svLog.Error("Error finding server by alias", "alias", alias, "error", err)
		}
		return nil, err
	}
	return &server, nil
}

func (d *ServerDAOMongo) Update(ctx context.Context, server *model.Server) error {
	filter := bson.M{"_id": server.Id}
	res, err := d.collection.ReplaceOne(ctx, filter, server)
	if err != nil {
		svLog.Error("Error updating server", "id", server.Id, "error", err)
		return err
	}

	return HandleUpdateResult(res, interfaces.ErrNotFound)
}

func (d *ServerDAOMongo) Delete(ctx context.Context, id string) error {
	docId, err := ParseObjectID(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": docId}
	res, err := d.collection.DeleteOne(ctx, filter)
	if err != nil {
		svLog.Error("Error deleting server", "id", id, "error", err)
		return err
	}

	return HandleDeleteResult(res, interfaces.ErrNotFound)
}

func (d *ServerDAOMongo) List(ctx context.Context) ([]model.Server, error) {
	cursor, err := d.collection.Find(ctx, bson.D{})
	if err != nil {
		svLog.Error("Error listing servers", "error", err)
		return nil, err
	}

	var servers []model.Server
	err = cursor.All(ctx, &servers)
	if err != nil {
		svLog.Error("Error parsing servers", "error", err)
		return nil, err
	}
	return servers, nil
}
