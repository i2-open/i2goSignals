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

var errClientNotInit = errors.New("mongo collection not initialized")

type ClientDAOMongo struct {
    ref collectionRef
}

func NewClientDAO(collection *mongo.Collection) interfaces.ClientDAO {
    d := &ClientDAOMongo{}
    d.ref.set(collection)
    return d
}

func (d *ClientDAOMongo) SetCollection(c *mongo.Collection) {
    d.ref.set(c)
}

func (d *ClientDAOMongo) col() (*mongo.Collection, error) {
    c := d.ref.load()
    if c == nil {
        return nil, errClientNotInit
    }
    return c, nil
}

func (d *ClientDAOMongo) Insert(ctx context.Context, client *model.SsfClient) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    _, err = c.InsertOne(ctx, client)
    if err != nil {
        cLog.Error("Error inserting client", "error", err)
    }
    return err
}

func (d *ClientDAOMongo) FindByID(ctx context.Context, id string) (*model.SsfClient, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    docId, err := ParseObjectID(id)
    if err != nil {
        return nil, err
    }

    filter := bson.M{"_id": docId}
    var client model.SsfClient
    err = c.FindOne(ctx, filter).Decode(&client)
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
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"project_id": projectID}
    cursor, err := c.Find(ctx, filter)
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
    c, err := d.col()
    if err != nil {
        return err
    }
    docId, err := ParseObjectID(id)
    if err != nil {
        return err
    }

    filter := bson.M{"_id": docId}
    res, err := c.DeleteOne(ctx, filter)
    if err != nil {
        cLog.Error("Error deleting client", "id", id, "error", err)
        return err
    }
    return HandleDeleteResult(res, errors.New("client not found"))
}
