package mongo

import (
    "context"
    "errors"

    interfaces "github.com/i2-open/i2goSignals/pkg/dao"
    "github.com/i2-open/i2goSignals/pkg/logger"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "go.mongodb.org/mongo-driver/v2/bson"
    "go.mongodb.org/mongo-driver/v2/mongo"
)

var svLog = logger.Sub("SERVER_DAO")

var errServerNotInit = errors.New("mongo collection not initialized")

type ServerDAOMongo struct {
    ref collectionRef
}

func NewServerDAO(collection *mongo.Collection) interfaces.ServerDAO {
    d := &ServerDAOMongo{}
    d.ref.set(collection)
    return d
}

func (d *ServerDAOMongo) SetCollection(c *mongo.Collection) {
    d.ref.set(c)
}

func (d *ServerDAOMongo) col() (*mongo.Collection, error) {
    c := d.ref.load()
    if c == nil {
        return nil, errServerNotInit
    }
    return c, nil
}

func (d *ServerDAOMongo) Create(ctx context.Context, server *model.Server) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    _, err = c.InsertOne(ctx, server)
    if err != nil {
        svLog.Error("Error inserting server", "error", err)
    }
    return err
}

func (d *ServerDAOMongo) FindByID(ctx context.Context, id string) (*model.Server, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    docId, err := ParseObjectID(id)
    if err != nil {
        return nil, err
    }

    filter := bson.M{"_id": docId}
    var server model.Server
    err = c.FindOne(ctx, filter).Decode(&server)
    if err != nil {
        err = HandleFindError(err, interfaces.ErrNotFound)
        if !errors.Is(err, interfaces.ErrNotFound) {
            svLog.Error("Error finding server", "id", id, "error", err)
        }
        return nil, err
    }
    return &server, nil
}

func (d *ServerDAOMongo) FindByAlias(ctx context.Context, alias string) (*model.Server, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    filter := bson.M{"alias": alias}
    var server model.Server
    err = c.FindOne(ctx, filter).Decode(&server)
    if err != nil {
        err = HandleFindError(err, interfaces.ErrNotFound)
        if !errors.Is(err, interfaces.ErrNotFound) {
            svLog.Error("Error finding server by alias", "alias", alias, "error", err)
        }
        return nil, err
    }
    return &server, nil
}

func (d *ServerDAOMongo) Update(ctx context.Context, server *model.Server) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    filter := bson.M{"_id": server.Id}
    res, err := c.ReplaceOne(ctx, filter, server)
    if err != nil {
        svLog.Error("Error updating server", "id", server.Id, "error", err)
        return err
    }
    return HandleUpdateResult(res, interfaces.ErrNotFound)
}

func (d *ServerDAOMongo) Delete(ctx context.Context, id string) error {
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
        svLog.Error("Error deleting server", "id", id, "error", err)
        return err
    }
    return HandleDeleteResult(res, interfaces.ErrNotFound)
}

func (d *ServerDAOMongo) List(ctx context.Context) ([]model.Server, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    cursor, err := c.Find(ctx, bson.D{})
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
