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

var sLog = logger.Sub("STREAM_DAO")

type StreamDAOMongo struct {
	collection *mongo.Collection
}

func NewStreamDAO(collection *mongo.Collection) interfaces.StreamDAO {
	return &StreamDAOMongo{collection: collection}
}

func (d *StreamDAOMongo) Create(ctx context.Context, state *model.StreamStateRecord) error {
	_, err := d.collection.InsertOne(ctx, state)
	if err != nil {
		sLog.Error("Error inserting stream", "error", err)
	}
	return err
}

func (d *StreamDAOMongo) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	docId, err := ParseObjectID(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": docId}
	res := d.collection.FindOne(ctx, filter)

	if err := HandleFindError(res.Err(), errors.New("not found")); err != nil {
		return nil, err
	}

	var rec model.StreamStateRecord
	err = res.Decode(&rec)
	if err != nil {
		sLog.Error("Error parsing StreamStateRecord", "error", err)
		return nil, err
	}
	return &rec, nil
}

func (d *StreamDAOMongo) Update(ctx context.Context, state *model.StreamStateRecord) error {
	filter := bson.M{"_id": state.Id}
	res, err := d.collection.ReplaceOne(ctx, filter, state)
	if err != nil {
		return errors.New("stream update error: " + err.Error())
	}

	return HandleUpdateResult(res, errors.New("not found"))
}

func (d *StreamDAOMongo) Delete(ctx context.Context, id string) error {
	docId, err := ParseObjectID(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": docId}
	resp, err := d.collection.DeleteOne(ctx, filter)
	if err != nil {
		return err
	}

	return HandleDeleteResult(resp, errors.New("not found"))
}

func (d *StreamDAOMongo) List(ctx context.Context) ([]model.StreamStateRecord, error) {
	cursor, err := d.collection.Find(ctx, bson.D{})
	if err != nil {
		sLog.Error("Error listing Stream Configs", "error", err)
		return nil, err
	}

	var recs []model.StreamStateRecord
	err = cursor.All(ctx, &recs)
	if err != nil {
		sLog.Error("Error parsing Stream Configs", "error", err)
		return nil, err
	}
	return recs, nil
}

func (d *StreamDAOMongo) FindByProjectID(ctx context.Context, projectID string) ([]model.StreamStateRecord, error) {
	filter := bson.M{"project_id": projectID}
	cursor, err := d.collection.Find(ctx, filter)
	if err != nil {
		sLog.Error("Error finding streams by project", "projectID", projectID, "error", err)
		return nil, err
	}

	var recs []model.StreamStateRecord
	err = cursor.All(ctx, &recs)
	if err != nil {
		sLog.Error("Error parsing Stream Configs", "error", err)
		return nil, err
	}
	return recs, nil
}

func (d *StreamDAOMongo) FindReceiverStreams(ctx context.Context) ([]model.StreamStateRecord, error) {
	// Receiver streams have RouteMode = "import"
	filter := bson.M{"route_mode": model.RouteModeImport}
	cursor, err := d.collection.Find(ctx, filter)
	if err != nil {
		sLog.Error("Error finding receiver streams", "error", err)
		return nil, err
	}

	var recs []model.StreamStateRecord
	err = cursor.All(ctx, &recs)
	if err != nil {
		sLog.Error("Error parsing receiver streams", "error", err)
		return nil, err
	}
	return recs, nil
}

func (d *StreamDAOMongo) UpdateStatus(ctx context.Context, id string, status string, errorMsg string) error {
	docId, err := ParseObjectID(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": docId}
	update := bson.M{
		"$set": bson.M{
			"status":    status,
			"error_msg": errorMsg,
		},
	}

	res, err := d.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		sLog.Error("Error updating stream status", "error", err)
		return err
	}

	return HandleUpdateResult(res, errors.New("not found"))
}
