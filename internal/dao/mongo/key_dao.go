package mongo

import (
	"context"
	"errors"
	"slices"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var kLog = logger.Sub("KEY_DAO")

type KeyDAOMongo struct {
	collection *mongo.Collection
}

func NewKeyDAO(collection *mongo.Collection) interfaces.KeyDAO {
	return &KeyDAOMongo{collection: collection}
}

func (d *KeyDAOMongo) Insert(ctx context.Context, keyRec *interfaces.JwkKeyRec) error {
	_, err := d.collection.InsertOne(ctx, keyRec)
	if err != nil {
		kLog.Error("Error inserting key", "error", err)
	}
	return err
}

func (d *KeyDAOMongo) FindByKid(ctx context.Context, kid string) (*interfaces.JwkKeyRec, error) {
	filter := bson.M{"kid": kid}
	res := d.collection.FindOne(ctx, filter)

	var rec interfaces.JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, interfaces.ErrKeyNotFound
		}
		kLog.Error("Error finding key by kid", "kid", kid, "error", err)
		return nil, err
	}
	return &rec, nil
}

func (d *KeyDAOMongo) FindByKeyName(ctx context.Context, keyName string) ([]*interfaces.JwkKeyRec, error) {
	filter := bson.M{"key_name": keyName}
	cursor, err := d.collection.Find(ctx, filter)
	if err != nil {
		kLog.Error("Error retrieving keys for keyName", "keyName", keyName, "error", err)
		return nil, err
	}

	var keys []*interfaces.JwkKeyRec
	err = cursor.All(ctx, &keys)
	if err != nil {
		kLog.Error("Error parsing JwkKeyRec", "error", err)
		return nil, err
	}
	return keys, nil
}

func (d *KeyDAOMongo) FindLatestByKeyName(ctx context.Context, keyName string) (*interfaces.JwkKeyRec, error) {
	filter := bson.M{"key_name": keyName}
	opts := options.FindOne().SetSort(bson.M{"_id": -1}) // Newest first based on ObjectID

	res := d.collection.FindOne(ctx, filter, opts)

	var rec interfaces.JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, interfaces.ErrKeyNotFound
		}
		kLog.Error("Error parsing JwkKeyRec for keyName", "keyName", keyName, "error", err)
		return nil, err
	}

	if len(rec.KeyBytes) == 0 {
		return nil, interfaces.ErrKeyNotFound
	}

	return &rec, nil
}

func (d *KeyDAOMongo) FindByStreamID(ctx context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	filter := bson.M{"stream_id": streamID}
	res := d.collection.FindOne(ctx, filter)

	var rec interfaces.JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		kLog.Error("Error locating key by streamId", "streamId", streamID, "error", err)
		return nil, err
	}
	return &rec, nil
}

func (d *KeyDAOMongo) DeleteByKid(ctx context.Context, kid string) error {
	filter := bson.M{"kid": kid}
	res, err := d.collection.DeleteOne(ctx, filter)
	if err != nil {
		kLog.Error("Error deleting key by kid", "kid", kid, "error", err)
		return err
	}
	if res.DeletedCount == 0 {
		return interfaces.ErrKeyNotFound
	}
	return nil
}

func (d *KeyDAOMongo) DeleteByKeyName(ctx context.Context, keyName string) error {
	filter := bson.M{"key_name": keyName}
	res := d.collection.FindOne(ctx, filter)
	if res.Err() != nil {
		err := res.Err()
		if errors.Is(err, mongo.ErrNoDocuments) {
			return interfaces.ErrKeyNotFound
		}
		return err
	}

	delResult, err := d.collection.DeleteMany(ctx, filter)
	if err != nil {
		kLog.Error("Error deleting keys for keyName", "keyName", keyName, "error", err)
		return err
	}

	if delResult.DeletedCount == 0 {
		return interfaces.ErrKeyNotFound
	}

	kLog.Info("Deleted keys for keyName", "keyName", keyName, "count", delResult.DeletedCount)
	return nil
}

func (d *KeyDAOMongo) ListKids(ctx context.Context) ([]string, error) {
	cursor, err := d.collection.Find(ctx, bson.M{})
	if err != nil {
		kLog.Error("Error listing kids", "error", err)
		return nil, err
	}

	var keys []*interfaces.JwkKeyRec
	err = cursor.All(ctx, &keys)
	if err != nil {
		kLog.Error("Error parsing keys for kid list", "error", err)
		return nil, err
	}

	kids := make([]string, 0, len(keys))
	for _, key := range keys {
		if key.Kid != "" {
			kids = append(kids, key.Kid)
		}
	}
	return kids, nil
}

func (d *KeyDAOMongo) ListKeyNames(ctx context.Context) ([]string, error) {
	cursor, err := d.collection.Find(ctx, bson.D{})
	if err != nil {
		kLog.Error("Error retrieving key names", "error", err)
		return nil, err
	}

	var keys []*interfaces.JwkKeyRec
	err = cursor.All(ctx, &keys)
	if err != nil {
		kLog.Error("Error parsing key names", "error", err)
		return nil, err
	}

	// There can be more than one key for a particular keyname
	var names []string
	for _, key := range keys {
		keyName := key.KeyName
		if !slices.Contains(names, keyName) {
			names = append(names, keyName)
		}
	}

	return names, nil
}

func (d *KeyDAOMongo) KeySummary(ctx context.Context, keyName string) (*interfaces.KeySummary, error) {
	recs, err := d.FindByKeyName(ctx, keyName)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, nil
	}
	// If multiple keys are returned assume it is rotated.  Just produce one summary for all.
	firstKey := recs[0]
	var kids []string
	for _, rec := range recs {
		kids = append(kids, rec.Kid)
	}
	summary := firstKey.ToSummary()
	summary.Kids = kids
	summary.Rotations = len(recs) - 1
	return &summary, nil
}

func (d *KeyDAOMongo) ListSummaries(ctx context.Context) ([]interfaces.KeySummary, error) {

	names, err := d.ListKeyNames(ctx)
	if err != nil {
		return nil, err
	}

	var summaries []interfaces.KeySummary
	for _, name := range names {
		summary, err := d.KeySummary(ctx, name)
		if err != nil {
			return nil, err
		}
		if summary == nil {
			kLog.Error("Received unexpected nil summary", "keyName", name)
			continue
		}
		summaries = append(summaries, *summary)
	}

	return summaries, nil
}
