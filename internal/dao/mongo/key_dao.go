package mongo

import (
	"context"
	"errors"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/logger"
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

func (d *KeyDAOMongo) FindByIssuer(ctx context.Context, issuer string) ([]*interfaces.JwkKeyRec, error) {
	filter := bson.M{"iss": issuer}
	cursor, err := d.collection.Find(ctx, filter)
	if err != nil {
		kLog.Error("Error retrieving keys for issuer", "issuer", issuer, "error", err)
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

func (d *KeyDAOMongo) FindLatestByIssuer(ctx context.Context, issuer string) (*interfaces.JwkKeyRec, error) {
	filter := bson.M{"iss": issuer}
	opts := options.FindOne().SetSort(bson.M{"_id": -1}) // Newest first based on ObjectID

	res := d.collection.FindOne(ctx, filter, opts)

	var rec interfaces.JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, interfaces.ErrKeyNotFound
		}
		kLog.Error("Error parsing JwkKeyRec for issuer", "issuer", issuer, "error", err)
		return nil, err
	}

	if len(rec.KeyBytes) == 0 {
		return nil, interfaces.ErrKeyNotFound
	}

	return &rec, nil
}

func (d *KeyDAOMongo) DeleteByIssuer(ctx context.Context, issuer string) error {
	filter := bson.M{"iss": issuer}
	res := d.collection.FindOne(ctx, filter)
	if res.Err() != nil {
		err := res.Err()
		if errors.Is(err, mongo.ErrNoDocuments) {
			return interfaces.ErrKeyNotFound
		}
		return err
	}

	delResult, err := d.collection.DeleteOne(ctx, filter)
	if err != nil {
		kLog.Error("Error deleting issuer keys for issuer", "issuer", issuer, "error", err)
		return err
	}

	if delResult.DeletedCount == 0 {
		return interfaces.ErrKeyNotFound
	}

	kLog.Info("Deleted issuer keys for issuer", "issuer", issuer)
	return nil
}

func (d *KeyDAOMongo) ListIssuers(ctx context.Context) ([]string, error) {
	cursor, err := d.collection.Find(ctx, bson.D{})
	if err != nil {
		kLog.Error("Error retrieving issuer keys", "error", err)
		return nil, err
	}

	var keys []*interfaces.JwkKeyRec
	err = cursor.All(ctx, &keys)
	if err != nil {
		kLog.Error("Error parsing issuer keys", "error", err)
		return nil, err
	}

	issuers := make([]string, 0, len(keys))
	for _, key := range keys {
		if key.Iss != "" {
			issuers = append(issuers, key.Iss)
		}
	}

	return issuers, nil
}

func (d *KeyDAOMongo) InsertReceiverKey(ctx context.Context, streamID string, audience string, jwksUri string) error {
	keyPairRec := interfaces.JwkKeyRec{
		Id:              bson.NewObjectID(),
		Aud:             audience,
		StreamId:        streamID,
		ReceiverJwksUrl: jwksUri,
	}

	_, err := d.collection.InsertOne(ctx, &keyPairRec)
	return err
}

func (d *KeyDAOMongo) FindReceiverKeyByStreamID(ctx context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	filter := bson.M{"stream_id": streamID}
	res := d.collection.FindOne(ctx, filter)

	var rec interfaces.JwkKeyRec
	err := res.Decode(&rec)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		kLog.Error("Error locating receiver key", "streamId", streamID, "error", err)
		return nil, err
	}
	return &rec, nil
}
