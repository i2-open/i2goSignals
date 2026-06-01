package mongo

import (
	"context"
	"errors"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var tLog = logger.Sub("TOKEN_DAO")

type tokenRecordBson struct {
	JTI       any       `bson:"_id"`
	ClientID  any       `bson:"client_id,omitzero"`
	Subject   string    `bson:"subject,omitempty"`
	ProjectID string    `bson:"project_id"`
	Type      string    `bson:"type"`
	Scopes    []string  `bson:"scopes"`
	IssuedAt  time.Time `bson:"iat"`
	ExpiresAt time.Time `bson:"exp"`
	RevokedAt time.Time `bson:"revoked_at,omitzero"`
	Parent    any       `bson:"parent,omitzero"`

	LastRedemptionIP string    `bson:"last_redemption_ip,omitzero"`
	LastRedemptionAt time.Time `bson:"last_redemption_at,omitzero"`
	RedemptionCount  int64     `bson:"redemption_count,omitzero"`
}

func toBson(record *model.TokenRecord) *tokenRecordBson {
	return &tokenRecordBson{
		JTI:       ToFlexibleID(record.JTI),
		ClientID:  ToFlexibleID(record.ClientID),
		Subject:   record.Subject,
		ProjectID: record.ProjectID,
		Type:      record.Type,
		Scopes:    record.Scopes,
		IssuedAt:  record.IssuedAt,
		ExpiresAt: record.ExpiresAt,
		RevokedAt: record.RevokedAt,
		Parent:    ToFlexibleID(record.Parent),

		LastRedemptionIP: record.LastRedemptionIP,
		LastRedemptionAt: record.LastRedemptionAt,
		RedemptionCount:  record.RedemptionCount,
	}
}

func fromBson(b *tokenRecordBson) *model.TokenRecord {
	return &model.TokenRecord{
		JTI:       IDToString(b.JTI),
		ClientID:  IDToString(b.ClientID),
		Subject:   b.Subject,
		ProjectID: b.ProjectID,
		Type:      b.Type,
		Scopes:    b.Scopes,
		IssuedAt:  b.IssuedAt,
		ExpiresAt: b.ExpiresAt,
		RevokedAt: b.RevokedAt,
		Parent:    IDToString(b.Parent),

		LastRedemptionIP: b.LastRedemptionIP,
		LastRedemptionAt: b.LastRedemptionAt,
		RedemptionCount:  b.RedemptionCount,
	}
}

var errTokenNotInit = errors.New("mongo collection not initialized")

type TokenDAOMongo struct {
    ref collectionRef
}

func NewTokenDAO(collection *mongo.Collection) interfaces.TokenDAO {
    d := &TokenDAOMongo{}
    d.ref.set(collection)
    return d
}

func (d *TokenDAOMongo) SetCollection(c *mongo.Collection) {
    d.ref.set(c)
}

func (d *TokenDAOMongo) col() (*mongo.Collection, error) {
    c := d.ref.load()
    if c == nil {
        return nil, errTokenNotInit
    }
    return c, nil
}

func (d *TokenDAOMongo) Insert(ctx context.Context, record *model.TokenRecord) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    _, err = c.InsertOne(ctx, toBson(record))
    if err != nil {
        tLog.Error("Error inserting token record", "jti", record.JTI, "error", err)
    }
    return err
}

func (d *TokenDAOMongo) FindByJTI(ctx context.Context, jti string) (*model.TokenRecord, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    var recordBson tokenRecordBson
    err = c.FindOne(ctx, bson.M{"_id": ToFlexibleID(jti)}).Decode(&recordBson)
    if err != nil {
        err = HandleFindError(err, errors.New("token not found"))
        if err.Error() != "token not found" {
            tLog.Error("Error finding token record", "jti", jti, "error", err)
        }
        return nil, err
    }
    return fromBson(&recordBson), nil
}

func (d *TokenDAOMongo) Revoke(ctx context.Context, jti string) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    _, err = c.UpdateOne(ctx, bson.M{"_id": ToFlexibleID(jti)}, bson.M{"$set": bson.M{"revoked_at": time.Now().UTC()}})
    if err != nil {
        tLog.Error("Error revoking token record", "jti", jti, "error", err)
    }
    return err
}

func (d *TokenDAOMongo) RecordRedemption(ctx context.Context, jti string, ip string, at time.Time) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    _, err = c.UpdateOne(ctx,
        bson.M{"_id": ToFlexibleID(jti)},
        bson.M{
            "$inc": bson.M{"redemption_count": 1},
            "$set": bson.M{"last_redemption_ip": ip, "last_redemption_at": at},
        })
    if err != nil {
        tLog.Error("Error recording token redemption", "jti", jti, "error", err)
    }
    return err
}

func (d *TokenDAOMongo) DeleteExpired(ctx context.Context) error {
    c, err := d.col()
    if err != nil {
        return err
    }
    _, err = c.DeleteMany(ctx, bson.M{"exp": bson.M{"$lt": time.Now().UTC()}})
    if err != nil {
        tLog.Error("Error deleting expired tokens", "error", err)
    }
    return err
}

func (d *TokenDAOMongo) FindByProjectID(ctx context.Context, projectID string) ([]*model.TokenRecord, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    cursor, err := c.Find(ctx, bson.M{"project_id": projectID})
    if err != nil {
        tLog.Error("Error finding tokens by project", "projectID", projectID, "error", err)
        return nil, err
    }
    var bResults []*tokenRecordBson
    err = cursor.All(ctx, &bResults)
    if err != nil {
        tLog.Error("Error parsing tokens by project", "projectID", projectID, "error", err)
        return nil, err
    }
    results := make([]*model.TokenRecord, len(bResults))
    for i, b := range bResults {
        results[i] = fromBson(b)
    }
    return results, nil
}

func (d *TokenDAOMongo) FindByClientID(ctx context.Context, clientID string) ([]*model.TokenRecord, error) {
    c, err := d.col()
    if err != nil {
        return nil, err
    }
    cursor, err := c.Find(ctx, bson.M{"client_id": ToFlexibleID(clientID)})
    if err != nil {
        tLog.Error("Error finding tokens by client", "clientID", clientID, "error", err)
        return nil, err
    }
    var bResults []*tokenRecordBson
    err = cursor.All(ctx, &bResults)
    if err != nil {
        tLog.Error("Error parsing tokens by client", "clientID", clientID, "error", err)
        return nil, err
    }
    results := make([]*model.TokenRecord, len(bResults))
    for i, b := range bResults {
        results[i] = fromBson(b)
    }
    return results, nil
}
