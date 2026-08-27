package mongo

import (
	"context"
	"errors"
	"slices"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var kLog = logger.Sub("KEY_DAO")

// keyDoc is the on-disk shape of a JwkKeyRec inside Mongo. _id stays as
// bson.ObjectID for backward compatibility with existing data; the public
// JwkKeyRec exposes Id as a string and converts at the boundary.
type keyDoc struct {
	Id              bson.ObjectID `bson:"_id"`
	KeyName         string        `bson:"key_name"`
	Kid             string        `bson:"kid"`
	Use             string        `bson:"use"`
	ProjectId       string        `bson:"project_id"`
	StreamId        string        `bson:"stream_id"`
	KeyBytes        []byte        `bson:"key_bytes"`
	PubKeyBytes     []byte        `bson:"pub_jwks"`
	ReceiverJwksUrl string        `bson:"receiver_jwks_url"`
	// Alg discriminates the key material's algorithm (see JwkKeyRec.Alg).
	// omitempty keeps it absent from RSA documents, which is exactly how
	// pre-existing documents decode: "" => RSA.
	Alg string `bson:"alg,omitempty"`
	// Lifecycle timestamps (ADR 0028). omitzero keeps them absent from
	// pre-existing documents, which decode as the zero time => active.
	SuspendedAt time.Time `bson:"suspended_at,omitzero"`
	RevokedAt   time.Time `bson:"revoked_at,omitzero"`
}

func (d *keyDoc) toRec() *interfaces.JwkKeyRec {
	return &interfaces.JwkKeyRec{
		Id:              d.Id.Hex(),
		KeyName:         d.KeyName,
		Kid:             d.Kid,
		Use:             d.Use,
		ProjectId:       d.ProjectId,
		StreamId:        d.StreamId,
		KeyBytes:        d.KeyBytes,
		PubKeyBytes:     d.PubKeyBytes,
		ReceiverJwksUrl: d.ReceiverJwksUrl,
		Alg:             d.Alg,
		SuspendedAt:     d.SuspendedAt,
		RevokedAt:       d.RevokedAt,
	}
}

func recToDoc(rec *interfaces.JwkKeyRec) (*keyDoc, error) {
	oid, err := ParseObjectID(rec.Id)
	if err != nil {
		return nil, err
	}
	return &keyDoc{
		Id:              oid,
		KeyName:         rec.KeyName,
		Kid:             rec.Kid,
		Use:             rec.Use,
		ProjectId:       rec.ProjectId,
		StreamId:        rec.StreamId,
		KeyBytes:        rec.KeyBytes,
		PubKeyBytes:     rec.PubKeyBytes,
		ReceiverJwksUrl: rec.ReceiverJwksUrl,
		Alg:             rec.Alg,
		SuspendedAt:     rec.SuspendedAt,
		RevokedAt:       rec.RevokedAt,
	}, nil
}

var errKeyNotInit = errors.New("mongo collection not initialized")

type KeyDAOMongo struct {
	ref collectionRef
}

func NewKeyDAO(collection *mongo.Collection) interfaces.KeyDAO {
	d := &KeyDAOMongo{}
	d.ref.set(collection)
	return d
}

func (d *KeyDAOMongo) SetCollection(c *mongo.Collection) {
	d.ref.set(c)
}

func (d *KeyDAOMongo) col() (*mongo.Collection, error) {
	c := d.ref.load()
	if c == nil {
		return nil, errKeyNotInit
	}
	return c, nil
}

func (d *KeyDAOMongo) Insert(ctx context.Context, keyRec *interfaces.JwkKeyRec) error {
	c, err := d.col()
	if err != nil {
		return err
	}
	if keyRec.Id == "" {
		keyRec.Id = ids.NewObjectID()
	}
	doc, err := recToDoc(keyRec)
	if err != nil {
		return err
	}
	_, err = c.InsertOne(ctx, doc)
	if err != nil {
		kLog.Error("Error inserting key", "error", err)
	}
	return err
}

func (d *KeyDAOMongo) FindByKid(ctx context.Context, kid string) (*interfaces.JwkKeyRec, error) {
	c, err := d.col()
	if err != nil {
		return nil, err
	}
	filter := bson.M{"kid": kid}
	res := c.FindOne(ctx, filter)

	var doc keyDoc
	err = res.Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, interfaces.ErrKeyNotFound
		}
		kLog.Error("Error finding key by kid", "kid", kid, "error", err)
		return nil, err
	}
	return doc.toRec(), nil
}

func (d *KeyDAOMongo) FindByKeyName(ctx context.Context, keyName string) ([]*interfaces.JwkKeyRec, error) {
	c, err := d.col()
	if err != nil {
		return nil, err
	}
	filter := bson.M{"key_name": keyName}
	cursor, err := c.Find(ctx, filter)
	if err != nil {
		kLog.Error("Error retrieving keys for keyName", "keyName", keyName, "error", err)
		return nil, err
	}

	var docs []keyDoc
	err = cursor.All(ctx, &docs)
	if err != nil {
		kLog.Error("Error parsing JwkKeyRec", "error", err)
		return nil, err
	}
	keys := make([]*interfaces.JwkKeyRec, len(docs))
	for i := range docs {
		keys[i] = docs[i].toRec()
	}
	return keys, nil
}

func (d *KeyDAOMongo) FindLatestByKeyName(ctx context.Context, keyName string) (*interfaces.JwkKeyRec, error) {
	c, err := d.col()
	if err != nil {
		return nil, err
	}
	filter := bson.M{"key_name": keyName}
	opts := options.FindOne().SetSort(bson.M{"_id": -1}) // Newest first based on ObjectID

	res := c.FindOne(ctx, filter, opts)

	var doc keyDoc
	err = res.Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, interfaces.ErrKeyNotFound
		}
		kLog.Error("Error parsing JwkKeyRec for keyName", "keyName", keyName, "error", err)
		return nil, err
	}

	if len(doc.KeyBytes) == 0 {
		return nil, interfaces.ErrKeyNotFound
	}

	return doc.toRec(), nil
}

func (d *KeyDAOMongo) FindByStreamID(ctx context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	c, err := d.col()
	if err != nil {
		return nil, err
	}
	filter := bson.M{"stream_id": streamID}
	res := c.FindOne(ctx, filter)

	var doc keyDoc
	err = res.Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		kLog.Error("Error locating key by streamId", "streamId", streamID, "error", err)
		return nil, err
	}
	return doc.toRec(), nil
}

func (d *KeyDAOMongo) DeleteByKid(ctx context.Context, kid string) error {
	c, err := d.col()
	if err != nil {
		return err
	}
	filter := bson.M{"kid": kid}
	res, err := c.DeleteOne(ctx, filter)
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
	c, err := d.col()
	if err != nil {
		return err
	}
	filter := bson.M{"key_name": keyName}
	res := c.FindOne(ctx, filter)
	if res.Err() != nil {
		err := res.Err()
		if errors.Is(err, mongo.ErrNoDocuments) {
			return interfaces.ErrKeyNotFound
		}
		return err
	}

	delResult, err := c.DeleteMany(ctx, filter)
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

func (d *KeyDAOMongo) SetKeyStatus(ctx context.Context, keyName string, kid string, suspendedAt *time.Time, revokedAt *time.Time) (int, error) {
	c, err := d.col()
	if err != nil {
		return 0, err
	}

	filter := bson.M{"key_name": keyName}
	if kid != "" {
		filter["kid"] = kid
	}

	set := bson.M{}
	if suspendedAt != nil {
		set["suspended_at"] = *suspendedAt
	}

	total := 0
	if len(set) > 0 {
		res, err := c.UpdateMany(ctx, filter, bson.M{"$set": set})
		if err != nil {
			kLog.Error("Error updating key status", "keyName", keyName, "kid", kid, "error", err)
			return 0, err
		}
		total = int(res.MatchedCount)
	}

	// RevokedAt is write-once: only stamp records that do not already carry one.
	if revokedAt != nil {
		revFilter := bson.M{"key_name": keyName, "revoked_at": bson.M{"$in": bson.A{nil, time.Time{}}}}
		if kid != "" {
			revFilter["kid"] = kid
		}
		res, err := c.UpdateMany(ctx, revFilter, bson.M{"$set": bson.M{"revoked_at": *revokedAt}})
		if err != nil {
			kLog.Error("Error revoking key", "keyName", keyName, "kid", kid, "error", err)
			return 0, err
		}
		if len(set) == 0 {
			// No suspension change was requested, so the matched count for this
			// operation is our best measure of affected records. When some are
			// already revoked (excluded by revFilter) fall back to a plain match.
			total = int(res.MatchedCount)
			if total == 0 {
				cnt, cerr := c.CountDocuments(ctx, filter)
				if cerr != nil {
					return 0, cerr
				}
				total = int(cnt)
			}
		}
	}

	if total == 0 {
		return 0, interfaces.ErrKeyNotFound
	}
	return total, nil
}

func (d *KeyDAOMongo) ListKids(ctx context.Context) ([]string, error) {
	c, err := d.col()
	if err != nil {
		return nil, err
	}
	cursor, err := c.Find(ctx, bson.M{})
	if err != nil {
		kLog.Error("Error listing kids", "error", err)
		return nil, err
	}

	var docs []keyDoc
	err = cursor.All(ctx, &docs)
	if err != nil {
		kLog.Error("Error parsing keys for kid list", "error", err)
		return nil, err
	}

	kids := make([]string, 0, len(docs))
	for _, doc := range docs {
		if doc.Kid != "" {
			kids = append(kids, doc.Kid)
		}
	}
	return kids, nil
}

func (d *KeyDAOMongo) ListKeyNames(ctx context.Context) ([]string, error) {
	c, err := d.col()
	if err != nil {
		return nil, err
	}
	cursor, err := c.Find(ctx, bson.D{})
	if err != nil {
		kLog.Error("Error retrieving key names", "error", err)
		return nil, err
	}

	var docs []keyDoc
	err = cursor.All(ctx, &docs)
	if err != nil {
		kLog.Error("Error parsing key names", "error", err)
		return nil, err
	}

	// There can be more than one key for a particular keyname
	var names []string
	for _, doc := range docs {
		if !slices.Contains(names, doc.KeyName) {
			names = append(names, doc.KeyName)
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
	var states []interfaces.KeyState
	for _, rec := range recs {
		kids = append(kids, rec.Kid)
		states = append(states, rec.ToKeyState())
	}
	summary := firstKey.ToSummary()
	summary.Kids = kids
	summary.KeyStates = states
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
