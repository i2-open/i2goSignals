package mongo_provider

import (
	"time"

	"github.com/i2-open/i2goSignals/internal/model"

	"github.com/MicahParks/keyfunc"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type JwkKeyRec struct {
	Id              primitive.ObjectID `json:"id" bson:"_id"`
	Iss             string             `json:"iss,omitempty" bson:"iss"`
	Aud             string             `json:"aud,omitempty" bson:"aud"`
	ProjectId       string             `bson:"project_id" json:"projectId,omitempty"`
	StreamId        string             `json:"streamId" bson:"stream_id"`
	KeyBytes        []byte             `json:"keyBytes" bson:"key_bytes"`
	PubKeyBytes     []byte             `json:"pubJwks" bson:"pub_jwks"`
	ReceiverJwksUrl string             `json:"receiverJwksUrl" bson:"receiver_jwks_url"`
}

// DeliveredEvent is stored in MongoProvider.deliveredCol
type DeliveredEvent struct {
	DeliverableEvent
	AckDate time.Time `json:"ackDate"`
}

// DeliverableEvent is stored in MongoProvider.pendingCol
type DeliverableEvent struct {
	// Id       primitive.ObjectID `json:"id" bson:"_id"`
	Jti      string             `json:"jti" bson:"jti"`
	StreamId primitive.ObjectID `json:"sid" bson:"sid"`
}

type EventReceiver struct {
	model.StreamConfiguration
	jwks *keyfunc.JWKS
}

type documentKey struct {
	ID primitive.ObjectID `bson:"_id"`
}

type changeID struct {
	Data string `bson:"_data"`
}

type namespace struct {
	Db   string `bson:"db"`
	Coll string `bson:"coll"`
}

// PendingChangeEvent holds a changeEvent for the pending events collection
// https://docs.mongodb.com/manual/reference/change-events/
type PendingChangeEvent struct {
	ID            changeID            `bson:"_id"`
	OperationType string              `bson:"operationType"`
	ClusterTime   primitive.Timestamp `bson:"clusterTime"`
	FullDocument  model.EventRecord   `bson:"fullDocument"`
	DocumentKey   documentKey         `bson:"documentKey"`
	Ns            namespace           `bson:"ns"`
}
