package mongo_provider

import (
	"i2goSignals/internal/model"
	"i2goSignals/pkg/goSet"
	"time"

	"github.com/MicahParks/keyfunc"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type JwkKeyRec struct {
	Id              primitive.ObjectID `json:"id" bson:"_id"`
	Iss             string             `json:"iss,omitempty" bson:"iss"`
	Aud             string             `bson:"aud,omitempty" bson:"aud"`
	StreamId        string             `json:"streamId" bson:"stream_id"`
	KeyBytes        []byte             `json:"keyBytes" bson:"key_bytes"`
	PubKeyBytes     []byte             `json:"pubJwks" bson:"pub_jwks"`
	ReceiverJwksUrl string             `json:"receiverJwksUrl" bson:"receiver_jwks_url"`
}

// EventRecord is stored in MongoProvider.eventCol
type EventRecord struct {
	// Id        primitive.ObjectID       `json:"id" bson:"_id"`
	Jti   string                   `json:"jti" bson:"jti"`
	Event goSet.SecurityEventToken `json:"event"`

	// Inbound indicates that the event has been received and is destined for a local client
	Inbound bool     `json:"inbound,omitempty" bson:"inbound,omitempty"`
	Types   []string `json:"types,omitempty" bson:"types,omitempty"`
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
	FullDocument  EventRecord         `bson:"fullDocument"`
	DocumentKey   documentKey         `bson:"documentKey"`
	Ns            namespace           `bson:"ns"`
}
