package mongo_provider

import (
	"i2goSignals/internal/model"
	"i2goSignals/pkg/goSet"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	CState_Active   = "A"
	CState_Pause    = "P"
	CState_Inactive = "I"
	CBatch_Size     = 5
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

type EventRecord struct {
	// Id        primitive.ObjectID       `json:"id" bson:"_id"`
	Jti   string                   `json:"jti" bson:"jti"`
	Event goSet.SecurityEventToken `json:"event"`
}

type DeliveredEvent struct {
	DeliverableEvent
	AckDate time.Time `json:"ackDate"`
}

type DeliverableEvent struct {
	// Id       primitive.ObjectID `json:"id" bson:"_id"`
	Jti      string             `json:"jti" bson:"jti"`
	StreamId primitive.ObjectID `json:"sid" bson:"sid"`
}

type StreamStateRecord struct {
	Id primitive.ObjectID `bson:"_id"`
	model.StreamConfiguration
	StartDate time.Time
	CreatedAt time.Time
	Status    string
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

// pendingChangeEvent holds a changeEvent for the pending events collection
// https://docs.mongodb.com/manual/reference/change-events/
type pendingChangeEvent struct {
	ID            changeID            `bson:"_id"`
	OperationType string              `bson:"operationType"`
	ClusterTime   primitive.Timestamp `bson:"clusterTime"`
	FullDocument  EventRecord         `bson:"fullDocument"`
	DocumentKey   documentKey         `bson:"documentKey"`
	Ns            namespace           `bson:"ns"`
}
