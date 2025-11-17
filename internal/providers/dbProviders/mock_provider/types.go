package mock_provider

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

// DeliveredEvent is stored in MockMongoProvider.deliveredEvents
type DeliveredEvent struct {
	DeliverableEvent
	AckDate time.Time `json:"ackDate"`
}

// DeliverableEvent is stored in MockMongoProvider.pendingEvents
type DeliverableEvent struct {
	Jti      string             `json:"jti" bson:"jti"`
	StreamId primitive.ObjectID `json:"sid" bson:"sid"`
}

type EventReceiver struct {
	model.StreamConfiguration
	jwks *keyfunc.JWKS
}
