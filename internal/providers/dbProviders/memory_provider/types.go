package memory_provider

import (
	"time"

	"github.com/i2-open/i2goSignals/internal/model"

	"github.com/MicahParks/keyfunc"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type JwkKeyRec struct {
	Id              bson.ObjectID `json:"id" bson:"_id"`
	Iss             string        `json:"iss,omitempty" bson:"iss"`
	Kid             string        `json:"kid,omitempty" bson:"kid"`
	Aud             string        `json:"aud,omitempty" bson:"aud"`
	ProjectId       string        `bson:"project_id" json:"projectId,omitempty"`
	StreamId        string        `json:"streamId" bson:"stream_id"`
	KeyBytes        []byte        `json:"keyBytes" bson:"key_bytes"`
	PubKeyBytes     []byte        `json:"pubJwks" bson:"pub_jwks"`
	ReceiverJwksUrl string        `json:"receiverJwksUrl" bson:"receiver_jwks_url"`
}

// DeliveredEvent is stored in MemoryProvider.deliveredEvents
type DeliveredEvent struct {
	DeliverableEvent
	AckDate time.Time `json:"ackDate"`
}

// DeliverableEvent is stored in MemoryProvider.pendingEvents
type DeliverableEvent struct {
	Jti      string        `json:"jti" bson:"jti"`
	StreamId bson.ObjectID `json:"sid" bson:"sid"`
}

type EventReceiver struct {
	model.StreamConfiguration
	jwks *keyfunc.JWKS
}
