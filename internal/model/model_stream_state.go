package model

import (
	"time"

	"github.com/MicahParks/keyfunc"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// StreamStateRecord is stored in MongoProvider.streamCol
type StreamStateRecord struct {
	Id primitive.ObjectID `bson:"_id"`
	StreamConfiguration
	StartDate    time.Time
	CreatedAt    time.Time
	Status       string
	Inbound      bool          `json:"inbound,omitempty" bson:"inbound,omitempty"`
	ValidateJwks *keyfunc.JWKS `json:"-" bson:"-"` // not persisted
	ErrorMsg     string        `json:"-" bson:"-"`
	Receiver     ReceiveConfig `bson:"receiver"`
}

type ReceiveConfig struct {
	Method     string
	PollAuth   string
	PollParams PollParameters
	PollUrl    string
}

const (
	DeliveryPoll        = "https://schemas.openid.net/secevent/risc/delivery-method/poll"
	DeliveryPush        = "https://schemas.openid.net/secevent/risc/delivery-method/push"
	StreamStateActive   = "A"
	StreamStatePause    = "P"
	StreamStateInactive = "I"
	StreamPollBatchSize = 5
)
