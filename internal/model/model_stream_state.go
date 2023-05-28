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
	StartDate  time.Time
	CreatedAt  time.Time
	ModifiedAt time.Time

	// Status indicates the current operational status and is one of StreamStateActive, StreamStatePause, StreamStateInactive
	Status string

	// Inbound indicates the stream is inbound and configured by ReceiverConfig
	Inbound bool `json:"inbound,omitempty" bson:"inbound,omitempty"`

	// ValidateJwks is used when in Inbound mode to validate the inbound issuer. This value acts like a cache
	ValidateJwks *keyfunc.JWKS `json:"-" bson:"-"` // not persisted

	// ErrorMsg holds the reason a stream has been paused
	ErrorMsg string

	// Receiver holds Client configuration information
	Receiver ReceiveConfig `bson:"receiver"`
}

func (ss *StreamStateRecord) Update(mod *StreamStateRecord) {
	// This is being done to preserve the handle on the PushStreams.
	ss.Status = mod.Status
	ss.ErrorMsg = mod.ErrorMsg
	ss.Receiver = mod.Receiver

	ss.Inbound = mod.Inbound
	ss.ValidateJwks = mod.ValidateJwks

	ss.StreamConfiguration = mod.StreamConfiguration
	ss.StartDate = mod.StartDate
	ss.ModifiedAt = mod.ModifiedAt
}

/*
ReceiveConfig is used when the server is acting as a client and is receiving events. Note that
when Method is DeliveryPoll, the server will accept posts to the normal stream endpoint (no config needed)
*/
type ReceiveConfig struct {
	// RouteMode determines what the EventRouter does with an inbound event.
	RouteMode  string // Is one of RouteModeImport, RouteModeForward or RouteModePublish
	Method     string // Indicates DeliveryPoll or DeliveryPush
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
	RouteModeImport     = "IM" // Indicates the router will not further propagate the event and save to database for local use
	RouteModeForward    = "FW" // Indicates the router will move events received to other eligable streams
	RouteModePublish    = "PB" // Indicates the router will router to target streams and generate new JWS/JWE tokens
)
