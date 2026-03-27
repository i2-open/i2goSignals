package model

import (
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// StreamStateRecord is stored in MongoProvider.streamCol
type StreamStateRecord struct {
	Id                  bson.ObjectID `bson:"_id"`
	ProjectId           string        `json:"project_id" bson:"project_id"` // ProjectId links SsfClient entities to streams.
	StreamConfiguration `bson:",inline"`
	StartDate           time.Time `json:"start_date" bson:"start_date"`
	CreatedAt           time.Time `json:"created_at" bson:"created_at"`
	ModifiedAt          time.Time `json:"modified_at" bson:"modified_at"`

	// Status indicates the current operational status and is one of StreamStateEnabled, StreamStatePause, StreamStateDisable
	Status string `json:"status" bson:"status"`

	// ValidateJwks is used when in Inbound mode to validate the inbound issuer. This value acts like a cache
	ValidateJwks *keyfunc.JWKS `json:"-" bson:"-"` // not persisted

	// ErrorMsg holds the reason a stream has been paused
	ErrorMsg string `json:"reason,omitempty" bson:"error_msg,omitempty"`
}

func (ss *StreamStateRecord) DeepCopy() *StreamStateRecord {
	if ss == nil {
		return nil
	}
	res := *ss
	res.StreamConfiguration = ss.StreamConfiguration.DeepCopy()
	return &res
}

func (ss *StreamStateRecord) Update(mod *StreamStateRecord) {
	// This is being done to preserve the handle on the PushStreams.
	ss.Status = mod.Status
	ss.ErrorMsg = mod.ErrorMsg
	// ss.Receiver = mod.Receiver - now handled by StreamConfiguration

	ss.ValidateJwks = mod.ValidateJwks

	ss.StreamConfiguration = mod.StreamConfiguration
	ss.StartDate = mod.StartDate
	ss.ModifiedAt = mod.ModifiedAt
}

// GetType returns the delivery method for the stream state record. Returns one of ReceivePush, ReceivePoll, DeliveryPush, DeliveryPoll.
func (ss *StreamStateRecord) GetType() string {
	return ss.Delivery.GetMethod()
}

func (ss *StreamStateRecord) IsReceiver() bool {
	switch ss.GetType() {
	case ReceivePush, ReceivePoll:
		return true
	default:
		return false
	}
}

func (ss *StreamStateRecord) HasTxServer() bool {
	if ss.TxAlias != nil && *ss.TxAlias != "" {
		return true
	}
	if ss.TxWellKnownUrl != nil && *ss.TxWellKnownUrl != "" {
		return true
	}
	return false
}

func (ss *StreamStateRecord) GetRouteMode() string {
	return ss.StreamConfiguration.RouteMode
}

const (
	// DeliveryPoll indicates that a stream delivers events using HTTP Set Delivery via Polling using HTTP GET by the receiver. It defines an SSF transmitter.
	DeliveryPoll = "urn:ietf:rfc:8936"

	// DeliveryPush indicates that a stream delivers events using HTTP Set Delivery via Pushing using HTTP POST by the transmitter. It defines an SSF transmitter.
	DeliveryPush = "urn:ietf:rfc:8935"

	// ReceivePoll indicates that a stream receives events using HTTP Set Delivery via Polling using HTTP GET by the receiver. It defines an SSF receiver. This is used by goSignals to define the receiver half of a transmitter/receiver pair.
	ReceivePoll = "urn:ietf:rfc:8936:receive"

	// ReceivePush indicates that a stream receives events using HTTP Set Delivery via PUSH using HTTP POST by the transmitter. It defines an SSF receiver. This is used by goSignals to define the receiver half of a transmitter/receiver pair.
	ReceivePush = "urn:ietf:rfc:8935:receive"

	StreamStateEnabled  = "enabled"
	StreamStatePause    = "paused"
	StreamStateDisable  = "disabled"
	StreamPollBatchSize = 5
	RouteModeImport     = "IM" // Indicates the router will not further propagate the event and save to database for local use
	RouteModeForward    = "FW" // Indicates the router will move events received to other eligable streams
	RouteModePublish    = "PB" // Indicates the router will router to target streams and generate new JWS/JWE tokens
)
