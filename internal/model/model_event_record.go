package model

import "i2goSignals/pkg/goSet"

// EventRecord is stored in MongoProvider.eventCol
type EventRecord struct {
	// Id        primitive.ObjectID       `json:"id" bson:"_id"`
	Jti   string                   `json:"jti" bson:"jti"`
	Event goSet.SecurityEventToken `json:"event"`

	// Inbound indicates that the event has been received and is destined for a local client
	Inbound bool     `json:"inbound,omitempty" bson:"inbound,omitempty"`
	Types   []string `json:"types,omitempty" bson:"types,omitempty"`
}
