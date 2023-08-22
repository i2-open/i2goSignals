package model

import (
	"github.com/independentid/i2goSignals/pkg/goSet"
	"time"
)

// EventRecord is stored in MongoProvider.eventCol
type EventRecord struct {
	// Id        primitive.ObjectID       `json:"id" bson:"_id"`
	Jti string `json:"jti" bson:"jti"`

	// A parsed Security Event Token
	Event goSet.SecurityEventToken `json:"event"`

	// Original holds the original token received. This is useful for scenarios when the original
	// signature or encrypted token is desired
	Original string

	// Sid indicates the origin Stream that the event came from
	Sid string
	// Types indicates the event URIs available. This may be used for filtering and sorting of events
	Types []string `json:"types,omitempty" bson:"types,omitempty"`

	/*
		SortTime is used to reset event streams and allow searching historical events from a certain point in time.
		When set it is based upon one of the following attributes in order of preference:  toe, iat, time of insertion
	*/
	SortTime time.Time `bson:"sortTime"`
}
