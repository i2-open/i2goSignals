package model

import "time"

// StreamConfiguration is a JSON Object describing and Event Stream's configuration [Spec](https://openid.net/specs/openid-sse-framework-1_0.html#stream-config)\"
type StreamConfiguration struct {
	Id string `json:"stream_id" bson:"id"`

	// Read-Only. A URL using the https scheme with no query or fragment component that the Transmitter asserts as its Issuer Identifier. This MUST be identical to the iss Claim value in Security Event Tokens issued from this Transmitter.
	Iss string `json:"iss,omitempty"`

	// Read-Only. A string or an array of strings containing an audience claim as defined in [JSON Web Auth (JWT)](https://openid.net/specs/openid-sse-framework-1_0.html#RFC7519) that identifies the Event Receiver(s) for the Event Stream. This property cannot be updated. If multiple Receivers are specified then the Transmitter SHOULD know that these Receivers are the same entity.
	Aud []string `json:"aud,omitempty"`

	// Read-Only. An array of URIs identifying the set of events supported by the Transmitter for this Receiver. If omitted, Event Transmitters SHOULD make this set available to the Event Receiver via some other means (e.g. publishing it in online documentation).
	EventsSupported []string `json:"events_supported,omitempty"`

	// Read-Write. An array of URIs identifying the set of events that the Receiver requested. A Receiver SHOULD request only the events that it understands and it can act on. This is configurable by the Receiver.
	EventsRequested []string `json:"events_requested"`

	// Read-Only. An array of URIs which is the intersection of events_supported and events_requested. These events MAY be delivered over the Event Stream.
	EventsDelivered []string `json:"events_delivered,omitempty"`

	// Read-Write. A JSON object containing a set of name/value pairs specifying configuration parameters for the SET delivery method. The actual delivery method is identified by the special key method with the value being a URI as defined in [Section 11.2.1](https://openid.net/specs/openid-sse-framework-1_0.html#delivery-meta).
	Delivery *OneOfStreamConfigurationDelivery `json:"delivery"`

	// Read-Only. An integer indicating the minimum amount of time in seconds that must pass in between verification requests. If an Event Receiver submits verification requests more frequently than this, the Event Transmitter MAY respond with a 429 status code. An Event Transmitter SHOULD NOT respond with a 429 status code if an Event Receiver is not exceeding this frequency.
	MinVerificationInterval int32 `json:"min_verification_interval,omitempty"`

	// Read-Write. The Subject Identifier Format that the Receiver wants for the events. If not set then the Transmitter might decide to use a type that discloses more information than necessary.
	Format string `json:"format,omitempty"`

	// Read-Write. If set, events will be encrypted using the public key at this URL
	ReceiverJWKSUrl string `json:"receiverJWKSUrl,omitempty"`

	// Read-Only. Url for the event issuer public key
	IssuerJWKSUrl string `json:"issuerJWKSUrl,omitempty"`

	// Used to reset a stream to a specific date, if available events will be loaded >= date
	ResetDate *time.Time `json:"resetDate,omitempty"`
	// Used to reset a stream to a specific jti (assuming jti's are sortable). Events equal to or since the JTI will be available
	ResetJti string `json:"resetJti,omitempty"`

	RouteMode string `json:"route_mode,omitempty"` // Is one of RouteModeImport, RouteModeForward or RouteModePublish
}
