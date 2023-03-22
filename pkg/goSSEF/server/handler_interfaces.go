package server

import (
	"crypto/rsa"
	model2 "i2goSignals/internal/model"

	"github.com/MicahParks/keyfunc"
)

/*
StreamConfigHandler defines the interface to the stream configuration store (e.g. MongoDb).
*/
type StreamConfigHandler interface {
	// Open the provider and insure DB connection working
	Open(url string) (*StreamConfigHandler, error)

	// Returns the name of the provider
	Name(token string) string

	// ListStreams returns all configured streams
	ListStreams() []model2.StreamConfiguration

	// RegisterStream creates a new stream
	RegisterStream(request model2.RegisterParameters) model2.RegisterResponse

	DeleteStream(streamId string) (string, error)

	// GetStream retrieves a current stream and often used to UpdateStream
	GetStream(streamId string) (model2.StreamConfiguration, error)

	// UpdateStream replaces the current configuration with the new configuration requested (read-only attributes ignored)
	UpdateStream(streamId string, configuration model2.StreamConfiguration) (model2.StreamConfiguration, error)

	// GetTransmitterJWKS returns the key that will be used to sign events
	GetTransmitterJWKS(issuer string) (*rsa.PrivateKey, error)

	// GetPublicTransmitterJWKS is used by an event receiver to return the transmitter's public key in JWKS form
	GetPublicTransmitterJWKS(streamId string) (*keyfunc.JWKS, error)

	// GetReceiverJWKS returns the receiver public key used to encrypt events
	GetReceiverJWKS(streamid string) (*keyfunc.JWKS, error)

	// ResetDb is used to reset the database by dropping all collections/tables. Used for testing only.
	ResetDb()
}

/*
StreamHandler largely handles all interactions with using an operational stream. This usually involves backend
calls to Kafka (or other provider).
*/
type StreamHandler interface {
	GetStatus(token string, subject model2.Subject) (model2.StreamStatus, error)
	SetStatus(token string, status model2.StreamStatus) (model2.StreamStatus, error)
	AddSubject(token string, parameters model2.AddSubjectParameters) error
	RemoveSubject(token string, parameters model2.RemoveSubjectParameters) error
	TriggerEvent(token string, parameters model2.TriggerEventParameters) error
	PollEvents(streamId string, parameters model2.PollParameters) (model2.PollResponse, error)
	CreateStream(streamId string) error
}
