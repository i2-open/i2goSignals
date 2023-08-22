package handler

import (
	"crypto/rsa"
	model "github.com/independentid/i2goSignals/internal/model"

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
	ListStreams() []model.StreamConfiguration

	// RegisterStream creates a new stream
	RegisterStream(request model.RegisterParameters) model.RegisterResponse

	DeleteStream(streamId string) (string, error)

	// GetStream retrieves a current stream and often used to UpdateStream
	GetStream(streamId string) (model.StreamConfiguration, error)

	// UpdateStream replaces the current configuration with the new configuration requested (read-only attributes ignored)
	UpdateStream(streamId string, configuration model.StreamConfiguration) (model.StreamConfiguration, error)

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
	GetStatus(token string, subject model.Subject) (model.StreamStatus, error)
	SetStatus(token string, status model.StreamStatus) (model.StreamStatus, error)
	AddSubject(token string, parameters model.AddSubjectParameters) error
	RemoveSubject(token string, parameters model.RemoveSubjectParameters) error
	TriggerEvent(token string, parameters model.TriggerEventParameters) error
	PollEvents(streamId string, parameters model.PollParameters) (model.PollResponse, error)
	CreateStream(streamId string) error
}
