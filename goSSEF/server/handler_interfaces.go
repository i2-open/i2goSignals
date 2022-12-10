package server

import (
	"crypto/rsa"
	"github.com/MicahParks/keyfunc"
)

/*
StreamConfigHandler defines the interface to the stream configuraiton store (e.g. MongoDb).
*/
type StreamConfigHandler interface {
	// Open the provider and insure DB connection working
	Open(url string) error

	// Returns the name of the provider
	Name(token string) string

	// ListStreams returns all configured streams
	ListStreams() []StreamConfiguration

	// RegisterStream creates a new stream
	RegisterStream(request RegisterParameters) RegisterResponse

	DeleteStream(streamId string) (string, error)

	// GetStream retrieves a current stream and often used to UpdateStream
	GetStream(streamId string) (StreamConfiguration, error)

	// UpdateStream replaces the current configuration with the new configuration requested (read-only attributes ignored)
	UpdateStream(streamId string, configuration StreamConfiguration) (StreamConfiguration, error)

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
	GetStatus(token string, subject Subject) (StreamStatus, error)
	SetStatus(token string, status StreamStatus) (StreamStatus, error)
	AddSubject(token string, parameters AddSubjectParameters) error
	RemoveSubject(token string, parameters RemoveSubjectParameters) error
	TriggerEvent(token string, parameters TriggerEventParameters) error
	PollEvents(streamId string, parameters PollParameters) (PollResponse, error)
	CreateStream(streamId string) error
}
