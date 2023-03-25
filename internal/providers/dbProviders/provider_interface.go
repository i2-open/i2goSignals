package dbProviders

import (
	"crypto/rsa"
	"encoding/json"
	"i2goSignals/internal/model"
	"i2goSignals/pkg/goSet"

	"github.com/MicahParks/keyfunc"
)

type DbProviderInterface interface {
	Name(token string) string
	Check() error
	GetPublicTransmitterJWKS(issuer string) *json.RawMessage
	Close() error
	RegisterStream(request model.RegisterParameters) *model.RegisterResponse
	AuthenticateToken(token string) (string, error)
	GetStream(id string) (*model.StreamConfiguration, error)
	GetStatus(streamId string, subject string) (*model.StreamStatus, error)
	DeleteStream(streamId string) error
	UpdateStream(streamId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error)
	GetEventIds(streamId string, params model.PollParameters) ([]string, bool)
	GetEvents(jtis []string) *[]goSet.SecurityEventToken
	AckEvent(jtiString string, streamId string)
	GetIssuerJWKS(issuer string) (*rsa.PrivateKey, error)
	GetAuthValidatorPubKey() *keyfunc.JWKS
	// handler.StreamHandler
	// handler.StreamConfigHandler
}
