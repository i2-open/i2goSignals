package dbProviders

import (
	"crypto/rsa"
	"encoding/json"
	"i2goSignals/internal/model"
	"i2goSignals/pkg/goSet"

	"github.com/MicahParks/keyfunc"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type DbProviderInterface interface {
	Name() string
	Check() error
	Close() error

	GetPublicTransmitterJWKS(issuer string) *json.RawMessage
	GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error)
	GetAuthValidatorPubKey() *keyfunc.JWKS
	GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS

	RegisterStream(request model.RegisterParameters) *model.RegisterResponse
	UpdateStream(streamId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error)
	DeleteStream(streamId string) error
	GetStream(id string) (*model.StreamConfiguration, error)

	AuthenticateToken(token string) (string, error)

	GetStreamState(id string) (*model.StreamStateRecord, error)
	PauseStream(streamId string, status string, errorMsg string)
	GetStatus(streamId string, subject string) (*model.StreamStatus, error)
	ListStreams() []model.StreamConfiguration
	GetStateMap() map[string]model.StreamStateRecord

	GetEventIds(streamId string, params model.PollParameters) ([]string, bool)
	GetEvents(jtis []string) *[]goSet.SecurityEventToken
	AckEvent(jtiString string, streamId string)
	AddEvent(event *goSet.SecurityEventToken, inbound bool)
	AddEventToStream(jti string, streamId primitive.ObjectID)

	// handler.PushStreamHandler
	// handler.StreamConfigHandler
}
