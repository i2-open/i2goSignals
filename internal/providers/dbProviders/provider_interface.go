package dbProviders

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/independentid/i2goSignals/internal/model"
	"github.com/independentid/i2goSignals/pkg/goSet"
	"time"

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
	CreateIssuerJwkKeyPair(issuer string) *rsa.PrivateKey

	RegisterStream(request model.RegisterParameters) *model.RegisterResponse
	UpdateStream(streamId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error)
	DeleteStream(streamId string) error
	GetStream(id string) (*model.StreamConfiguration, error)

	AuthenticateToken(token string) (string, error)

	GetStreamState(id string) (*model.StreamStateRecord, error)
	UpdateStreamStatus(streamId string, status string, errorMsg string)
	GetStatus(streamId string) (*model.StreamStatus, error)
	ListStreams() []model.StreamConfiguration
	GetStateMap() map[string]model.StreamStateRecord

	GetEventIds(streamId string, params model.PollParameters) ([]string, bool)
	GetEvent(jti string) *goSet.SecurityEventToken
	GetEvents(jtis []string) []*goSet.SecurityEventToken
	GetEventRecord(jti string) *model.EventRecord
	AckEvent(jtiString string, streamId string)
	AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (eventRecord *model.EventRecord)
	AddEventToStream(jti string, streamId primitive.ObjectID)
	ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error

	// handler.PushStreamHandler
	// handler.StreamConfigHandler
}
