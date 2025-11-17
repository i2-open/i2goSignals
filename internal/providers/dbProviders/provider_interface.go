package dbProviders

import (
	"crypto/rsa"
	"encoding/json"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"

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
	GetAuthIssuer() *authUtil.AuthIssuer
	GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS
	CreateIssuerJwkKeyPair(issuer string, projectId string) *rsa.PrivateKey

	RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse
	CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error)
	UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error)
	DeleteStream(streamId string) error
	GetStream(id string) (*model.StreamConfiguration, error)

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

	ResetDb(initialize bool) error
	// handler.PushStreamHandler
	// handler.StreamConfigHandler
}
