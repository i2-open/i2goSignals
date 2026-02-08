package common

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// WriteHook is a callback function that can be invoked after write operations
type WriteHook func()

// BaseProvider provides common delegation methods for all provider implementations
// It contains the service layer instances and delegates interface methods to them
type BaseProvider struct {
	// DAOs - stored for reference but primarily used by services
	streamDAO interfaces.StreamDAO
	eventDAO  interfaces.EventDAO
	keyDAO    interfaces.KeyDAO
	clientDAO interfaces.ClientDAO

	// Services - business logic layer
	keyService    *services.KeyService
	streamService *services.StreamService
	eventService  *services.EventService
	clientService *services.ClientService

	// Optional hook for write operations (used by memory provider for dirty tracking)
	afterWrite WriteHook
}

// NewBaseProvider creates a new base provider with the given DAOs and services
func NewBaseProvider(
	streamDAO interfaces.StreamDAO,
	eventDAO interfaces.EventDAO,
	keyDAO interfaces.KeyDAO,
	clientDAO interfaces.ClientDAO,
	keyService *services.KeyService,
	streamService *services.StreamService,
	eventService *services.EventService,
	clientService *services.ClientService,
) *BaseProvider {
	return &BaseProvider{
		streamDAO:     streamDAO,
		eventDAO:      eventDAO,
		keyDAO:        keyDAO,
		clientDAO:     clientDAO,
		keyService:    keyService,
		streamService: streamService,
		eventService:  eventService,
		clientService: clientService,
	}
}

// SetWriteHook sets a callback to be invoked after successful write operations
func (b *BaseProvider) SetWriteHook(hook WriteHook) {
	b.afterWrite = hook
}

// notifyWrite calls the write hook if it's set
func (b *BaseProvider) notifyWrite() {
	if b.afterWrite != nil {
		b.afterWrite()
	}
}

// DAO accessor methods for provider-specific operations (e.g., persistence)

func (b *BaseProvider) GetStreamDAO() interfaces.StreamDAO {
	return b.streamDAO
}

func (b *BaseProvider) GetEventDAO() interfaces.EventDAO {
	return b.eventDAO
}

func (b *BaseProvider) GetKeyDAO() interfaces.KeyDAO {
	return b.keyDAO
}

func (b *BaseProvider) GetClientDAO() interfaces.ClientDAO {
	return b.clientDAO
}

// Service accessor methods for test helpers

func (b *BaseProvider) StoreReceiverKey(streamID string, audience string, jwksUri string) error {
	return b.keyService.StoreReceiverKey(context.Background(), streamID, audience, jwksUri)
}

func (b *BaseProvider) GetReceiverKey(streamID string) *interfaces.JwkKeyRec {
	rec, _ := b.keyService.GetReceiverKey(context.Background(), streamID)
	return rec
}

// Key Management Methods

func (b *BaseProvider) DeleteIssuer(issuer string) error {
	err := b.keyService.DeleteIssuer(context.Background(), issuer)
	if err == nil {
		b.notifyWrite()
	}
	return err
}

func (b *BaseProvider) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	return b.keyService.GetPublicTransmitterJWKS(context.Background(), issuer)
}

func (b *BaseProvider) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	return b.keyService.GetIssuerPrivateKey(context.Background(), issuer)
}

func (b *BaseProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return b.keyService.GetAuthValidatorPubKey()
}

func (b *BaseProvider) GetAuthIssuer() *authUtil.AuthIssuer {
	return b.keyService.GetAuthIssuer()
}

func (b *BaseProvider) CreateIssuerJwkKeyPair(issuer string, projectId string) (*rsa.PrivateKey, error) {
	key, err := b.keyService.CreateIssuerJwkKeyPair(context.Background(), issuer, projectId)
	if err == nil {
		b.notifyWrite()
	}
	return key, err
}

func (b *BaseProvider) RotateIssuerKey(issuer string, projectId string) (*rsa.PrivateKey, string, error) {
	key, kid, err := b.keyService.RotateIssuerKey(context.Background(), issuer, projectId)
	if err == nil {
		b.notifyWrite()
	}
	return key, kid, err
}

func (b *BaseProvider) GetIssuerKeyNames() []string {
	names, _ := b.keyService.GetIssuerKeyNames(context.Background())
	return names
}

func (b *BaseProvider) GetIssuerPrivateKeyWithKid(issuer string) (*rsa.PrivateKey, string, error) {
	return b.keyService.GetIssuerPrivateKeyWithKid(context.Background(), issuer)
}

func (b *BaseProvider) AddIssuerKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	err := b.keyService.AddIssuerKey(context.Background(), issuer, kid, privateKey, publicKey, projectId)
	if err == nil {
		b.notifyWrite()
	}
	return err
}

// Client Management Methods

func (b *BaseProvider) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	resp := b.clientService.RegisterClient(context.Background(), request, projectId)
	if resp != nil {
		b.notifyWrite()
	}
	return resp
}

// Stream Management Methods

func (b *BaseProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return b.streamService.GetIssuerJwksForReceiver(context.Background(), sid)
}

func (b *BaseProvider) CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error) {
	res, err := b.streamService.CreateStream(context.Background(), request, projectId)
	if err == nil {
		b.notifyWrite()
	}
	return res, err
}

func (b *BaseProvider) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	res, err := b.streamService.UpdateStream(context.Background(), streamId, projectId, configReq)
	if err == nil {
		b.notifyWrite()
	}
	return res, err
}

func (b *BaseProvider) DeleteStream(streamId string) error {
	err := b.streamService.DeleteStream(context.Background(), streamId)
	if err == nil {
		b.notifyWrite()
	}
	return err
}

func (b *BaseProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	return b.streamService.GetStream(context.Background(), id)
}

func (b *BaseProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return b.streamService.GetStreamState(context.Background(), id)
}

func (b *BaseProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	b.streamService.UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
	b.notifyWrite()
}

func (b *BaseProvider) GetStatus(streamId string) (*model.StreamStatus, error) {
	return b.streamService.GetStatus(context.Background(), streamId)
}

func (b *BaseProvider) ListStreams() []model.StreamConfiguration {
	return b.streamService.ListStreams(context.Background())
}

func (b *BaseProvider) GetStateMap() map[string]model.StreamStateRecord {
	return b.streamService.GetStateMap(context.Background())
}

func (b *BaseProvider) SetBaseUrl(u *url.URL) {
	b.streamService.SetBaseUrl(u)
}

// Event Management Methods

func (b *BaseProvider) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return b.eventService.GetEventIds(context.Background(), streamId, params)
}

func (b *BaseProvider) GetEvent(jti string) *goSet.SecurityEventToken {
	return b.eventService.GetEvent(context.Background(), jti)
}

func (b *BaseProvider) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	return b.eventService.GetEvents(context.Background(), jtis)
}

func (b *BaseProvider) GetEventRecord(jti string) *model.EventRecord {
	return b.eventService.GetEventRecord(context.Background(), jti)
}

func (b *BaseProvider) AckEvent(jtiString string, streamId string, fencingToken int64) error {
	err := b.eventService.AckEvent(context.Background(), jtiString, streamId, fencingToken)
	if err == nil {
		b.notifyWrite()
	}
	return err
}

func (b *BaseProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (*model.EventRecord, error) {
	res, err := b.eventService.AddEvent(context.Background(), event, sid, raw)
	if err == nil {
		b.notifyWrite()
	}
	return res, err
}

func (b *BaseProvider) AddEventToStream(jti string, streamId bson.ObjectID) error {
	err := b.eventService.AddEventToStream(context.Background(), jti, streamId)
	if err == nil {
		b.notifyWrite()
	}
	return err
}

func (b *BaseProvider) WatchPending(ctx context.Context, callback func(jti string, streamId bson.ObjectID)) {
	b.eventService.WatchPending(ctx, callback)
}

func (b *BaseProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	err := b.eventService.ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
	if err == nil {
		b.notifyWrite()
	}
	return err
}
