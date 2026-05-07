package common

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// BaseProvider provides common delegation methods for all provider implementations
// It contains the service layer instances and delegates interface methods to them.
//
// Persistence-side after-mutation tracking (used by the file-backed memory
// adapter) used to live here as a WriteHook plumbed through every façade
// method. After #44 that responsibility moved into per-DAO decorator
// wrappers inside memory_provider — this struct carries no hook.
type BaseProvider struct {
	// DAOs - stored for reference but primarily used by services
	streamDAO interfaces.StreamDAO
	eventDAO  interfaces.EventDAO
	keyDAO    interfaces.KeyDAO
	clientDAO interfaces.ClientDAO
	serverDAO interfaces.ServerDAO
	tokenDAO  interfaces.TokenDAO

	// Services - business logic layer
	keyService    *services.KeyService
	streamService *services.StreamService
	eventService  *services.EventService
	clientService *services.ClientService
	serverService *services.ServerService
	tokenService  *services.TokenService
}

// NewBaseProvider creates a new base provider with the given DAOs and services
func NewBaseProvider(
	streamDAO interfaces.StreamDAO,
	eventDAO interfaces.EventDAO,
	keyDAO interfaces.KeyDAO,
	clientDAO interfaces.ClientDAO,
	serverDAO interfaces.ServerDAO,
	tokenDAO interfaces.TokenDAO,
	keyService *services.KeyService,
	streamService *services.StreamService,
	eventService *services.EventService,
	clientService *services.ClientService,
	serverService *services.ServerService,
	tokenService *services.TokenService,
) *BaseProvider {
	bp := &BaseProvider{
		streamDAO:     streamDAO,
		eventDAO:      eventDAO,
		keyDAO:        keyDAO,
		clientDAO:     clientDAO,
		serverDAO:     serverDAO,
		tokenDAO:      tokenDAO,
		keyService:    keyService,
		streamService: streamService,
		eventService:  eventService,
		clientService: clientService,
		serverService: serverService,
		tokenService:  tokenService,
	}
	// Wire the ServerService into StreamService so CreateStream can resolve
	// tx_alias internally (logic lifted out of this façade in PRD #39 PR 4).
	if streamService != nil && serverService != nil {
		streamService.SetServerService(serverService)
	}
	return bp
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

// GetTokenDAOForRebind exposes the underlying TokenDAO so MongoProvider's
// reconnect path can rebind its collection. The non-rebind public surface
// goes through services.TokenService.
func (b *BaseProvider) GetTokenDAOForRebind() interfaces.TokenDAO {
	return b.tokenDAO
}

// GetKeyService returns the embedded *KeyService. Used by MongoProvider's
// reconnect path to call InitializeTokenKey on the long-lived service
// instance instead of constructing a new one.
func (b *BaseProvider) GetKeyService() *services.KeyService {
	return b.keyService
}

// GetStreamService returns the embedded *StreamService. Used by
// MongoProvider's reconnect path to call LoadReceiverStreams on the
// long-lived service instance.
func (b *BaseProvider) GetStreamService() *services.StreamService {
	return b.streamService
}

// Per-service accessors used by the SignalsApplication / SsfApplication
// service-source interface assertion. After PRD #39 PR4, callers in
// pkg/goSignals/server depend on these directly instead of going through
// the BaseProvider façade methods below.
func (b *BaseProvider) GetEventService() *services.EventService   { return b.eventService }
func (b *BaseProvider) GetClientService() *services.ClientService { return b.clientService }
func (b *BaseProvider) GetServerService() *services.ServerService { return b.serverService }

func (b *BaseProvider) GetServerDAO() interfaces.ServerDAO {
	return b.serverDAO
}

// Service accessor methods for test helpers

func (b *BaseProvider) StoreExternalKey(keyName string, kids []string, streamID string, use string, jwksUri string) error {
	return b.keyService.StoreExternalKey(context.Background(), keyName, kids, streamID, use, jwksUri)
}

func (b *BaseProvider) GetKeyByStreamID(streamID string) *interfaces.JwkKeyRec {
	rec, _ := b.keyService.GetKeyByStreamID(context.Background(), streamID)
	return rec
}

// Key Management Methods

func (b *BaseProvider) DeleteKeysByName(keyName string) error {
	return b.keyService.DeleteKeysByName(context.Background(), keyName)
}

func (b *BaseProvider) GetPublicJWKS(keyName string) *json.RawMessage {
	return b.keyService.GetPublicJWKS(context.Background(), keyName)
}

func (b *BaseProvider) GetPrivateKey(keyName string) (*rsa.PrivateKey, error) {
	return b.keyService.GetPrivateKey(context.Background(), keyName)
}

func (b *BaseProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return b.keyService.GetAuthValidatorPubKey()
}

func (b *BaseProvider) GetAuthIssuer() *authUtil.AuthIssuer {
	return b.keyService.GetAuthIssuer()
}

func (b *BaseProvider) CreateKeyPair(keyName string, use string, projectId string) (*rsa.PrivateKey, error) {
	return b.keyService.CreateKeyPair(context.Background(), keyName, use, projectId)
}

func (b *BaseProvider) RotateKey(keyName string, projectId string) (*rsa.PrivateKey, string, error) {
	return b.keyService.RotateKey(context.Background(), keyName, projectId)
}

func (b *BaseProvider) ListKeyNames() []string {
	names, _ := b.keyService.ListKeyNames(context.Background())
	return names
}

func (b *BaseProvider) ListSummaries() ([]interfaces.KeySummary, error) {
	return b.keyService.ListSummaries(context.Background())
}

func (b *BaseProvider) GetPrivateKeyWithKid(keyName string) (*rsa.PrivateKey, string, error) {
	return b.keyService.GetPrivateKeyWithKeyname(context.Background(), keyName)
}

func (b *BaseProvider) AddKey(keyName string, use string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	return b.keyService.AddKey(context.Background(), keyName, use, kid, privateKey, publicKey, projectId)
}

// Client Management Methods

func (b *BaseProvider) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	return b.clientService.RegisterClient(context.Background(), request, projectId)
}

// Stream Management Methods

func (b *BaseProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return b.streamService.GetIssuerJwksForReceiver(context.Background(), sid)
}

func (b *BaseProvider) CreateStream(request model.StreamConfiguration, authCtx *authUtil.AuthContext) (model.StreamConfiguration, error) {
    // tx_alias resolution and IssuerJWKSUrl="NONE" normalisation now live
    // inside StreamService.CreateStream — this façade is a thin pass-through.
    ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authCtx)
    return b.streamService.CreateStream(ctx, request, authCtx.ProjectId, nil)
}

func (b *BaseProvider) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	return b.streamService.UpdateStream(context.Background(), streamId, projectId, configReq)
}

func (b *BaseProvider) DeleteStream(streamId string) error {
	return b.streamService.DeleteStream(context.Background(), streamId)
}

func (b *BaseProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	return b.streamService.GetStream(context.Background(), id)
}

func (b *BaseProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return b.streamService.GetStreamState(context.Background(), id)
}

func (b *BaseProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	b.streamService.UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
}

func (b *BaseProvider) UpdateRemoteAddress(streamId string, addr *model.RemoteIP) {
	b.streamService.UpdateRemoteAddress(context.Background(), streamId, addr)
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

func (b *BaseProvider) GetEventRecord(jti string) *model.AgEventRecord {
	return b.eventService.GetEventRecord(context.Background(), jti)
}

func (b *BaseProvider) AckEvent(jtiString string, streamId string, fencingToken int64) error {
	return b.eventService.AckEvent(context.Background(), jtiString, streamId, fencingToken)
}

func (b *BaseProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (*model.AgEventRecord, error) {
	return b.eventService.AddEvent(context.Background(), event, sid, raw)
}

func (b *BaseProvider) AddOperationalEvent(event *goSet.SecurityEventToken, sid string, raw string) (*model.AgEventRecord, error) {
	return b.eventService.AddOperationalEvent(context.Background(), event, sid, raw)
}

func (b *BaseProvider) AddEventToStream(jti string, streamId string) error {
	return b.eventService.AddEventToStream(context.Background(), jti, streamId)
}

func (b *BaseProvider) ClearPending(streamId string) error {
	_, err := b.eventService.ClearPendingForStream(context.Background(), streamId)
	return err
}

func (b *BaseProvider) WatchPending(ctx context.Context, callback func(jti string, streamId string)) {
	b.eventService.WatchPending(ctx, callback)
}

func (b *BaseProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.AgEventRecord) bool) error {
	return b.eventService.ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
}

// Server Management Methods

func (b *BaseProvider) CreateServer(ctx context.Context, server *model.Server) error {
	return b.serverService.CreateServer(ctx, server)
}

func (b *BaseProvider) GetServer(ctx context.Context, id string) (*model.Server, error) {
	return b.serverService.GetServer(ctx, id)
}

func (b *BaseProvider) GetServerByAlias(ctx context.Context, alias string) (*model.Server, error) {
	return b.serverService.GetServerByAlias(ctx, alias)
}

func (b *BaseProvider) UpdateServer(ctx context.Context, server *model.Server) error {
	return b.serverService.UpdateServer(ctx, server)
}

func (b *BaseProvider) DeleteServer(ctx context.Context, id string) error {
	return b.serverService.DeleteServer(ctx, id)
}

func (b *BaseProvider) ListServers(ctx context.Context) ([]model.Server, error) {
	return b.serverService.ListServers(ctx)
}

func (b *BaseProvider) GetTokenService() *services.TokenService {
	return b.tokenService
}
