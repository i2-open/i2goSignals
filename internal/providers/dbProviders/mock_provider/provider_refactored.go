package mock_provider

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var pLog2 = logger.Sub("MOCK_V2")

// MockMongoProviderV2 provides an in-memory implementation using DAOs and services
type MockMongoProviderV2 struct {
	DbUrl  string
	DbName string
	dbInit bool

	// DAOs
	streamDAO interfaces.StreamDAO
	eventDAO  interfaces.EventDAO
	keyDAO    interfaces.KeyDAO
	clientDAO interfaces.ClientDAO

	// Services
	keyService    *services.KeyService
	streamService *services.StreamService
	eventService  *services.EventService
	clientService *services.ClientService

	DefaultIssuer string
	TokenIssuer   string
}

func (m *MockMongoProviderV2) Name() string {
	return m.DbName
}

func (m *MockMongoProviderV2) initialize() {
	pLog2.Info("Initializing new in-memory mock database", "dbName", m.DbName)

	// Initialize DAOs
	m.streamDAO = memory.NewStreamDAO()
	m.eventDAO = memory.NewEventDAO()
	m.keyDAO = memory.NewKeyDAO()
	m.clientDAO = memory.NewClientDAO()

	// Initialize Services
	m.keyService = services.NewKeyService(m.keyDAO, m.TokenIssuer)
	m.streamService = services.NewStreamService(m.streamDAO, m.keyService, m.DefaultIssuer)
	m.eventService = services.NewEventService(m.eventDAO)
	m.clientService = services.NewClientService(m.clientDAO, m.keyService)

	// Initialize token keys
	ctx := context.Background()
	err := m.keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
	if err != nil {
		pLog2.Error("Error initializing token key", "error", err)
	}

	m.dbInit = true
}

func (m *MockMongoProviderV2) Check() error {
	// Mock provider is always available
	return nil
}

func (m *MockMongoProviderV2) ResetDb(initialize bool) error {
	// Create new DAOs to reset all data
	m.streamDAO = memory.NewStreamDAO()
	m.eventDAO = memory.NewEventDAO()
	m.keyDAO = memory.NewKeyDAO()
	m.clientDAO = memory.NewClientDAO()

	if initialize {
		// Re-initialize services with new DAOs
		m.keyService = services.NewKeyService(m.keyDAO, m.TokenIssuer)
		m.streamService = services.NewStreamService(m.streamDAO, m.keyService, m.DefaultIssuer)
		m.eventService = services.NewEventService(m.eventDAO)
		m.clientService = services.NewClientService(m.clientDAO, m.keyService)

		ctx := context.Background()
		err := m.keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
		if err != nil {
			pLog2.Error("Error reinitializing token key", "error", err)
		}
	}

	return nil
}

// OpenV2 creates and initializes a new MockMongoProviderV2
func OpenV2(mongoUrl string, dbName string) (*MockMongoProviderV2, error) {
	// Check if this is a mock URL
	if !strings.HasPrefix(mongoUrl, "mockdb:") && mongoUrl != "" {
		return nil, fmt.Errorf("mock provider only supports 'mockdb:' URL prefix, got: %s", mongoUrl)
	}

	defaultIssuer, issDefined := os.LookupEnv(CEnvIssuer)
	if !issDefined {
		defaultIssuer = CDefIssuer
	}

	if dbName == "" {
		dbEnvName, dbDefined := os.LookupEnv(CEnvDbName)
		if !dbDefined {
			dbName = CDbName
		} else {
			dbName = dbEnvName
		}
	}

	tknIssuer, tknDefined := os.LookupEnv(CEnvTokenIssuer)
	if !tknDefined {
		tknIssuer = CDefTokenIssuer
	}

	if mongoUrl == "" {
		mongoUrl = "mockdb://localhost:27017/"
		pLog2.Info("Defaulting Mock Mongo Database URL", "url", mongoUrl)
	}

	m := &MockMongoProviderV2{
		DbName:        dbName,
		DbUrl:         mongoUrl,
		DefaultIssuer: defaultIssuer,
		TokenIssuer:   tknIssuer,
	}

	err := m.Check()
	if err != nil {
		return nil, err
	}

	m.initialize()
	pLog2.Info("Created new mock database", "dbName", dbName)

	return m, nil
}

func (m *MockMongoProviderV2) Close() error {
	// No resources to clean up for in-memory provider
	return nil
}

// Provider Interface Implementation - delegating to services

func (m *MockMongoProviderV2) DeleteIssuer(issuer string) error {
	return m.keyService.DeleteIssuer(context.Background(), issuer)
}

func (m *MockMongoProviderV2) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	return m.keyService.GetPublicTransmitterJWKS(context.Background(), issuer)
}

func (m *MockMongoProviderV2) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	return m.keyService.GetIssuerPrivateKey(context.Background(), issuer)
}

func (m *MockMongoProviderV2) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.keyService.GetAuthValidatorPubKey()
}

func (m *MockMongoProviderV2) GetAuthIssuer() *authUtil.AuthIssuer {
	return m.keyService.GetAuthIssuer()
}

func (m *MockMongoProviderV2) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return m.streamService.GetIssuerJwksForReceiver(context.Background(), sid)
}

func (m *MockMongoProviderV2) CreateIssuerJwkKeyPair(issuer string, projectId string) *rsa.PrivateKey {
	return m.keyService.CreateIssuerJwkKeyPair(context.Background(), issuer, projectId)
}

func (m *MockMongoProviderV2) RotateIssuerKey(issuer string, projectId string) (*rsa.PrivateKey, string, error) {
	return m.keyService.RotateIssuerKey(context.Background(), issuer, projectId)
}

func (m *MockMongoProviderV2) GetIssuerKeyNames() []string {
	names, _ := m.keyService.GetIssuerKeyNames(context.Background())
	return names
}

func (m *MockMongoProviderV2) GetIssuerPrivateKeyWithKid(issuer string) (*rsa.PrivateKey, string, error) {
	return m.keyService.GetIssuerPrivateKeyWithKid(context.Background(), issuer)
}

func (m *MockMongoProviderV2) AddIssuerKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	return m.keyService.AddIssuerKey(context.Background(), issuer, kid, privateKey, publicKey, projectId)
}

func (m *MockMongoProviderV2) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	return m.clientService.RegisterClient(context.Background(), request, projectId)
}

func (m *MockMongoProviderV2) CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error) {
	return m.streamService.CreateStream(context.Background(), request, projectId)
}

func (m *MockMongoProviderV2) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	return m.streamService.UpdateStream(context.Background(), streamId, projectId, configReq)
}

func (m *MockMongoProviderV2) DeleteStream(streamId string) error {
	return m.streamService.DeleteStream(context.Background(), streamId)
}

func (m *MockMongoProviderV2) GetStream(id string) (*model.StreamConfiguration, error) {
	return m.streamService.GetStream(context.Background(), id)
}

func (m *MockMongoProviderV2) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return m.streamService.GetStreamState(context.Background(), id)
}

func (m *MockMongoProviderV2) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	m.streamService.UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
}

func (m *MockMongoProviderV2) GetStatus(streamId string) (*model.StreamStatus, error) {
	return m.streamService.GetStatus(context.Background(), streamId)
}

func (m *MockMongoProviderV2) ListStreams() []model.StreamConfiguration {
	return m.streamService.ListStreams(context.Background())
}

func (m *MockMongoProviderV2) GetStateMap() map[string]model.StreamStateRecord {
	return m.streamService.GetStateMap(context.Background())
}

func (m *MockMongoProviderV2) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return m.eventService.GetEventIds(context.Background(), streamId, params)
}

func (m *MockMongoProviderV2) GetEvent(jti string) *goSet.SecurityEventToken {
	return m.eventService.GetEvent(context.Background(), jti)
}

func (m *MockMongoProviderV2) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	return m.eventService.GetEvents(context.Background(), jtis)
}

func (m *MockMongoProviderV2) GetEventRecord(jti string) *model.EventRecord {
	return m.eventService.GetEventRecord(context.Background(), jti)
}

func (m *MockMongoProviderV2) AckEvent(jtiString string, streamId string) {
	m.eventService.AckEvent(context.Background(), jtiString, streamId)
}

func (m *MockMongoProviderV2) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (eventRecord *model.EventRecord) {
	return m.eventService.AddEvent(context.Background(), event, sid, raw)
}

func (m *MockMongoProviderV2) AddEventToStream(jti string, streamId primitive.ObjectID) {
	m.eventService.AddEventToStream(context.Background(), jti, streamId)
}

func (m *MockMongoProviderV2) WatchPending(ctx context.Context, callback func(jti string, streamId primitive.ObjectID)) {
	m.eventService.WatchPending(ctx, callback)
}

func (m *MockMongoProviderV2) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	return m.eventService.ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
}
