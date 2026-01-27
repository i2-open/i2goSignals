package mock_provider

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/url"
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

const CDbName = "ssef"
const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"

var pLog = logger.Sub("MOCK_MONGO")

// MockMongoProvider provides an in-memory implementation using DAOs and services
type MockMongoProvider struct {
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

func (m *MockMongoProvider) Name() string {
	return m.DbName
}

func (m *MockMongoProvider) initialize() {
	pLog.Info("Initializing new in-memory mock database", "dbName", m.DbName)

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
		pLog.Error("Error initializing token key", "error", err)
	}

	m.dbInit = true
}

func (m *MockMongoProvider) Check() error {
	// Mock provider is always available
	return nil
}

func (m *MockMongoProvider) ResetDb(initialize bool) error {
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
			pLog.Error("Error reinitializing token key", "error", err)
		}
	}

	return nil
}

// Open creates and initializes a new MockMongoProvider
func Open(mongoUrl string, dbName string) (*MockMongoProvider, error) {
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
		pLog.Info("Defaulting Mock Mongo Database URL", "url", mongoUrl)
	}

	m := &MockMongoProvider{
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
	pLog.Info("Created new mock database", "dbName", dbName)

	return m, nil
}

func (m *MockMongoProvider) Close() error {
	// No resources to clean up for in-memory provider
	return nil
}

// Provider Interface Implementation - delegating to services

func (m *MockMongoProvider) DeleteIssuer(issuer string) error {
	return m.keyService.DeleteIssuer(context.Background(), issuer)
}

func (m *MockMongoProvider) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	return m.keyService.GetPublicTransmitterJWKS(context.Background(), issuer)
}

func (m *MockMongoProvider) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	return m.keyService.GetIssuerPrivateKey(context.Background(), issuer)
}

func (m *MockMongoProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.keyService.GetAuthValidatorPubKey()
}

func (m *MockMongoProvider) GetAuthIssuer() *authUtil.AuthIssuer {
	return m.keyService.GetAuthIssuer()
}

func (m *MockMongoProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return m.streamService.GetIssuerJwksForReceiver(context.Background(), sid)
}

func (m *MockMongoProvider) CreateIssuerJwkKeyPair(issuer string, projectId string) *rsa.PrivateKey {
	return m.keyService.CreateIssuerJwkKeyPair(context.Background(), issuer, projectId)
}

func (m *MockMongoProvider) RotateIssuerKey(issuer string, projectId string) (*rsa.PrivateKey, string, error) {
	return m.keyService.RotateIssuerKey(context.Background(), issuer, projectId)
}

func (m *MockMongoProvider) GetIssuerKeyNames() []string {
	names, _ := m.keyService.GetIssuerKeyNames(context.Background())
	return names
}

func (m *MockMongoProvider) GetIssuerPrivateKeyWithKid(issuer string) (*rsa.PrivateKey, string, error) {
	return m.keyService.GetIssuerPrivateKeyWithKid(context.Background(), issuer)
}

func (m *MockMongoProvider) AddIssuerKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	return m.keyService.AddIssuerKey(context.Background(), issuer, kid, privateKey, publicKey, projectId)
}

func (m *MockMongoProvider) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	return m.clientService.RegisterClient(context.Background(), request, projectId)
}

func (m *MockMongoProvider) CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error) {
	return m.streamService.CreateStream(context.Background(), request, projectId)
}

func (m *MockMongoProvider) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	return m.streamService.UpdateStream(context.Background(), streamId, projectId, configReq)
}

func (m *MockMongoProvider) DeleteStream(streamId string) error {
	return m.streamService.DeleteStream(context.Background(), streamId)
}

func (m *MockMongoProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	return m.streamService.GetStream(context.Background(), id)
}

func (m *MockMongoProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return m.streamService.GetStreamState(context.Background(), id)
}

func (m *MockMongoProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	m.streamService.UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
}

func (m *MockMongoProvider) GetStatus(streamId string) (*model.StreamStatus, error) {
	return m.streamService.GetStatus(context.Background(), streamId)
}

func (m *MockMongoProvider) ListStreams() []model.StreamConfiguration {
	return m.streamService.ListStreams(context.Background())
}

func (m *MockMongoProvider) GetStateMap() map[string]model.StreamStateRecord {
	return m.streamService.GetStateMap(context.Background())
}

func (m *MockMongoProvider) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return m.eventService.GetEventIds(context.Background(), streamId, params)
}

func (m *MockMongoProvider) GetEvent(jti string) *goSet.SecurityEventToken {
	return m.eventService.GetEvent(context.Background(), jti)
}

func (m *MockMongoProvider) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	return m.eventService.GetEvents(context.Background(), jtis)
}

func (m *MockMongoProvider) GetEventRecord(jti string) *model.EventRecord {
	return m.eventService.GetEventRecord(context.Background(), jti)
}

func (m *MockMongoProvider) AckEvent(jtiString string, streamId string, fencingToken int64) {
	m.eventService.AckEvent(context.Background(), jtiString, streamId, fencingToken)
}

func (m *MockMongoProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (eventRecord *model.EventRecord) {
	return m.eventService.AddEvent(context.Background(), event, sid, raw)
}

func (m *MockMongoProvider) AddEventToStream(jti string, streamId primitive.ObjectID) {
	m.eventService.AddEventToStream(context.Background(), jti, streamId)
}

func (m *MockMongoProvider) WatchPending(ctx context.Context, callback func(jti string, streamId primitive.ObjectID)) {
	m.eventService.WatchPending(ctx, callback)
}

func (m *MockMongoProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	return m.eventService.ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
}

func (m *MockMongoProvider) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
	return true, 1, nil
}

func (m *MockMongoProvider) ReleaseLeaseIfOwned(resource string, nodeId string) error {
	return nil
}

func (m *MockMongoProvider) RegisterNode(node model.ClusterNode) error {
	return nil
}

func (m *MockMongoProvider) GetActiveNodeCount() (int64, error) {
	return 1, nil
}

func (m *MockMongoProvider) SetBaseUrl(u *url.URL) {
	m.streamService.SetBaseUrl(u)
}
