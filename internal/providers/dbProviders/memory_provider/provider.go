package memory_provider

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
	"go.mongodb.org/mongo-driver/v2/bson"
)

const CDbName = "ssef"
const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"

var pLog = logger.Sub("MEMORY_DB")

// MemoryProvider provides an in-memory implementation using DAOs and services
type MemoryProvider struct {
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

func (m *MemoryProvider) Name() string {
	return m.DbName
}

func (m *MemoryProvider) initialize() {
	pLog.Info("Initializing new in-memory database", "dbName", m.DbName)

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

func (m *MemoryProvider) Check() error {
	// Mock provider is always available
	return nil
}

func (m *MemoryProvider) ResetDb(initialize bool) error {
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

// Open creates and initializes a new MemoryProvider
func Open(mongoUrl string, dbName string) (*MemoryProvider, error) {
	// Check if this is a memory URL
	if !strings.HasPrefix(mongoUrl, "memorydb:") && mongoUrl != "" {
		return nil, fmt.Errorf("memory provider only supports 'memorydb:' URL prefix, got: %s", mongoUrl)
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
		mongoUrl = "memorydb://localhost"
		pLog.Info("Defaulting Memory Database URL", "url", mongoUrl)
	}

	m := &MemoryProvider{
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
	pLog.Info("Created new memory database", "dbName", dbName)
	pLog.Warn("****************************************************************")
	pLog.Warn("* WARNING: The server is running with an IN-MEMORY database.   *")
	pLog.Warn("* This is for development and testing purposes only.           *")
	pLog.Warn("* Data will NOT be persisted across restarts.                  *")
	pLog.Warn("* The server is running as a SINGLE NODE.                      *")
	pLog.Warn("****************************************************************")

	return m, nil
}

func (m *MemoryProvider) Close() error {
	// No resources to clean up for in-memory provider
	return nil
}

// Provider Interface Implementation - delegating to services

func (m *MemoryProvider) DeleteIssuer(issuer string) error {
	return m.keyService.DeleteIssuer(context.Background(), issuer)
}

func (m *MemoryProvider) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	return m.keyService.GetPublicTransmitterJWKS(context.Background(), issuer)
}

func (m *MemoryProvider) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	return m.keyService.GetIssuerPrivateKey(context.Background(), issuer)
}

func (m *MemoryProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.keyService.GetAuthValidatorPubKey()
}

func (m *MemoryProvider) GetAuthIssuer() *authUtil.AuthIssuer {
	return m.keyService.GetAuthIssuer()
}

func (m *MemoryProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return m.streamService.GetIssuerJwksForReceiver(context.Background(), sid)
}

func (m *MemoryProvider) CreateIssuerJwkKeyPair(issuer string, projectId string) (*rsa.PrivateKey, error) {
	return m.keyService.CreateIssuerJwkKeyPair(context.Background(), issuer, projectId)
}

func (m *MemoryProvider) RotateIssuerKey(issuer string, projectId string) (*rsa.PrivateKey, string, error) {
	return m.keyService.RotateIssuerKey(context.Background(), issuer, projectId)
}

func (m *MemoryProvider) GetIssuerKeyNames() []string {
	names, _ := m.keyService.GetIssuerKeyNames(context.Background())
	return names
}

func (m *MemoryProvider) GetIssuerPrivateKeyWithKid(issuer string) (*rsa.PrivateKey, string, error) {
	return m.keyService.GetIssuerPrivateKeyWithKid(context.Background(), issuer)
}

func (m *MemoryProvider) AddIssuerKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	return m.keyService.AddIssuerKey(context.Background(), issuer, kid, privateKey, publicKey, projectId)
}

func (m *MemoryProvider) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	return m.clientService.RegisterClient(context.Background(), request, projectId)
}

func (m *MemoryProvider) CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error) {
	return m.streamService.CreateStream(context.Background(), request, projectId)
}

func (m *MemoryProvider) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	return m.streamService.UpdateStream(context.Background(), streamId, projectId, configReq)
}

func (m *MemoryProvider) DeleteStream(streamId string) error {
	return m.streamService.DeleteStream(context.Background(), streamId)
}

func (m *MemoryProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	return m.streamService.GetStream(context.Background(), id)
}

func (m *MemoryProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return m.streamService.GetStreamState(context.Background(), id)
}

func (m *MemoryProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	m.streamService.UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
}

func (m *MemoryProvider) GetStatus(streamId string) (*model.StreamStatus, error) {
	return m.streamService.GetStatus(context.Background(), streamId)
}

func (m *MemoryProvider) ListStreams() []model.StreamConfiguration {
	return m.streamService.ListStreams(context.Background())
}

func (m *MemoryProvider) GetStateMap() map[string]model.StreamStateRecord {
	return m.streamService.GetStateMap(context.Background())
}

func (m *MemoryProvider) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return m.eventService.GetEventIds(context.Background(), streamId, params)
}

func (m *MemoryProvider) GetEvent(jti string) *goSet.SecurityEventToken {
	return m.eventService.GetEvent(context.Background(), jti)
}

func (m *MemoryProvider) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	return m.eventService.GetEvents(context.Background(), jtis)
}

func (m *MemoryProvider) GetEventRecord(jti string) *model.EventRecord {
	return m.eventService.GetEventRecord(context.Background(), jti)
}

func (m *MemoryProvider) AckEvent(jtiString string, streamId string, fencingToken int64) error {
	return m.eventService.AckEvent(context.Background(), jtiString, streamId, fencingToken)
}

func (m *MemoryProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (*model.EventRecord, error) {
	return m.eventService.AddEvent(context.Background(), event, sid, raw)
}

func (m *MemoryProvider) AddEventToStream(jti string, streamId bson.ObjectID) error {
	return m.eventService.AddEventToStream(context.Background(), jti, streamId)
}

func (m *MemoryProvider) WatchPending(ctx context.Context, callback func(jti string, streamId bson.ObjectID)) {
	m.eventService.WatchPending(ctx, callback)
}

func (m *MemoryProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	return m.eventService.ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
}

func (m *MemoryProvider) TryAcquireOrRenewLease(_ string, _ string, _ time.Duration) (bool, int64, error) {
	return true, 1, nil
}

func (m *MemoryProvider) ReleaseLeaseIfOwned(_ string, _ string) error {
	return nil
}

func (m *MemoryProvider) RegisterNode(_ model.ClusterNode) error {
	return nil
}

func (m *MemoryProvider) GetActiveNodeCount() (int64, error) {
	return 1, nil
}

func (m *MemoryProvider) SetBaseUrl(u *url.URL) {
	m.streamService.SetBaseUrl(u)
}
